"""
evaluate_models.py

Trains LightGBM, Random Forest, and PCA+SVC on CICDDoS2019 and produces
for each model:

  - Train/test split summary + 5-fold stratified cross-validation
  - Full classification report (text)
  - Confusion matrix (text + PNG)
  - ROC curves with per-class and macro/micro AUC (text + PNG)

All outputs are saved to models/evaluation/<timestamp>/
Run from the project root:
    python models/evaluate_models.py
"""

import json
import time
import warnings
from datetime import datetime
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")  # no display required
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd
import seaborn as sns
from lightgbm import LGBMClassifier
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler, label_binarize
from sklearn.svm import SVC

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
DATASET_DIR  = Path("dataset")
OUTPUT_ROOT  = Path("models/evaluation")
RANDOM_STATE = 42
TEST_SIZE    = 0.20
CV_FOLDS     = 5
CV_MAX_ROWS  = 50_000   # subsample for CV — keeps RF and SVC tractable
SVC_MAX_TRAIN_SAMPLES = 60_000


# ── Data ──────────────────────────────────────────────────────────────────────

def load_dataset() -> pd.DataFrame:
    files = sorted(DATASET_DIR.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files in {DATASET_DIR}")
    print(f"Loading {len(files)} parquet files...")
    return pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)


def preprocess(df: pd.DataFrame):
    X = df.drop(columns=["Label"])
    y = df["Label"].astype(str)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    X = X.select_dtypes(include=[np.number])
    return X, y


# ── Models ────────────────────────────────────────────────────────────────────

MODELS = {
    "LightGBM": LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=63,
        objective="multiclass",
        metric="multi_logloss",
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
        verbose=-1,
    ),
    "RandomForest": RandomForestClassifier(
        n_estimators=200,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    ),
    "PCA_SVC": Pipeline([
        ("scaler", StandardScaler()),
        ("pca",    PCA(n_components=30, random_state=RANDOM_STATE)),
        ("svc",    SVC(kernel="rbf", C=10.0, gamma="scale",
                       class_weight="balanced", probability=True,
                       decision_function_shape="ovr", random_state=RANDOM_STATE)),
    ]),
}


# ── Plotting helpers ──────────────────────────────────────────────────────────

def _save(fig: plt.Figure, path: Path):
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved → {path.name}")


def plot_confusion_matrix(cm: np.ndarray, classes: list[str],
                          title: str, out: Path):
    norm = cm.astype(float) / cm.sum(axis=1, keepdims=True).clip(min=1)

    fig, axes = plt.subplots(1, 2, figsize=(22, 9))
    fig.suptitle(title, fontsize=14, fontweight="bold")

    for ax, data, fmt, subtitle in [
        (axes[0], norm,  ".2f", "Row-normalised (recall per class)"),
        (axes[1], cm,    "d",   "Raw counts"),
    ]:
        sns.heatmap(
            data, annot=True, fmt=fmt, cmap="Blues",
            xticklabels=classes, yticklabels=classes,
            linewidths=0.3, linecolor="lightgrey",
            ax=ax, cbar=True,
            annot_kws={"size": 7},
        )
        ax.set_title(subtitle, fontsize=11)
        ax.set_xlabel("Predicted", fontsize=10)
        ax.set_ylabel("True",      fontsize=10)
        ax.tick_params(axis="x", rotation=45, labelsize=8)
        ax.tick_params(axis="y", rotation=0,  labelsize=8)

    fig.tight_layout()
    _save(fig, out)


def plot_roc(y_test_bin: np.ndarray, y_score: np.ndarray,
             classes: list[str], title: str, out: Path):
    n_classes = len(classes)
    cmap      = plt.colormaps["tab20"].resampled(n_classes)

    # Per-class ROC
    fpr_dict, tpr_dict, auc_dict = {}, {}, {}
    for i, cls in enumerate(classes):
        fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_score[:, i])
        fpr_dict[cls] = fpr
        tpr_dict[cls] = tpr
        auc_dict[cls] = auc(fpr, tpr)

    # Micro-average
    fpr_micro, tpr_micro, _ = roc_curve(y_test_bin.ravel(), y_score.ravel())
    auc_micro = auc(fpr_micro, tpr_micro)

    # Macro-average
    auc_macro = float(np.mean(list(auc_dict.values())))

    fig, ax = plt.subplots(figsize=(11, 8))
    ax.set_title(title, fontsize=13, fontweight="bold")

    # Per-class lines
    for i, cls in enumerate(classes):
        ax.plot(fpr_dict[cls], tpr_dict[cls],
                color=cmap(i), lw=1.2, alpha=0.75,
                label=f"{cls}  (AUC {auc_dict[cls]:.3f})")

    # Averages
    ax.plot(fpr_micro, tpr_micro, color="black", lw=2.5, linestyle="-",
            label=f"Micro-avg  (AUC {auc_micro:.3f})")
    ax.plot([0, 1], [0, 1], color="grey", lw=1, linestyle="--",
            label=f"Macro-avg  AUC {auc_macro:.3f}")

    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.02])
    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_ylabel("True Positive Rate",  fontsize=11)
    ax.legend(loc="lower right", fontsize=7.5, ncol=2,
              framealpha=0.9, edgecolor="lightgrey")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    _save(fig, out)

    return auc_dict, auc_micro, auc_macro


def plot_auc_bar(auc_dict: dict, model_name: str, out: Path):
    classes = list(auc_dict.keys())
    aucs    = [auc_dict[c] for c in classes]
    colours = ["#d62728" if v < 0.90 else "#2ca02c" for v in aucs]

    fig, ax = plt.subplots(figsize=(12, 5))
    bars = ax.barh(classes, aucs, color=colours, edgecolor="white", height=0.6)
    ax.bar_label(bars, fmt="%.3f", padding=3, fontsize=8)
    ax.set_xlim(0.5, 1.02)
    ax.set_xlabel("AUC (OvR)", fontsize=11)
    ax.set_title(f"{model_name} — Per-class AUC", fontsize=13, fontweight="bold")
    ax.axvline(0.90, color="red", linestyle="--", linewidth=1, alpha=0.6,
               label="AUC = 0.90")
    ax.legend(fontsize=9)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    _save(fig, out)


# ── Cross-validation ──────────────────────────────────────────────────────────

def run_cv(model, X_train: pd.DataFrame, y_train_enc: np.ndarray,
           le: LabelEncoder) -> dict:
    """5-fold stratified CV on a capped subsample."""
    n = min(CV_MAX_ROWS, len(X_train))
    if n < len(X_train):
        X_cv, _, y_cv, _ = train_test_split(
            X_train, y_train_enc,
            train_size=n, random_state=RANDOM_STATE, stratify=y_train_enc,
        )
        note = f"(subsample {n:,} / {len(X_train):,} rows)"
    else:
        X_cv, y_cv = X_train, y_train_enc
        note = f"(full {n:,} rows)"

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    scores = cross_validate(
        model, X_cv, y_cv, cv=cv,
        scoring=["accuracy", "f1_macro", "f1_weighted"],
        n_jobs=-1,
    )
    return {
        "note":         note,
        "folds":        CV_FOLDS,
        "accuracy":     scores["test_accuracy"],
        "f1_macro":     scores["test_f1_macro"],
        "f1_weighted":  scores["test_f1_weighted"],
    }


def fmt_cv(cv: dict) -> str:
    lines = [
        f"  Cross-validation  {cv['folds']}-fold stratified  {cv['note']}",
        f"  {'Metric':<18} {'Mean':>8}  {'Std':>8}  {'Min':>8}  {'Max':>8}",
        f"  {'-'*54}",
    ]
    for key in ("accuracy", "f1_macro", "f1_weighted"):
        arr = cv[key]
        lines.append(
            f"  {key:<18} {arr.mean():>8.4f}  {arr.std():>8.4f}"
            f"  {arr.min():>8.4f}  {arr.max():>8.4f}"
        )
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    run_dir = OUTPUT_ROOT / datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {run_dir}\n")

    # ── Load & split ──────────────────────────────────────────────────────────
    df = load_dataset()
    X, y = preprocess(df)

    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    classes = le.classes_.tolist()
    n_classes = len(classes)
    print(f"Total rows  : {len(X):,}")
    print(f"Features    : {X.shape[1]}")
    print(f"Classes     : {n_classes}  →  {classes}\n")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_enc,
    )
    y_test_bin = label_binarize(y_test, classes=list(range(n_classes)))

    split_summary = (
        f"Train/test split\n"
        f"  Strategy   : stratified  random_state={RANDOM_STATE}\n"
        f"  Train rows : {len(X_train):,}  ({100*(1-TEST_SIZE):.0f}%)\n"
        f"  Test rows  : {len(X_test):,}   ({100*TEST_SIZE:.0f}%)\n"
        f"  Features   : {X_train.shape[1]}\n"
        f"  Classes    : {n_classes}\n"
    )
    print(split_summary)

    all_results = {}

    for model_name, model in MODELS.items():
        print(f"{'='*60}")
        print(f"  {model_name}")
        print(f"{'='*60}")

        model_dir = run_dir / model_name
        model_dir.mkdir()

        # ── Train ─────────────────────────────────────────────────────────────
        if model_name == "PCA_SVC" and len(X_train) > SVC_MAX_TRAIN_SAMPLES:
            X_fit, _, y_fit, _ = train_test_split(
                X_train, y_train,
                train_size=SVC_MAX_TRAIN_SAMPLES,
                random_state=RANDOM_STATE,
                stratify=y_train,
            )
            print(f"  SVC fit on {len(X_fit):,} / {len(X_train):,} rows")
        else:
            X_fit, y_fit = X_train, y_train

        t0 = time.time()
        model.fit(X_fit, y_fit)
        train_secs = time.time() - t0
        print(f"  Train time : {train_secs:.1f}s")

        # ── Predict ───────────────────────────────────────────────────────────
        y_pred  = model.predict(X_test)
        y_score = model.predict_proba(X_test)

        acc = accuracy_score(y_test, y_pred)
        f1w = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        f1m = f1_score(y_test, y_pred, average="macro",    zero_division=0)
        print(f"  Accuracy   : {acc:.4f}")
        print(f"  F1 weighted: {f1w:.4f}")
        print(f"  F1 macro   : {f1m:.4f}")

        # ── Cross-validation ──────────────────────────────────────────────────
        print(f"  Running {CV_FOLDS}-fold CV...")
        cv_results = run_cv(model, X_train, y_train, le)
        print(fmt_cv(cv_results))

        # ── Classification report ─────────────────────────────────────────────
        report_str = classification_report(
            y_test, y_pred, target_names=classes, zero_division=0,
        )
        print("\n  Classification Report:")
        for line in report_str.splitlines():
            print(f"    {line}")

        # ── Confusion matrix ──────────────────────────────────────────────────
        print("\n  Confusion Matrix (row-normalised):")
        cm   = confusion_matrix(y_test, y_pred)
        norm = cm.astype(float) / cm.sum(axis=1, keepdims=True).clip(min=1)
        col_w = max(len(c) for c in classes) + 2
        header = " " * col_w + "".join(f"{c:>{col_w}}" for c in classes)
        print(f"    {header}")
        for i, row_cls in enumerate(classes):
            row_vals = "".join(f"{norm[i,j]:>{col_w}.2f}" for j in range(n_classes))
            print(f"    {row_cls:<{col_w}}{row_vals}")

        plot_confusion_matrix(
            cm, classes,
            title=f"{model_name} — Confusion Matrix",
            out=model_dir / "confusion_matrix.png",
        )

        # ── ROC ───────────────────────────────────────────────────────────────
        print("\n  ROC / AUC:")
        auc_dict, auc_micro, auc_macro = plot_roc(
            y_test_bin, y_score, classes,
            title=f"{model_name} — ROC Curves (One-vs-Rest)",
            out=model_dir / "roc_curves.png",
        )
        plot_auc_bar(auc_dict, model_name, out=model_dir / "auc_per_class.png")

        print(f"    {'Class':<22} {'AUC':>7}")
        print(f"    {'-'*30}")
        for cls, a in sorted(auc_dict.items(), key=lambda x: x[1], reverse=True):
            flag = "  ← low" if a < 0.90 else ""
            print(f"    {cls:<22} {a:>7.4f}{flag}")
        print(f"    {'-'*30}")
        print(f"    {'Micro-average':<22} {auc_micro:>7.4f}")
        print(f"    {'Macro-average':<22} {auc_macro:>7.4f}")

        # ── Save artifacts ────────────────────────────────────────────────────
        joblib.dump(model, model_dir / "model.joblib")
        joblib.dump(le,    model_dir / "label_encoder.joblib")

        result = {
            "accuracy":   round(acc,  4),
            "f1_weighted": round(f1w, 4),
            "f1_macro":   round(f1m,  4),
            "train_secs": round(train_secs, 1),
            "train_rows": len(X_train),
            "fit_rows":   len(X_fit),
            "test_rows":  len(X_test),
            "auc_per_class": {c: round(v, 4) for c, v in auc_dict.items()},
            "auc_micro":  round(auc_micro, 4),
            "auc_macro":  round(auc_macro, 4),
            "cv": {
                "folds":        CV_FOLDS,
                "note":         cv_results["note"],
                "accuracy_mean": round(float(cv_results["accuracy"].mean()),    4),
                "accuracy_std":  round(float(cv_results["accuracy"].std()),     4),
                "f1_macro_mean": round(float(cv_results["f1_macro"].mean()),    4),
                "f1_macro_std":  round(float(cv_results["f1_macro"].std()),     4),
                "f1_weighted_mean": round(float(cv_results["f1_weighted"].mean()), 4),
                "f1_weighted_std":  round(float(cv_results["f1_weighted"].std()),  4),
            },
            "classification_report": report_str,
        }
        with open(model_dir / "results.json", "w") as f:
            json.dump(result, f, indent=4)

        all_results[model_name] = result
        print(f"\n  Artifacts: {model_dir}/\n")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    print(f"\n{split_summary}")

    header = f"  {'Model':<16} {'Acc':>7}  {'F1-w':>7}  {'F1-m':>7}  {'AUC-micro':>10}  {'AUC-macro':>10}  {'Train(s)':>9}"
    print(header)
    print(f"  {'-'*75}")
    for name, r in all_results.items():
        print(
            f"  {name:<16} {r['accuracy']:>7.4f}  {r['f1_weighted']:>7.4f}"
            f"  {r['f1_macro']:>7.4f}  {r['auc_micro']:>10.4f}"
            f"  {r['auc_macro']:>10.4f}  {r['train_secs']:>9.1f}s"
        )

    # ── Comparison plot ───────────────────────────────────────────────────────
    metrics  = ["accuracy", "f1_weighted", "f1_macro", "auc_micro", "auc_macro"]
    labels   = ["Accuracy", "F1 Weighted", "F1 Macro", "AUC Micro", "AUC Macro"]
    names    = list(all_results.keys())
    x        = np.arange(len(metrics))
    width    = 0.22
    colours  = ["#1f77b4", "#2ca02c", "#d62728"]

    fig, ax = plt.subplots(figsize=(13, 6))
    for i, (name, colour) in enumerate(zip(names, colours)):
        vals = [all_results[name][m] for m in metrics]
        bars = ax.bar(x + i * width, vals, width, label=name,
                      color=colour, alpha=0.85, edgecolor="white")
        ax.bar_label(bars, fmt="%.3f", padding=2, fontsize=8)

    ax.set_xticks(x + width)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylim(0.7, 1.05)
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.2f"))
    ax.set_title("Model Comparison — CICDDoS2019", fontsize=14, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    _save(fig, run_dir / "model_comparison.png")

    # ── Save combined summary ─────────────────────────────────────────────────
    with open(run_dir / "summary.json", "w") as f:
        json.dump(all_results, f, indent=4)

    print(f"\nAll outputs saved to: {run_dir}/")
    print("\nFiles generated:")
    for p in sorted(run_dir.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(run_dir)}")


if __name__ == "__main__":
    main()
