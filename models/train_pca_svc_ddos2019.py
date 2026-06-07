"""
PCA + SVC classifier trained on CICDDoS2019.

Loads all parquet files from dataset/, performs an 80/20 stratified split,
trains, evaluates, saves artifacts, then removes legacy NetFlow v9 CSVs.

Note on scale: SVC with an RBF kernel is O(n²–n³) in training samples.
At 431k total rows the full training set (~345k) would take hours. The SVC
fit therefore uses a stratified subsample (SVC_MAX_TRAIN_SAMPLES). PCA is
fit on the same subsample; the full test set is evaluated without any cap.
"""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import SVC

DATASET_DIR          = Path("dataset")
OUTPUT_DIR           = Path("models/artifacts_ddos2019/pca_svc")
RANDOM_STATE         = 42
TEST_SIZE            = 0.20
PCA_COMPONENTS       = 30
SVC_MAX_TRAIN_SAMPLES = 60_000   # cap to keep RBF-SVC training tractable

NETFLOW_CSV_PATHS = [
    Path("data/train_net.csv"),
    Path("data/valid_net.csv"),
    Path("data/test_net.csv"),
    Path("data/raw/netflow"),
]


# ── Data loading ──────────────────────────────────────────────────────────────

def load_dataset() -> pd.DataFrame:
    files = sorted(DATASET_DIR.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files found in {DATASET_DIR}")
    print(f"Loading {len(files)} parquet files...")
    return pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)


def preprocess(df: pd.DataFrame):
    X = df.drop(columns=["Label"])
    y = df["Label"].astype(str)

    # CICFlowMeter produces inf on zero-duration flows
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    X = X.select_dtypes(include=[np.number])
    return X, y


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup_netflow_csvs():
    removed = []
    for path in NETFLOW_CSV_PATHS:
        if path.is_file():
            path.unlink()
            removed.append(str(path))
        elif path.is_dir():
            for csv in path.rglob("*.csv"):
                csv.unlink()
                removed.append(str(csv))
    if removed:
        print(f"\nCleaned up {len(removed)} NetFlow v9 CSV(s):")
        for r in removed:
            print(f"  removed  {r}")
    else:
        print("\nNo NetFlow v9 CSVs found to remove.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = load_dataset()
    print(f"Total rows: {len(df):,}  |  Features: {df.shape[1] - 1}")

    X, y = preprocess(df)

    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    print(f"Classes ({len(le.classes_)}): {le.classes_.tolist()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_enc
    )
    print(f"Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # Stratified subsample for SVC training
    if len(X_train) > SVC_MAX_TRAIN_SAMPLES:
        print(f"\nSubsampling training set to {SVC_MAX_TRAIN_SAMPLES:,} rows for SVC (RBF kernel scale constraint)")
        X_train_fit, _, y_train_fit, _ = train_test_split(
            X_train, y_train,
            train_size=SVC_MAX_TRAIN_SAMPLES,
            random_state=RANDOM_STATE,
            stratify=y_train,
        )
    else:
        X_train_fit, y_train_fit = X_train, y_train

    print(f"SVC fit rows: {len(X_train_fit):,}")

    print("\nTraining PCA + SVC pipeline...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("pca",    PCA(n_components=PCA_COMPONENTS, random_state=RANDOM_STATE)),
        ("svc",    SVC(kernel="rbf", C=10.0, gamma="scale", class_weight="balanced",
                       decision_function_shape="ovr", random_state=RANDOM_STATE)),
    ])
    pipeline.fit(X_train_fit, y_train_fit)

    explained = pipeline.named_steps["pca"].explained_variance_ratio_.sum()
    print(f"PCA explained variance ({PCA_COMPONENTS} components): {explained:.3%}")

    print("Evaluating on full test set...")
    y_pred = pipeline.predict(X_test)

    metrics = {
        "accuracy":  round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, average="weighted", zero_division=0), 4),
        "recall":    round(recall_score(y_test, y_pred,    average="weighted", zero_division=0), 4),
        "f1":        round(f1_score(y_test, y_pred,        average="weighted", zero_division=0), 4),
        "classes":   le.classes_.tolist(),
        "pca_components":       PCA_COMPONENTS,
        "pca_explained_variance": round(float(explained), 4),
        "svc_fit_rows": len(X_train_fit),
        "test_rows":    len(X_test),
        "test_size":    TEST_SIZE,
    }
    print(f"\nAccuracy : {metrics['accuracy']}")
    print(f"F1       : {metrics['f1']}")
    print(f"PCA var  : {metrics['pca_explained_variance']:.3%}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

    joblib.dump(pipeline, OUTPUT_DIR / "model.joblib")
    joblib.dump(le,       OUTPUT_DIR / "label_encoder.joblib")
    with open(OUTPUT_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=4)

    print(f"\nArtifacts saved to {OUTPUT_DIR}/")

    cleanup_netflow_csvs()


if __name__ == "__main__":
    main()
