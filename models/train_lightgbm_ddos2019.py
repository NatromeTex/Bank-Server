"""
LightGBM classifier trained on CICDDoS2019.

Loads all parquet files from dataset/, performs an 80/20 stratified split,
trains, evaluates, saves artifacts, then removes legacy NetFlow v9 CSVs.
"""
import json
import os
import shutil
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

DATASET_DIR  = Path("dataset")
OUTPUT_DIR   = Path("models/artifacts_ddos2019/lightgbm")
RANDOM_STATE = 42
TEST_SIZE    = 0.20

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

    print("\nTraining LightGBM...")
    model = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=63,
        max_depth=-1,
        objective="multiclass",
        metric="multi_logloss",
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
        verbose=-1,
    )
    model.fit(X_train, y_train)

    print("Evaluating...")
    y_pred = model.predict(X_test)

    metrics = {
        "accuracy":  round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, average="weighted", zero_division=0), 4),
        "recall":    round(recall_score(y_test, y_pred,    average="weighted", zero_division=0), 4),
        "f1":        round(f1_score(y_test, y_pred,        average="weighted", zero_division=0), 4),
        "classes":   le.classes_.tolist(),
        "train_rows": len(X_train),
        "test_rows":  len(X_test),
        "test_size":  TEST_SIZE,
    }
    print(f"\nAccuracy : {metrics['accuracy']}")
    print(f"F1       : {metrics['f1']}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

    joblib.dump(model, OUTPUT_DIR / "model.joblib")
    joblib.dump(le,    OUTPUT_DIR / "label_encoder.joblib")
    with open(OUTPUT_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=4)

    print(f"\nArtifacts saved to {OUTPUT_DIR}/")

    cleanup_netflow_csvs()


if __name__ == "__main__":
    main()
