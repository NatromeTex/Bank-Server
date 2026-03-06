import pandas as pd
import numpy as np
import yaml
import joblib
import json
import os
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score

def load_config(config_path="models/config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def load_data(path, dev_mode=False):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Data file not found: {path}")
    
    df = pd.read_csv(path)
    
    if dev_mode:
        print(f"Dev mode enabled: Sampling 45% of data from {path}")
        df = df.sample(frac=0.45, random_state=42)
        
    return df

def preprocess_data(df):
    # Revoked columns from notebook
    revoked_columns = [
        'FLOW_ID', 'ID', 'ANALYSIS_TIMESTAMP', 'IPV4_SRC_ADDR', 'IPV4_DST_ADDR',
        'PROTOCOL_MAP', 'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN', 'TOTAL_PKTS_EXP',
        'TOTAL_BYTES_EXP'
    ]
    
    # Drop revoked columns if they exist
    cols_to_drop = [c for c in revoked_columns if c in df.columns]
    df = df.drop(columns=cols_to_drop)
    
    # Fill missing ANOMALY
    if 'ANOMALY' in df.columns:
        df['ANOMALY'] = df['ANOMALY'].fillna(0)
    
    # Fill missing ALERT
    if 'ALERT' in df.columns:
        df['ALERT'] = df['ALERT'].fillna('None')
        
    return df

def main():
    config = load_config()
    
    # Create output directory
    os.makedirs(config['output_dir'], exist_ok=True)
    
    print("Loading data...")
    try:
        train_df = load_data(config['train_data_path'], dev_mode=config['dev_mode'])
        test_df = load_data(config['test_data_path'], dev_mode=config['dev_mode'])
    except FileNotFoundError as e:
        print(e)
        return

    print("Preprocessing data...")
    train_df = preprocess_data(train_df)
    test_df = preprocess_data(test_df)
    
    # Separate features and target
    # Assuming 'ALERT' is the target as per notebook
    target_col = 'ALERT'
    
    if target_col not in train_df.columns:
        print(f"Target column {target_col} not found in training data.")
        return

    X_train = train_df.drop(columns=[target_col])
    y_train = train_df[target_col]
    
    X_test = test_df.drop(columns=[target_col])
    y_test = test_df[target_col]
    
    
    X_train = X_train.select_dtypes(include=[np.number])
    X_test = X_test.select_dtypes(include=[np.number])
    
    print(f"Training features: {X_train.shape[1]}")

    # Pipeline
    print("Training model...")
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('pca', PCA(n_components=config['pca_components'])),
        ('svc', SVC(kernel=config['svc_kernel'], C=config['svc_C']))
    ])
    
    pipeline.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = pipeline.predict(X_test)
    
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, average='weighted', zero_division=0),
        "recall": recall_score(y_test, y_pred, average='weighted', zero_division=0),
        "f1": f1_score(y_test, y_pred, average='weighted', zero_division=0)
    }
    
    print(f"Metrics: {metrics}")
    
    # Save artifacts
    model_path = os.path.join(config['output_dir'], "model.joblib")
    metrics_path = os.path.join(config['output_dir'], "metrics.json")
    
    joblib.dump(pipeline, model_path)
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=4)
        
    print(f"Model saved to {model_path}")
    print(f"Metrics saved to {metrics_path}")

if __name__ == "__main__":
    main()
