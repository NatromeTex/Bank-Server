import pandas as pd
import numpy as np
import yaml
import joblib
import json
import os
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import LabelEncoder

def load_config(config_path="models/config_lightgbm.yaml"):
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
    
    # Encode target labels
    le = LabelEncoder()
    y_train = le.fit_transform(y_train)
    # Handle unseen labels in test set if any by checking or just transform (risky if new labels)
    # For simplicity assuming test labels are subset of train or same.
    # To be safe, we can union or handle exception.
    # Given the static nature of dataset, fit on train is standard.
    # Check if test has unknown labels
    # diff = set(y_test) - set(le.classes_)
    # if diff:
    #     print(f"Warning: Test set has unknown labels: {diff}")
    
    # We apply transform carefully
    # Use unique classes from both to ensure safely encoded if we want robustness,
    # but standard ML assumes train set defines the world.
    
    # Simplest valid approach for this script:
    y_test = le.transform(y_test)
    
    print(f"Classes: {le.classes_}")
    
    # Select numeric columns only, as in original script (though LightGBM can handle others if configured, we stick to criteria)
    X_train = X_train.select_dtypes(include=[np.number])
    X_test = X_test.select_dtypes(include=[np.number])
    
    print(f"Training features columns: {X_train.columns.tolist()}") # Debug
    print(f"Training features shape: {X_train.shape}")

    # Model
    print("Training LightGBM model...")
    params = config.get('lgbm_params', {})
    model = LGBMClassifier(**params)
    
    model.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = model.predict(X_test)
    
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
    
    joblib.dump(model, model_path)
    metrics['classes'] = le.classes_.tolist()
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=4)
        
    print(f"Model saved to {model_path}")
    print(f"Metrics saved to {metrics_path}")

if __name__ == "__main__":
    main()
