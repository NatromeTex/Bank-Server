# AI Multi-Layer DDoS Detection for Financial Networks

This project implements a secure Bank Server with integrated AI-based DDoS detection. It consists of a main banking application, a NetFlow data ingestion pipeline, a machine learning model training pipeline, and a real-time inference service.

## Project Structure

- **`bank/`**: Contains the main FastAPI banking application.
    - `main.py`: Entry point, includes NetFlow logging middleware and Security Dashboard.
- **`ingest/`**: Data ingestion components.
    - `netflow_v9_parser.py`: Parses NetFlow packets and logs them to CSV.
- **`models/`**: Machine learning model training.
    - `train_pca_svc.py`: Trains a PCA + SVC model to detect attacks.
    - `config.yaml`: Configuration for training.
- **`inference/`**: Real-time inference service.
    - `app.py`: FastAPI service that loads the model and predicts on incoming flows. Pushes alerts to the Bank Server.
- **`features/`**: Feature engineering.
    - `window_agg.py`: Sliding window aggregator for computing advanced flow metrics.
- **`data/`**: Stores raw logs and training data.

## Data Flow Architecture

The system processes network traffic through the following pipeline:

1.  **Traffic Ingestion**:
    -   An incoming HTTP request reaches the **Bank Server**.
    -   The **NetFlow Middleware** intercepts the request before it reaches the application logic.

2.  **Feature Extraction**:
    -   The middleware extracts key network metadata: Source/Dest IP, Ports, Protocol, Bytes Transferred, and Timestamps.
    -   It constructs a canonical **Flow Record**.

3.  **Logging & Persistence**:
    -   The flow record is passed to the **NetFlow Parser**.
    -   The parser logs the record to a rotating CSV file in `data/raw/netflow/` for historical analysis and model retraining.

4.  **Inference**:
    -   Flow data is sent to the **Inference Service** (via the `/infer/flow` endpoint).
    -   The service maps the raw flow features to the 22-dimensional vector expected by the **PCA + SVC Model**.
    -   The model predicts whether the flow is benign or malicious.

5.  **Alerting**:
    -   If an attack is detected, the Inference Service connects to the Bank Server's **WebSocket** (`/ws/security`).
    -   The alert payload is broadcast to the **Security Dashboard**.
    -   The dashboard updates in real-time to notify security personnel.

## Setup

1.  **Install Dependencies**:
    ```bash
    pip install fastapi uvicorn sqlalchemy pandas scikit-learn joblib pyyaml websockets
    ```

2.  **Generate Dummy Data** (if you don't have `data/train_net.csv`):
    ```bash
    python create_dummy_data.py
    ```

## Usage

### 1. Train the Model
Train the anomaly detection model using the provided dataset.
```bash
python models/train_pca_svc.py
```
This will save the trained model to `models/artifacts/model.joblib`.

### 2. Run the Bank Server
The Bank Server handles transactions and hosts the Security Dashboard.
```bash
python bank/main.py
```
- **Banking App**: [http://localhost:8000](http://localhost:8000)
- **Security Dashboard**: [http://localhost:8000/security](http://localhost:8000/security)

### 3. Run the Inference Service
The Inference Service analyzes flows and sends alerts to the Bank Server.
```bash
python inference/app.py
```
- **Health Check**: [http://localhost:8001/health](http://localhost:8001/health)

### 4. Simulate Traffic & Attacks
You can use `curl` or a script to send flow data to the Inference Service.

**Example Attack Flow:**
```bash
curl -X POST "http://localhost:8001/infer/flow" \
     -H "Content-Type: application/json" \
     -d '{
           "srcIP": "10.0.0.5",
           "dstIP": "192.168.1.1",
           "srcPort": 12345,
           "dstPort": 80,
           "protocol": 6,
           "bytes": 1000,
           "packets": 10,
           "startTime": 1678886400.0,
           "endTime": 1678886401.0,
           "tcp_flags": "SYN"
         }'
```

If the model detects an attack, an alert will appear instantly on the **Security Dashboard**.

## Logging
- **NetFlow Logs**: All requests to the Bank Server are logged to `data/raw/netflow/YYYY/MM/DD/HH/flows_0.csv`.
