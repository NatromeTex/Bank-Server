# Bank Server Project Documentation

This document provides a comprehensive overview of the Bank Server project, detailing its architecture, API endpoints, data models, and core functionality.

## Project Overview

The Bank Server is a FastAPI-based application designed to simulate basic banking operations. It utilizes an asynchronous worker pattern to handle transactions sequentially, ensuring data consistency. The system includes real-time metrics monitoring via WebSockets and persists data using SQLAlchemy (SQLite).

## Directory Structure

- **`main.py`**: Application entry point, API route definitions, and WebSocket handler.
- **`worker.py`**: Background worker logic, transaction processing, and metrics calculation.
- **`models.py`**: SQLAlchemy database models (`Account`, `Transaction`).
- **`schemas.py`**: Pydantic models for request/response validation.
- **`database.py`**: Database connection and session management.
- **`test_load.py`**: Script for load testing the server.
- **`static/`**: Directory for static assets (likely for a frontend dashboard).

## Core Functionality

### 1. Asynchronous Transaction Processing
The server uses an `asyncio.Queue` (`transaction_queue`) to buffer incoming write requests (Create Account, Deposit, Withdraw, Transfer, Delete Account). A background `worker` coroutine processes these tasks one by one. This design:
- Serializes database writes, preventing race conditions.
- Decouples request acceptance from processing.
- Calculates metrics (latency, success/failure) for each operation.

### 2. Real-time Metrics
The system maintains an in-memory `Metrics` class (in `worker.py`) that tracks:
- **Total Funds**: Sum of balances across all accounts.
- **Account Count**: Total number of active accounts.
- **TPM (Transactions Per Minute)**: Calculated based on a 10-second sliding window.
- **Average Latency**: 30-second moving average of request processing time.
- **Transaction History**: List of the last 50 transactions with their status (pending, completed, failed).

### 3. Database Persistence
Data is stored in a relational database (SQLite by default) using SQLAlchemy ORM.
- **Accounts**: Stores user account details and current balance.
- **Transactions**: Logs every financial movement (deposit, withdraw, transfer) for audit purposes.

---

## API Endpoints

### Account Management

#### Create Account
- **Endpoint**: `POST /accounts`
- **Description**: Creates a new bank account.
- **Request Body**:
  ```json
  {
    "name": "string",
    "pin": "string"
  }
  ```
- **Process**: Queues a `create_account` task.

#### Delete Account
- **Endpoint**: `DELETE /accounts`
- **Description**: Deletes an existing account. Requires PIN verification.
- **Query Parameters**:
  - `account_id`: integer
  - `pin`: string
- **Process**: Queues a `delete_account` task.

### Financial Operations

#### Deposit
- **Endpoint**: `POST /deposit`
- **Description**: Adds funds to a specific account.
- **Request Body**:
  ```json
  {
    "account_id": 0,
    "amount": 0
  }
  ```
- **Process**: Queues a `deposit` task.

#### Withdraw
- **Endpoint**: `POST /withdraw`
- **Description**: Deducts funds from an account. Requires PIN verification and sufficient balance.
- **Request Body**:
  ```json
  {
    "amount": 0,
    "account_id": 0,
    "pin": "string"
  }
  ```
- **Process**: Queues a `withdraw` task.

#### Transfer
- **Endpoint**: `POST /transfer`
- **Description**: Moves funds from one account to another. Requires PIN verification for the source account.
- **Request Body**:
  ```json
  {
    "amount": 0,
    "from_account_id": 0,
    "to_account_id": 0,
    "pin": "string"
  }
  ```
- **Process**: Queues a `transfer` task.

### Monitoring & Statistics

#### Get Stats (HTTP)
- **Endpoint**: `GET /admin/stats`
- **Description**: Returns a snapshot of the current server metrics.
- **Response**:
  ```json
  {
    "total_funds": float,
    "account_count": int,
    "avg_latency": float,
    "tpm": int,
    "last_50_transactions": [...]
  }
  ```

#### Live Stats (WebSocket)
- **Endpoint**: `WS /ws/stats`
- **Description**: Streams real-time statistics updates every 0.5 seconds.
- **Payload**: Same as `/admin/stats` but includes additional fields like `completed_count`, `failed_count`, and `queue_size`.

---

## Data Models

### Account
| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer | Primary Key, Auto-incrementing |
| `name` | String | Account holder's name |
| `balance` | Float | Current funds (default 0.0) |
| `pin` | String | Security PIN for transactions |

### Transaction
| Field | Type | Description |
|-------|------|-------------|
| `id` | Integer | Primary Key |
| `type` | String | 'deposit', 'withdraw', or 'transfer' |
| `amount` | Float | Transaction value |
| `from_account` | Integer | Source Account ID (nullable) |
| `to_account` | Integer | Destination Account ID (nullable) |
| `timestamp` | DateTime | Time of transaction |
