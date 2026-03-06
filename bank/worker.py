import asyncio
import time
from collections import deque
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Account, Transaction
from schemas import AccountCreate, DepositRequest, WithdrawRequest, TransferRequest
import datetime
import uuid

# Global Queue
transaction_queue = asyncio.Queue()

class Metrics:
    def __init__(self):
        self.total_funds = 0.0
        self.account_count = 0
        self.total_latency = 0.0
        self.transaction_count = 0
        self.completed_count = 0
        self.failed_count = 0
        self.last_50_transactions = deque(maxlen=50)
        self.transaction_timestamps = deque() # For TPM
        self.latency_history = deque() # For 30s Moving Average Latency

    def get_tpm(self):
        now = time.time()
        while self.transaction_timestamps and self.transaction_timestamps[0] < now - 10:
            self.transaction_timestamps.popleft()
        return len(self.transaction_timestamps) * 6
    
    def get_avg_latency(self):
        now = time.time()
        while self.latency_history and self.latency_history[0][0] < now - 30:
            self.latency_history.popleft()
        
        if not self.latency_history:
            return 0.0
        return sum(l for t, l in self.latency_history) / len(self.latency_history)
    
    def add_transaction(self, tx_data):
        pass

metrics = Metrics()

def process_create_account(db: Session, data: AccountCreate):
    db_account = Account(name=data.name, pin=data.pin, balance=0.0)
    db.add(db_account)
    db.flush() # to get ID
    metrics.account_count += 1
    return db_account

def process_delete_account(db: Session, account_id: int, pin: str):
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise ValueError("Account not found")
    if account.pin != pin:
        raise ValueError("Invalid PIN")
    
    metrics.total_funds -= account.balance
    metrics.account_count -= 1
    db.delete(account)
    return {"message": "Account deleted"}

def process_deposit(db: Session, data: DepositRequest):
    account = db.query(Account).filter(Account.id == data.account_id).first()
    if not account:
        raise ValueError("Account not found")
    
    account.balance += data.amount
    metrics.total_funds += data.amount
    
    transaction = Transaction(
        type="deposit",
        amount=data.amount,
        to_account=data.account_id,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(transaction)
    return account

def process_withdraw(db: Session, data: WithdrawRequest):
    account = db.query(Account).filter(Account.id == data.account_id).first()
    if not account:
        raise ValueError("Account not found")
    if account.pin != data.pin:
        raise ValueError("Invalid PIN")
    if account.balance < data.amount:
        raise ValueError("Insufficient funds")
    
    account.balance -= data.amount
    metrics.total_funds -= data.amount
    
    transaction = Transaction(
        type="withdraw",
        amount=data.amount,
        from_account=data.account_id,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(transaction)
    return account

def process_transfer(db: Session, data: TransferRequest):
    from_acc = db.query(Account).filter(Account.id == data.from_account_id).first()
    to_acc = db.query(Account).filter(Account.id == data.to_account_id).first()
    
    if not from_acc:
        raise ValueError("Source account not found")
    if not to_acc:
        raise ValueError("Destination account not found")
    if from_acc.pin != data.pin:
        raise ValueError("Invalid PIN")
    if from_acc.balance < data.amount:
        raise ValueError("Insufficient funds")
    
    from_acc.balance -= data.amount
    to_acc.balance += data.amount
    
    transaction = Transaction(
        type="transfer",
        amount=data.amount,
        from_account=data.from_account_id,
        to_account=data.to_account_id,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(transaction)
    return {"message": "Transfer successful", "from_balance": from_acc.balance, "to_balance": to_acc.balance}


def init_metrics():
    print("Initializing metrics...")
    db = SessionLocal()
    try:
        metrics.account_count = db.query(Account).count()
        result = db.query(Account.balance).all()
        metrics.total_funds = sum([r[0] for r in result])
        # Load last 50 transactions
        txs = db.query(Transaction).order_by(Transaction.timestamp.desc()).limit(50).all()
        for tx in reversed(txs):
            metrics.last_50_transactions.append({
                "id": str(tx.id),
                "type": tx.type,
                "amount": tx.amount,
                "from": tx.from_account,
                "to": tx.to_account,
                "timestamp": str(tx.timestamp),
                "status": "completed"
            })
        print("Metrics initialized")
    except Exception as e:
        print(f"Error initializing metrics: {e}")
    finally:
        db.close()

async def worker():
    print("Worker started")
    await asyncio.to_thread(init_metrics)

    while True:
        task_type, data, future, start_time, tracking_id = await transaction_queue.get()
        
        # Find the pending transaction in metrics and update status to processing?
        # Or just wait until done.
        
        db = SessionLocal()
        try:
            result = None
            if task_type == "create_account":
                result = await asyncio.to_thread(process_create_account, db, data)
            elif task_type == "delete_account":
                result = await asyncio.to_thread(process_delete_account, db, data['account_id'], data['pin'])
            elif task_type == "deposit":
                result = await asyncio.to_thread(process_deposit, db, data)
            elif task_type == "withdraw":
                result = await asyncio.to_thread(process_withdraw, db, data)
            elif task_type == "transfer":
                result = await asyncio.to_thread(process_transfer, db, data)
            
            await asyncio.to_thread(db.commit)
            
            if task_type == "create_account":
                await asyncio.to_thread(db.refresh, result)
                
            if future and not future.done():
                future.set_result(result)
                
            end_time = time.time()
            latency = end_time - start_time
            metrics.total_latency += latency
            metrics.transaction_count += 1
            metrics.transaction_timestamps.append(end_time)
            metrics.latency_history.append((end_time, latency))
            
            # Update status to completed
            metrics.completed_count += 1
            for tx in metrics.last_50_transactions:
                if tx.get("tracking_id") == tracking_id:
                    tx["status"] = "completed"
                    tx["timestamp"] = str(datetime.datetime.utcnow()) # Update timestamp to completion time?
                    # Update other fields if needed (like IDs)
                    if task_type == "deposit":
                        tx["to"] = data.account_id
                    elif task_type == "withdraw":
                        tx["from"] = data.account_id
                    elif task_type == "transfer":
                        tx["from"] = data.from_account_id
                        tx["to"] = data.to_account_id
                    break

        except Exception as e:
            db.rollback()
            if future and not future.done():
                future.set_exception(e)
            
            metrics.failed_count += 1
            # Update status to failed
            for tx in metrics.last_50_transactions:
                if tx.get("tracking_id") == tracking_id:
                    tx["status"] = "failed"
                    break
        finally:
            db.close()
            transaction_queue.task_done()
