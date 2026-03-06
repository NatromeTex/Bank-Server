from sqlalchemy import Column, Integer, String, Float, DateTime
from database import Base
import datetime

class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    balance = Column(Float, default=0.0)
    pin = Column(String)

class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String) # deposit, withdraw, transfer
    amount = Column(Float)
    from_account = Column(Integer, nullable=True)
    to_account = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
