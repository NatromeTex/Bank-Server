from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AccountBase(BaseModel):
    name: str
    pin: str

class AccountCreate(AccountBase):
    pass

class AccountResponse(BaseModel):
    id: int
    name: str
    balance: float

    class Config:
        from_attributes = True

class TransactionBase(BaseModel):
    amount: float

class DepositRequest(TransactionBase):
    account_id: int

class WithdrawRequest(TransactionBase):
    account_id: int
    pin: str

class TransferRequest(TransactionBase):
    from_account_id: int
    to_account_id: int
    pin: str

class TransactionResponse(TransactionBase):
    id: int
    type: str
    from_account: Optional[int]
    to_account: Optional[int]
    timestamp: datetime

    class Config:
        from_attributes = True
