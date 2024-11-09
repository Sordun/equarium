from datetime import datetime

from pydantic import BaseModel


class TransferSchema(BaseModel):
    sender_id: int
    receiver_id: int
    amount: float
    date: datetime
    status: str


class TransactionSchema(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    amount: float
    status: str
    created_at: datetime

    class Config:
        orm_mode = True  # Включаем режим ORM
        from_attributes = True  # Включаем поддержку from_orm
