from datetime import datetime

from sqlalchemy import Column, Integer, ForeignKey, Float, String, DateTime
from sqlalchemy.ext.declarative import declarative_base

from auth_service.models import User

Base = declarative_base()


class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey(User.id))
    receiver_id = Column(Integer, ForeignKey(User.id))
    amount = Column(Float)
    status = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
