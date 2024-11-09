from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: EmailStr

    class Config:
        orm_mode = True


class ChangePassword(BaseModel):
    current_password: str
    new_password: str
    confirm_new_password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"


class UserInfo(BaseModel):
    email: str
    created_at: datetime
    updated_at: datetime
    balance: float
