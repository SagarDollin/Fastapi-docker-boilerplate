from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from bson.objectid import ObjectId

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    _id: ObjectId
    username: str
    email: EmailStr
    full_name: str
    disabled: bool = False
    admin: bool = False
    class Config:
        populate_by_name = True

class NewUser(BaseModel):
    username: str
    email: EmailStr
    full_name: str
    password: str
    disabled: bool = False
    admin: bool = False
    balance: float = 500.0
    CreatedAt: datetime
    class Config:
        populate_by_name = True

class UserInDB(User):
    hashed_password: str