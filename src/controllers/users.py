from typing import Optional
from datetime import datetime, timedelta
import json
from email_validator import validate_email, EmailNotValidError

from fastapi import Depends, Request, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext

from dotenv import dotenv_values

from models.users import *
from app import app

from jose import JWTError, jwt

 

SECRET_KEY = config["SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str, request: Request = None):
    if request is not None:
        db = request.app.database
        user_dict = db["Users"].find_one({'username': username})
    else:
        db = app.database
        print("getting through app")
        user_dict = app.database["Users"].find_one({'username': username})

    return UserInDB(**user_dict)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username, request=request)
    
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(request: Request, current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def login_for_access_token_controller(user):
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def signup_controller(request, user):
    db = request.app.database
    is_user = db["Users"].find_one({'username': user.username})
    is_email = db["Users"].find_one({'email': user.email})
    if is_user is None and is_email is None:
        user = json.loads(user.json())
        user["hashed_password"] = pwd_context.hash(user["password"])
        del user["password"]
        
        db["Users"].insert_one(user)
        added_user = db["Users"].find_one({'username': user['username']})
        
        return f"{added_user['username']} added successfully"
    
    elif is_user:
        raise HTTPException(status_code=400, detail='username already exists')
    else:
        raise HTTPException(status_code=400, detail='email already exists')

def get_user_id(username: str, request: Request = None):
    if request is not None:
        db = request.app.database
        users_collection = db["Users"]
        user_dict = users_collection.find_one({'username': username})
        return user_dict['_id']