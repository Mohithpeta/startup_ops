from dotenv import load_dotenv
import os
import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi import HTTPException, Depends, Request, Response
from fastapi.security import OAuth2PasswordBearer
from typing import List

# ------------------------------------------------------------------
# ENV & CONFIG
# ------------------------------------------------------------------

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set in environment variables")

# Token expiry
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# OAuth2 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ------------------------------------------------------------------
# PASSWORD UTILITIES
# ------------------------------------------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# ------------------------------------------------------------------
# TOKEN CREATION
# ------------------------------------------------------------------

def _create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_access_token(data: dict) -> str:
    return _create_token(
        data=data,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

def create_refresh_token(data: dict) -> str:
    return _create_token(
        data=data,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

# ------------------------------------------------------------------
# TOKEN VERIFICATION
# ------------------------------------------------------------------

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail="Token expired") from e
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail="Invalid token") from e

# ------------------------------------------------------------------
# AUTH DEPENDENCIES
# ------------------------------------------------------------------

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_token(token)

    user_id = payload.get("user_id")
    role = payload.get("role")

    if not user_id or not role:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    return {
        "user_id": user_id,
        "role": role
    }

# ------------------------------------------------------------------
# ROLE / PERMISSION CHECKS
# ------------------------------------------------------------------

ROLE_HIERARCHY = {
    "admin": ["admin", "user"],
    "user": ["user"]
}

def require_roles(allowed_roles: List[str]):
    def role_checker(current_user: dict = Depends(get_current_user)):
        user_role = current_user["role"]
        if user_role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return current_user
    return role_checker

# ------------------------------------------------------------------
# REFRESH TOKEN HANDLING
# ------------------------------------------------------------------

def refresh_access_token(request: Request):
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    payload = decode_token(refresh_token)

    user_id = payload.get("user_id")
    role = payload.get("role")

    if not user_id or not role:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    new_access_token = create_access_token(
        {"user_id": user_id, "role": role}
    )

    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }

# ------------------------------------------------------------------
# LOGOUT
# ------------------------------------------------------------------

def logout(response: Response):
    response.delete_cookie("refresh_token")
    return {"message": "Logged out successfully"}