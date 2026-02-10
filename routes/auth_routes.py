from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, EmailStr
from datetime import timedelta
from logging import getLogger

from database import user_collection
from utils.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
)

router = APIRouter(prefix="/auth", tags=["auth"])
logger = getLogger(__name__)

# ------------------------------------------------------------------
# SCHEMAS
# ------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    phone: str
    role: str = "user"   # "user" or "admin"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    id: str
    email: EmailStr
    username: str
    phone: str
    role: str
    access_token: str


# ------------------------------------------------------------------
# REGISTER
# ------------------------------------------------------------------

@router.post("/register", response_model=AuthResponse)
async def register_user(payload: RegisterRequest, response: Response):
    # sourcery skip: raise-from-previous-error
    # Check if user already exists
    if await user_collection.find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    if payload.role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    new_user = {
        "email": payload.email,
        "username": payload.username,
        "password": hash_password(payload.password),
        "phone": payload.phone,
        "role": payload.role,
    }

    try:
        result = await user_collection.insert_one(new_user)
    except Exception as e:
        logger.error(f"User registration failed: {e}")
        raise HTTPException(status_code=500, detail="User registration failed")

    access_token = create_access_token(
        {"user_id": str(result.inserted_id), "role": payload.role}
    )
    refresh_token = create_refresh_token(
        {"user_id": str(result.inserted_id), "role": payload.role}
    )

    # Store refresh token as HTTP-only cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )

    return AuthResponse(
        id=str(result.inserted_id),
        email=new_user["email"],
        username=new_user["username"],
        phone=new_user["phone"],
        role=new_user["role"],
        access_token=access_token,
    )


# ------------------------------------------------------------------
# LOGIN
# ------------------------------------------------------------------

@router.post("/login", response_model=AuthResponse)
async def login_user(payload: LoginRequest, response: Response):
    user = await user_collection.find_one({"email": payload.email})

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        {"user_id": str(user["_id"]), "role": user["role"]}
    )
    refresh_token = create_refresh_token(
        {"user_id": str(user["_id"]), "role": user["role"]}
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )

    return AuthResponse(
        id=str(user["_id"]),
        email=user["email"],
        username=user["username"],
        phone=user["phone"],
        role=user["role"],
        access_token=access_token,
    )