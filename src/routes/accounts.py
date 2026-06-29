from datetime import datetime, timezone
from typing import cast

from security.passwords import verify_password
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

import schemas
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
import secrets
from security.passwords import hash_password

router = APIRouter()


@router.post("/register/", status_code=201, response_model=schemas.UserResponseSchema)
async def register_user(
    user_data: schemas.UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    db_user = result.scalar_one_or_none()
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    user_group_result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = user_group_result.scalar_one()

    try:
        hashed_pwd = hash_password(user_data.password)
        user = UserModel(
            email=user_data.email,
            hashed_password=hashed_pwd,
            id=user_group.id,
            group_id=user_group.id,
        )
        db.add(user)
        await db.flush()

        token_string = secrets.token_urlsafe(32)

        activation_token = ActivationTokenModel(
            user_id=cast(int, user.id), token=token_string
        )
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)
        return user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=200)
async def activate_user(
    activation_data: schemas.AccountActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == activation_data.email)
    )
    user = result.scalar_one_or_none()

    if not user or user.is_active:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    token_result = await db.execute(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )
    token = token_result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if token.token != activation_data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    token_expiry = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if token_expiry < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=200)
async def reset_password(
    data: schemas.PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    user_db = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = user_db.scalar_one_or_none()

    if user and user.is_active:
        old_token_result = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        old_token = old_token_result.scalar_one_or_none()
        if old_token:
            await db.delete(old_token)

        new_token = secrets.token_urlsafe(32)
        token = PasswordResetTokenModel(user_id=cast(int, user.id), token=new_token)
        db.add(token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=200)
async def reset_password_complete(
    data: schemas.PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    user_db = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = user_db.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    reset_token_result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    reset_token = reset_token_result.scalar_one_or_none()

    if not reset_token or reset_token.token != data.token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_expiry = cast(datetime, reset_token.expires_at).replace(tzinfo=timezone.utc)
    if token_expiry < datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        hashed_pwd = hash_password(data.password)
        user.hashed_password = hashed_pwd

        await db.delete(reset_token)
        await db.commit()

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=200, response_model=schemas.TokenResponseSchema)
async def login(
    data: schemas.UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    user_db = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = user_db.scalar_one_or_none()

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token(user_id=user.id)
        refresh_token = jwt_manager.create_refresh_token(user_id=user.id)

        db_refresh_token = RefreshTokenModel(
            user_id=cast(int, user.id), token=refresh_token
        )
        db.add(db_refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )


@router.post(
    "/api/v1/accounts/refresh",
    status_code=200,
    response_model=schemas.TokenRefreshResponseSchema,
)
async def refresh(
    data: schemas.TokenRefreshSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.access_token)
        user_id = payload.get("user_id")
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")

    refresh_token_result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.access_token)
    )
    refresh_token = refresh_token_result.scalar_one_or_none()
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_exists_db = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user_exists = user_exists_db.scalar_one_or_none()

    if not user_exists:
        raise HTTPException(status_code=404, detail="User not found.")

    new_token = jwt_manager.create_access_token(user_id=user_id)

    return {"access_token": new_token}
