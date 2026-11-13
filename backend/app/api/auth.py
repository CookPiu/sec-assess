from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.auth import create_token, get_current_user, verify_password
from app.core.db import get_session
from app.models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    id: int
    username: str
    display_name: str
    role: str


class LoginResponse(BaseModel):
    token: str
    user: UserOut


def _user_out(user: User) -> UserOut:
    return UserOut(id=user.id, username=user.username, display_name=user.display_name, role=user.role)


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, session: AsyncSession = Depends(get_session)) -> LoginResponse:
    user = await session.scalar(select(User).where(User.username == body.username))
    if user is None or not verify_password(body.password, user.password_hash):
        audit.record(session, audit.AuditAction.LOGIN_FAILED, username=body.username)
        await session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    audit.record(session, audit.AuditAction.LOGIN, user=user)
    await session.commit()
    return LoginResponse(token=create_token(user), user=_user_out(user))


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> UserOut:
    return _user_out(user)
