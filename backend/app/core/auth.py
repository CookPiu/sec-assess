"""登录鉴权：bcrypt 密码哈希、JWT 签发与校验、按角色限制接口。"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.db import get_session
from app.models import User
from app.models.enums import Role

logger = logging.getLogger(__name__)

SEED_USERS: tuple[tuple[str, str, Role], ...] = (
    ("engineer", "安全工程师", Role.ENGINEER),
    ("developer", "研发人员", Role.DEVELOPER),
    ("admin", "系统管理员", Role.ADMIN),
)

_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        return False


@lru_cache
def _jwt_secret() -> str:
    secret = get_settings().jwt_secret
    if secret:
        return secret
    logger.warning("未配置 JWT_SECRET，本次启动使用随机密钥，重启后已签发的令牌失效")
    return secrets.token_urlsafe(48)


def create_token(user: User) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=settings.jwt_algorithm)


def _unauthorized(detail: str = "未登录或登录已过期") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: AsyncSession = Depends(get_session),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        payload = jwt.decode(
            credentials.credentials,
            _jwt_secret(),
            algorithms=[get_settings().jwt_algorithm],
            options={"require": ["sub", "exp"]},
        )
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, ValueError):
        raise _unauthorized() from None
    user = await session.get(User, user_id)
    if user is None:
        raise _unauthorized()
    return user


def require_roles(*roles: Role):
    """返回一个依赖项：当前用户角色不在 roles 中时返回 403。"""
    allowed = {str(role) for role in roles}

    async def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="当前角色无权执行该操作")
        return user

    return _checker


async def seed_users(session: AsyncSession) -> int:
    """库中没有任何用户时，用 SEED_PASSWORD 创建三类角色各一个账号。返回新建的账号数。"""
    existing = await session.scalar(select(func.count()).select_from(User))
    if existing:
        return 0
    password = get_settings().seed_password
    if not password:
        logger.error("用户表为空且未配置 SEED_PASSWORD，未创建预置账号；请在 .env 中设置后重启")
        return 0
    for username, display_name, role in SEED_USERS:
        session.add(
            User(username=username, display_name=display_name, role=role, password_hash=hash_password(password))
        )
    await session.commit()
    logger.info("已创建预置账号：%s", ", ".join(u for u, _, _ in SEED_USERS))
    return len(SEED_USERS)
