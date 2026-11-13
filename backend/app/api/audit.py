from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_roles
from app.core.db import get_session
from app.models import AuditLog
from app.models.enums import Role

router = APIRouter(prefix="/api/audit-logs", tags=["audit"])


class AuditLogOut(BaseModel):
    id: int
    username: str
    action: str
    target_type: str | None
    target_id: str | None
    detail: dict[str, Any] | None
    created_at: datetime


class AuditLogPage(BaseModel):
    total: int
    items: list[AuditLogOut]


@router.get("", response_model=AuditLogPage, dependencies=[Depends(require_roles(Role.ADMIN))])
async def list_audit_logs(
    action: str | None = None,
    username: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> AuditLogPage:
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if username:
        stmt = stmt.where(AuditLog.username == username)
    total = await session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await session.execute(stmt.order_by(AuditLog.id.desc()).limit(limit).offset(offset))
    ).scalars()
    return AuditLogPage(
        total=total,
        items=[
            AuditLogOut(
                id=r.id,
                username=r.username,
                action=r.action,
                target_type=r.target_type,
                target_id=r.target_id,
                detail=r.detail,
                created_at=r.created_at,
            )
            for r in rows
        ],
    )
