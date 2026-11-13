"""操作审计：记录登录、新建与停止评估、补丁采纳、报告导出和配置修改。"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog, User


class AuditAction:
    LOGIN = "login"
    LOGIN_FAILED = "login_failed"
    TASK_CREATE = "task_create"
    TASK_STOP = "task_stop"
    PATCH_ADOPT = "patch_adopt"
    REPORT_EXPORT = "report_export"
    SETTING_UPDATE = "setting_update"


def record(
    session: AsyncSession,
    action: str,
    *,
    user: User | None = None,
    username: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    """把一条审计记录加入当前会话，由调用方与业务改动一起提交。"""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else (username or "-"),
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        detail=detail,
    )
    session.add(entry)
    return entry
