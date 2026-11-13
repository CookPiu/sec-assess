"""沙箱与环境配置接口（FR-018、FR-020）：仅系统管理员可查看与修改，修改写审计日志。

保存的值覆盖默认值，对之后开始的评估生效；运行中的评估沿用开始时的快照。网络隔离策略固定为
none，不接受修改（D-019）。大模型密钥只在 .env 中配置，接口只返回是否已配置。
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.auth import require_roles
from app.core.config import get_settings
from app.core.db import get_session, utcnow
from app.core.runtime import RuntimeConfig, load_runtime
from app.models import Setting, User
from app.models.enums import Role
from app.pipeline.runner import runner

router = APIRouter(prefix="/api/settings", tags=["settings"])

READ_ONLY = {"network_policy"}
EDITABLE = set(RuntimeConfig.model_fields) - READ_ONLY
LABELS = {
    "sandbox_image": "沙箱镜像",
    "cpus": "CPU 核数",
    "memory_mb": "内存上限",
    "pids": "进程数上限",
    "task_timeout_min": "单任务超时",
    "probe_timeout_s": "单探针超时",
    "max_concurrent": "并发任务数",
    "network_policy": "网络隔离策略",
    "pypi_index_url": "PyPI 地址",
    "llm_enabled": "大模型开关",
    "llm_model": "模型名称",
    "llm_base_url": "接口地址",
    "llm_timeout_seconds": "请求超时",
    "llm_concurrency": "大模型并发数",
}


class ImageOut(BaseModel):
    tag: str
    size_mb: float
    created: str | None


class SettingsOut(BaseModel):
    values: RuntimeConfig
    defaults: RuntimeConfig
    images: list[ImageOut]
    docker_available: bool
    llm_key_configured: bool
    updated_at: datetime | None
    updated_by: str | None


def _error_text(exc: ValidationError) -> str:
    err = exc.errors()[0]
    field = str(err["loc"][0]) if err.get("loc") else ""
    # float 字段的边界是 0.0、8.0 这样的值，提示里按整数显示
    ctx = {k: int(v) if isinstance(v, float) and v.is_integer() else v for k, v in (err.get("ctx") or {}).items()}
    reasons = {
        "greater_than_equal": f"不能小于 {ctx.get('ge')}",
        "less_than_equal": f"不能大于 {ctx.get('le')}",
        "greater_than": f"必须大于 {ctx.get('gt')}",
        "string_pattern_mismatch": "必须是 http:// 或 https:// 开头的地址",
        "string_too_short": "不能为空",
        "string_too_long": f"不能超过 {ctx.get('max_length')} 个字符",
    }
    return f"{LABELS.get(field, field)}{reasons.get(err['type'], '的取值不合法')}"


def _images() -> tuple[list[dict[str, Any]], bool]:
    manager = runner.manager
    if not manager.ping():
        return [], False
    try:
        return manager.list_images(), True
    except Exception:  # Docker 连接中途失败时按不可用处理
        return [], False


async def _out(session: AsyncSession) -> SettingsOut:
    values = await load_runtime(session)
    images, docker_ok = await asyncio.to_thread(_images)
    latest = (await session.execute(select(Setting).order_by(Setting.updated_at.desc()).limit(1))).scalar_one_or_none()
    editor = await session.get(User, latest.updated_by) if latest and latest.updated_by else None
    return SettingsOut(
        values=values,
        defaults=RuntimeConfig(),
        images=[ImageOut(**item) for item in images],
        docker_available=docker_ok,
        llm_key_configured=bool(get_settings().llm_api_key),
        updated_at=latest.updated_at if latest else None,
        updated_by=editor.username if editor else None,
    )


@router.get("", response_model=SettingsOut, dependencies=[Depends(require_roles(Role.ADMIN))])
async def get_runtime_settings(session: AsyncSession = Depends(get_session)) -> SettingsOut:
    return await _out(session)


@router.put("", response_model=SettingsOut)
async def update_runtime_settings(
    changes: dict[str, Any] = Body(description="只需包含要修改的配置项"),
    user: User = Depends(require_roles(Role.ADMIN)),
    session: AsyncSession = Depends(get_session),
) -> SettingsOut:
    unknown = sorted(set(changes) - EDITABLE)
    if unknown:
        names = "、".join(LABELS.get(key, key) for key in unknown)
        raise HTTPException(status_code=422, detail=f"不能修改的配置项：{names}")
    current = await load_runtime(session)
    try:
        updated = RuntimeConfig.model_validate({**current.model_dump(), **changes})
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=_error_text(exc)) from None

    before, after = current.model_dump(mode="json"), updated.model_dump(mode="json")
    diff = {key: [before[key], after[key]] for key in changes if before[key] != after[key]}
    if "sandbox_image" in diff:
        manager = runner.manager
        if not await asyncio.to_thread(manager.ping):
            raise HTTPException(status_code=400, detail="Docker 未启动，无法确认沙箱镜像是否存在")
        if not await asyncio.to_thread(manager.image_exists, updated.sandbox_image):
            raise HTTPException(status_code=400, detail=f"本机没有镜像 {updated.sandbox_image}")
    if not diff:
        return await _out(session)

    rows = {row.key: row for row in (await session.execute(select(Setting).where(Setting.key.in_(diff)))).scalars()}
    now = utcnow()
    for key in diff:
        row = rows.get(key) or Setting(key=key)
        row.value, row.updated_by, row.updated_at = after[key], user.id, now
        session.add(row)
    audit.record(
        session,
        audit.AuditAction.SETTING_UPDATE,
        user=user,
        target_type="setting",
        target_id=",".join(sorted(diff)),
        detail={"changes": diff},
    )
    await session.commit()
    if "max_concurrent" in diff:
        # 调大并发上限后，排队中的评估立即补上空位
        await runner.pump()
    return await _out(session)
