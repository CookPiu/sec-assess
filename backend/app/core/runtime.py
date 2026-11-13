"""运行参数：默认值写在这里，管理员在配置页修改后存入 setting 表并覆盖默认值。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import Setting


class RuntimeConfig(BaseModel):
    sandbox_image: str = Field(default_factory=lambda: get_settings().sandbox_image)
    cpus: float = Field(default=1.0, gt=0, le=8)
    memory_mb: int = Field(default=1024, ge=256, le=8192)
    pids: int = Field(default=256, ge=64, le=4096)
    task_timeout_min: int = Field(default=30, ge=1, le=240)
    probe_timeout_s: int = Field(default=10, ge=1, le=120)
    max_concurrent: int = Field(default=1, ge=1, le=4)
    # 固定为无网络，配置页只展示（D-019）
    network_policy: Literal["none"] = "none"
    pypi_index_url: str = "https://pypi.org/simple"
    llm_enabled: bool = True
    llm_concurrency: int = Field(default=4, ge=1, le=16)


async def load_runtime(session: AsyncSession) -> RuntimeConfig:
    """默认值叠加 setting 表中已保存的覆盖项；表中出现未知或非法的键时忽略该键。"""
    rows = (await session.execute(select(Setting))).scalars().all()
    overrides = {row.key: row.value for row in rows if row.key in RuntimeConfig.model_fields}
    merged = RuntimeConfig().model_dump()
    for key, value in overrides.items():
        candidate = {**merged, key: value}
        try:
            RuntimeConfig.model_validate(candidate)
        except ValueError:
            continue
        merged = candidate
    return RuntimeConfig.model_validate(merged)
