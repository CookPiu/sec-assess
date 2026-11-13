from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, utcnow
from app.models.enums import VerifyStatus


class Finding(Base):
    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("task.id", ondelete="CASCADE"), index=True)
    # 报告中展示的唯一编号，如 SA-12-003
    code: Mapped[str] = mapped_column(String(32), unique=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(10))
    cvss_vector: Mapped[str | None] = mapped_column(String(64))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    file: Mapped[str] = mapped_column(String(256))
    line: Mapped[int] = mapped_column(Integer)
    # 所在路由（URL 与方法），没有路由的静态问题为空
    route: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(12), default=VerifyStatus.UNVERIFIED)
    model_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    judged_by: Mapped[str | None] = mapped_column(String(8))
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TaintStep(Base):
    __tablename__ = "taint_step"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("finding.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    file: Mapped[str] = mapped_column(String(256))
    line: Mapped[int] = mapped_column(Integer)
    snippet: Mapped[str] = mapped_column(Text)
    note: Mapped[str] = mapped_column(String(200))


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("finding.id", ondelete="CASCADE"), index=True)
    # 下发给容器内探针脚本的用例，可原样重放
    case: Mapped[dict[str, Any]] = mapped_column(JSON)
    request_raw: Mapped[str | None] = mapped_column(Text)
    response_raw: Mapped[str | None] = mapped_column(Text)
    matched: Mapped[str | None] = mapped_column(Text)
    hit: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Patch(Base):
    __tablename__ = "patch"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("finding.id", ondelete="CASCADE"), unique=True)
    diff: Mapped[str] = mapped_column(Text)
    adopted: Mapped[bool] = mapped_column(Boolean, default=False)
    adopted_by: Mapped[int | None] = mapped_column(ForeignKey("user.id", ondelete="SET NULL"))
    adopted_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
