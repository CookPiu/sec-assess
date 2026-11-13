from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, utcnow
from app.models.enums import TaskStatus


class Project(Base):
    __tablename__ = "project"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    source_type: Mapped[str] = mapped_column(String(8))
    source_url: Mapped[str | None] = mapped_column(String(512))
    # data/ 下的源码目录（相对路径）
    source_dir: Mapped[str] = mapped_column(String(256))
    tech_stack: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    loc: Mapped[int | None] = mapped_column(Integer)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("user.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime)


class Task(Base):
    __tablename__ = "task"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default=TaskStatus.CREATED, index=True)
    current_stage: Mapped[str | None] = mapped_column(String(16))
    container_id: Mapped[str | None] = mapped_column(String(80))
    # 创建任务时的运行参数快照（配额、超时等）
    quota: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    # 侦察结果：路由表、启动方式、访问前提、注册登录字段、密码与会话事实
    recon: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    deps_result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("user.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)


class StageLog(Base):
    __tablename__ = "stage_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("task.id", ondelete="CASCADE"), index=True)
    stage: Mapped[str | None] = mapped_column(String(16))
    level: Mapped[str] = mapped_column(String(8), default="info")
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
