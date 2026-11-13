"""评估任务接口：新建（含 Docker 预检与项目接入）、停止、查询与日志（FR-001、FR-004、FR-005）。

新建与停止只有安全工程师可以操作；所有登录用户都能查看。
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.auth import get_current_user, require_roles
from app.core.config import get_settings
from app.core.db import get_session
from app.core.runtime import load_runtime
from app.models import Finding, Project, StageLog, Task, User
from app.models.enums import Role, SourceType, TaskStatus
from app.pipeline.runner import runner
from app.project.ingest import IngestError, extract_zip, project_source_dir, repo_name_from_url, validate_git_url

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class TaskBrief(BaseModel):
    id: int
    status: str
    current_stage: str | None
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    counts: SeverityCounts


class TaskOut(TaskBrief):
    project_id: int
    project_name: str
    quota: dict[str, Any] | None


class LogOut(BaseModel):
    id: int
    stage: str | None
    level: str
    message: str
    created_at: datetime


async def severity_counts(session: AsyncSession, task_ids: list[int]) -> dict[int, SeverityCounts]:
    """按任务统计各严重等级的漏洞数，“模型判定误报”不计入。"""
    counts: dict[int, SeverityCounts] = defaultdict(SeverityCounts)
    if not task_ids:
        return counts
    rows = await session.execute(
        select(Finding.task_id, Finding.severity, func.count())
        .where(Finding.task_id.in_(task_ids), Finding.model_false_positive.is_(False))
        .group_by(Finding.task_id, Finding.severity)
    )
    for task_id, severity, n in rows:
        if severity in SeverityCounts.model_fields:
            setattr(counts[task_id], severity, n)
    return counts


def task_brief(task: Task, counts: SeverityCounts) -> TaskBrief:
    return TaskBrief(
        id=task.id,
        status=task.status,
        current_stage=task.current_stage,
        error=task.error,
        created_at=task.created_at,
        started_at=task.started_at,
        finished_at=task.finished_at,
        counts=counts,
    )


async def _task_out(session: AsyncSession, task_id: int) -> TaskOut:
    row = (
        await session.execute(
            select(Task, Project.name).join(Project, Task.project_id == Project.id).where(Task.id == task_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    task, project_name = row
    counts = (await severity_counts(session, [task.id]))[task.id]
    return TaskOut(
        **task_brief(task, counts).model_dump(),
        project_id=task.project_id,
        project_name=project_name,
        quota=task.quota,
    )


async def _precheck_sandbox(session: AsyncSession) -> None:
    runtime = await load_runtime(session)
    manager = runner.manager
    if not await asyncio.to_thread(manager.ping):
        raise HTTPException(status_code=503, detail="Docker 未启动，无法新建评估")
    if not await asyncio.to_thread(manager.image_exists, runtime.sandbox_image):
        raise HTTPException(
            status_code=503, detail=f"沙箱镜像 {runtime.sandbox_image} 不存在，请先运行 sandbox-images/build.ps1"
        )


@router.post("", response_model=TaskOut, status_code=status.HTTP_201_CREATED)
async def create_task(
    project_id: int | None = Form(default=None),
    git_url: str | None = Form(default=None),
    name: str | None = Form(default=None, max_length=128),
    file: UploadFile | None = File(default=None),
    user: User = Depends(require_roles(Role.ENGINEER)),
    session: AsyncSession = Depends(get_session),
) -> TaskOut:
    """三选一：对已有项目重新评估、填写 Git 地址、上传 zip 包。zip 在这里同步校验并解压。"""
    git_url = (git_url or "").strip() or None
    name = (name or "").strip() or None
    if sum(x is not None for x in (project_id, git_url, file)) != 1:
        raise HTTPException(status_code=400, detail="请选择一种来源：已有项目、Git 地址或 zip 包")
    await _precheck_sandbox(session)

    if project_id is not None:
        project = await session.get(Project, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="项目不存在")
    elif git_url is not None:
        try:
            url = validate_git_url(git_url)
        except IngestError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        project = Project(name=name or repo_name_from_url(url), source_type=SourceType.GIT, source_url=url, source_dir="")
        session.add(project)
        await session.flush()
        project.source_dir = f"projects/{project.id}/src"
    else:
        assert file is not None
        filename = Path(file.filename or "").name
        if not filename.lower().endswith(".zip"):
            raise HTTPException(status_code=400, detail="只接受 .zip 格式的源码包")
        project = Project(name=name or filename[:-4] or "upload", source_type=SourceType.ZIP, source_dir="")
        session.add(project)
        await session.flush()
        project.source_dir = f"projects/{project.id}/src"
        dest = project_source_dir(get_settings().resolved_data_dir, project.id)
        try:
            await asyncio.to_thread(extract_zip, file.file, dest)
        except IngestError as exc:
            await session.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from None

    task = Task(project_id=project.id, status=TaskStatus.CREATED, created_by=user.id)
    session.add(task)
    await session.flush()
    audit.record(
        session,
        audit.AuditAction.TASK_CREATE,
        user=user,
        target_type="task",
        target_id=task.id,
        detail={"project_id": project.id, "project_name": project.name, "source_type": project.source_type},
    )
    await session.commit()
    await runner.pump()
    return await _task_out(session, task.id)


@router.get("/{task_id}", response_model=TaskOut, dependencies=[Depends(get_current_user)])
async def get_task(task_id: int, session: AsyncSession = Depends(get_session)) -> TaskOut:
    return await _task_out(session, task_id)


@router.get("/{task_id}/logs", response_model=list[LogOut], dependencies=[Depends(get_current_user)])
async def list_logs(
    task_id: int,
    after: int = Query(default=0, ge=0, description="只返回 id 大于该值的日志"),
    limit: int = Query(default=1000, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
) -> list[LogOut]:
    if await session.get(Task, task_id) is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    rows = (
        await session.execute(
            select(StageLog).where(StageLog.task_id == task_id, StageLog.id > after).order_by(StageLog.id).limit(limit)
        )
    ).scalars()
    return [
        LogOut(id=r.id, stage=r.stage, level=r.level, message=r.message, created_at=r.created_at) for r in rows
    ]


@router.post("/{task_id}/stop", response_model=TaskOut)
async def stop_task(
    task_id: int,
    user: User = Depends(require_roles(Role.ENGINEER)),
    session: AsyncSession = Depends(get_session),
) -> TaskOut:
    task = await session.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status not in (TaskStatus.CREATED, TaskStatus.RUNNING):
        raise HTTPException(status_code=409, detail="任务已结束，无需停止")
    if await runner.stop(task_id):
        audit.record(session, audit.AuditAction.TASK_STOP, user=user, target_type="task", target_id=task_id)
        await session.commit()
    session.expire_all()
    return await _task_out(session, task_id)
