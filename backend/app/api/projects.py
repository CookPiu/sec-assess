"""项目查询接口：概览大盘的项目列表与项目详情（FR-016）。新建项目随新建评估一起完成，见 tasks.py。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.tasks import TaskBrief, severity_counts, task_brief
from app.core.auth import get_current_user
from app.core.db import get_session
from app.models import Project, Task

router = APIRouter(prefix="/api/projects", tags=["projects"], dependencies=[Depends(get_current_user)])


class ProjectOut(BaseModel):
    id: int
    name: str
    source_type: str
    source_url: str | None
    tech_stack: dict[str, Any] | None
    loc: int | None
    created_at: datetime
    last_assessed_at: datetime | None
    latest_task: TaskBrief | None


class ProjectDetail(ProjectOut):
    tasks: list[TaskBrief]


def _project_out(project: Project, latest: TaskBrief | None) -> ProjectOut:
    return ProjectOut(
        id=project.id,
        name=project.name,
        source_type=project.source_type,
        source_url=project.source_url,
        tech_stack=project.tech_stack,
        loc=project.loc,
        created_at=project.created_at,
        last_assessed_at=project.last_assessed_at,
        latest_task=latest,
    )


@router.get("", response_model=list[ProjectOut])
async def list_projects(session: AsyncSession = Depends(get_session)) -> list[ProjectOut]:
    projects = (await session.execute(select(Project).order_by(Project.id.desc()))).scalars().all()
    latest: dict[int, Task] = {}
    for task in (await session.execute(select(Task).order_by(Task.id.desc()))).scalars():
        latest.setdefault(task.project_id, task)
    counts = await severity_counts(session, [t.id for t in latest.values()])
    return [
        _project_out(p, task_brief(latest[p.id], counts[latest[p.id].id]) if p.id in latest else None)
        for p in projects
    ]


@router.get("/{project_id}", response_model=ProjectDetail)
async def get_project(project_id: int, session: AsyncSession = Depends(get_session)) -> ProjectDetail:
    project = await session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    tasks = (
        (await session.execute(select(Task).where(Task.project_id == project_id).order_by(Task.id.desc())))
        .scalars()
        .all()
    )
    counts = await severity_counts(session, [t.id for t in tasks])
    briefs = [task_brief(t, counts[t.id]) for t in tasks]
    return ProjectDetail(**_project_out(project, briefs[0] if briefs else None).model_dump(), tasks=briefs)
