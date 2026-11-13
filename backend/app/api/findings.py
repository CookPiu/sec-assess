"""漏洞查询接口：任务的漏洞列表、漏洞详情（污点步骤与验证证据）、工程源码文件内容（FR-017）。

所有登录用户都能查看。源码只读取项目源码目录内的普通文本文件。
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.core.config import get_settings
from app.core.db import get_session
from app.models import Evidence, Finding, Project, TaintStep, Task
from app.models.enums import Severity

router = APIRouter(prefix="/api", tags=["findings"], dependencies=[Depends(get_current_user)])

MAX_SOURCE_BYTES = 1024 * 1024
SEVERITY_RANK = {severity.value: rank for rank, severity in enumerate(Severity)}


class FindingBrief(BaseModel):
    id: int
    code: str
    category: str
    title: str
    severity: str
    cvss_vector: str | None
    cvss_score: float | None
    file: str
    line: int
    route: dict[str, Any] | None
    status: str
    model_false_positive: bool
    judged_by: str | None


class TaintStepOut(BaseModel):
    seq: int
    file: str
    line: int
    snippet: str
    note: str


class EvidenceOut(BaseModel):
    id: int
    case: dict[str, Any]
    request_raw: str | None
    response_raw: str | None
    # 命中时为命中特征，未命中时为未命中原因
    matched: str | None
    hit: bool
    created_at: datetime


class FindingDetail(FindingBrief):
    task_id: int
    reason: str | None
    created_at: datetime
    steps: list[TaintStepOut]
    evidence: list[EvidenceOut]


class SourceOut(BaseModel):
    path: str
    content: str


def _brief(f: Finding) -> FindingBrief:
    return FindingBrief(
        id=f.id,
        code=f.code,
        category=f.category,
        title=f.title,
        severity=f.severity,
        cvss_vector=f.cvss_vector,
        cvss_score=f.cvss_score,
        file=f.file,
        line=f.line,
        route=f.route,
        status=f.status,
        model_false_positive=f.model_false_positive,
        judged_by=f.judged_by,
    )


@router.get("/tasks/{task_id}/findings", response_model=list[FindingBrief])
async def list_findings(task_id: int, session: AsyncSession = Depends(get_session)) -> list[FindingBrief]:
    """按严重等级、CVSS 分数从高到低排列；分组由前端按验证状态和是否模型判定误报完成。"""
    if await session.get(Task, task_id) is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    rows = (await session.execute(select(Finding).where(Finding.task_id == task_id))).scalars().all()
    rows = sorted(rows, key=lambda f: (SEVERITY_RANK.get(f.severity, len(SEVERITY_RANK)), -(f.cvss_score or 0), f.id))
    return [_brief(f) for f in rows]


@router.get("/findings/{finding_id}", response_model=FindingDetail)
async def get_finding(finding_id: int, session: AsyncSession = Depends(get_session)) -> FindingDetail:
    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    steps = (
        await session.execute(select(TaintStep).where(TaintStep.finding_id == finding_id).order_by(TaintStep.seq))
    ).scalars()
    evidence = (
        await session.execute(select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.id))
    ).scalars()
    return FindingDetail(
        **_brief(finding).model_dump(),
        task_id=finding.task_id,
        reason=finding.reason,
        created_at=finding.created_at,
        steps=[TaintStepOut(seq=s.seq, file=s.file, line=s.line, snippet=s.snippet, note=s.note) for s in steps],
        evidence=[
            EvidenceOut(
                id=e.id,
                case=e.case,
                request_raw=e.request_raw,
                response_raw=e.response_raw,
                matched=e.matched,
                hit=e.hit,
                created_at=e.created_at,
            )
            for e in evidence
        ],
    )


class SourceError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def read_source_file(root: Path, rel: str) -> str:
    """读取 root 下的相对路径文件。拒绝绝对路径、`..`、指向目录外的符号链接、超限和二进制文件。"""
    pure = PurePosixPath(rel.replace("\\", "/"))
    if not rel or pure.is_absolute() or ".." in pure.parts or ":" in rel or "\0" in rel:
        raise SourceError(400, "文件路径不合法")
    base = root.resolve()
    target = (base / pure).resolve()
    if not target.is_relative_to(base):
        raise SourceError(400, "文件路径不合法")
    if not target.is_file():
        raise SourceError(404, "文件不存在")
    if target.stat().st_size > MAX_SOURCE_BYTES:
        raise SourceError(413, "文件超过 1 MB，不提供在线查看")
    data = target.read_bytes()
    if b"\0" in data:
        raise SourceError(415, "不是文本文件")
    return data.decode("utf-8", errors="replace")


@router.get("/tasks/{task_id}/source", response_model=SourceOut)
async def get_source(
    task_id: int,
    path: str = Query(min_length=1, max_length=512, description="相对工程根目录的文件路径"),
    session: AsyncSession = Depends(get_session),
) -> SourceOut:
    task = await session.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    project = await session.get(Project, task.project_id)
    if project is None or not project.source_dir:
        raise HTTPException(status_code=404, detail="项目源码不存在")
    root = get_settings().resolved_data_dir / project.source_dir
    try:
        content = await asyncio.to_thread(read_source_file, root, path)
    except SourceError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None
    return SourceOut(path=path, content=content)
