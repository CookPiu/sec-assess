"""补丁接口：查看补丁与修复前后对照、下载 .patch、标记采纳（FR-013、FR-020）。

所有登录用户可查看与下载；只有研发人员可以采纳，采纳只记录状态并写审计日志，不改动原工程（D-017）。
"""

from __future__ import annotations

import asyncio
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.findings import SourceError, read_source_file
from app.core import audit
from app.core.auth import get_current_user, require_roles
from app.core.config import get_settings
from app.core.db import get_session, utcnow
from app.models import Finding, Patch, Project, Task, User
from app.models.enums import Role
from app.patch.diff import PatchApplyError, apply_diff, diff_stats

router = APIRouter(prefix="/api", tags=["patches"], dependencies=[Depends(get_current_user)])


class PatchOut(BaseModel):
    finding_id: int
    finding_code: str
    file: str
    diff: str
    added: int
    removed: int
    adopted: bool
    adopted_by: str | None
    adopted_at: datetime | None
    created_at: datetime
    # 修复前后的整个文件，供左右对比；源码文件已变化、补丁对不上时为空，只显示 diff
    original: str | None
    patched: str | None


async def _load(session: AsyncSession, finding_id: int) -> tuple[Finding, Patch]:
    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    patch = (await session.execute(select(Patch).where(Patch.finding_id == finding_id))).scalar_one_or_none()
    if patch is None:
        raise HTTPException(status_code=404, detail="该漏洞没有修复补丁")
    return finding, patch


async def _out(session: AsyncSession, finding: Finding, patch: Patch) -> PatchOut:
    adopter = await session.get(User, patch.adopted_by) if patch.adopted_by is not None else None
    original = patched = None
    task = await session.get(Task, finding.task_id)
    project = await session.get(Project, task.project_id) if task else None
    if project is not None and project.source_dir:
        root = get_settings().resolved_data_dir / project.source_dir
        try:
            original = await asyncio.to_thread(read_source_file, root, finding.file)
            patched = apply_diff(original, patch.diff)
        except (SourceError, PatchApplyError):
            original = patched = None
    added, removed = diff_stats(patch.diff)
    return PatchOut(
        finding_id=finding.id,
        finding_code=finding.code,
        file=finding.file,
        diff=patch.diff,
        added=added,
        removed=removed,
        adopted=patch.adopted,
        adopted_by=adopter.username if adopter else None,
        adopted_at=patch.adopted_at,
        created_at=patch.created_at,
        original=original,
        patched=patched,
    )


@router.get("/findings/{finding_id}/patch", response_model=PatchOut)
async def get_patch(finding_id: int, session: AsyncSession = Depends(get_session)) -> PatchOut:
    finding, patch = await _load(session, finding_id)
    return await _out(session, finding, patch)


@router.get("/findings/{finding_id}/patch/download")
async def download_patch(finding_id: int, session: AsyncSession = Depends(get_session)) -> Response:
    finding, patch = await _load(session, finding_id)
    return Response(
        content=patch.diff.encode("utf-8"),
        media_type="text/x-diff; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{finding.code}.patch"'},
    )


@router.post("/findings/{finding_id}/patch/adopt", response_model=PatchOut)
async def adopt_patch(
    finding_id: int,
    user: User = Depends(require_roles(Role.DEVELOPER)),
    session: AsyncSession = Depends(get_session),
) -> PatchOut:
    finding, patch = await _load(session, finding_id)
    if patch.adopted:
        raise HTTPException(status_code=409, detail="补丁已经采纳")
    patch.adopted, patch.adopted_by, patch.adopted_at = True, user.id, utcnow()
    audit.record(
        session,
        audit.AuditAction.PATCH_ADOPT,
        user=user,
        target_type="finding",
        target_id=finding.id,
        detail={"finding_code": finding.code, "file": finding.file},
    )
    await session.commit()
    return await _out(session, finding, patch)
