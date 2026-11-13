"""流水线状态与任务上下文。

阶段产出直接写数据库，LangGraph 状态里只记录已完成的阶段；各阶段 Agent 通过 TaskContext
写日志、推送事件、访问沙箱和检查停止信号。
"""

from __future__ import annotations

import asyncio
import operator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, TypedDict

from app.core.db import session_factory
from app.core.events import bus
from app.core.runtime import RuntimeConfig
from app.models import Project, StageLog, Task
from app.models.enums import STAGE_LABELS, Stage
from app.sandbox.manager import Quota, SandboxManager
from app.sandbox.stats import StatsSampler


class PipelineState(TypedDict):
    task_id: int
    stages_done: Annotated[list[str], operator.add]


class StopRequested(Exception):
    """用户停止了任务，在阶段之间或验证用例之间抛出。"""


@dataclass
class TaskContext:
    task_id: int
    project_id: int
    source_type: str
    source_url: str | None
    source_dir: Path
    runtime: RuntimeConfig
    sandbox: SandboxManager
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)
    stage: Stage | None = None
    container_started: bool = False
    _sampler: StatsSampler | None = None

    def check_stop(self) -> None:
        if self.stop_event.is_set():
            raise StopRequested

    async def log(self, message: str, level: str = "info") -> None:
        """写入阶段日志并推送到工作台；事件带日志 id，前端断线重连补拉历史时据此去重。"""
        entry = StageLog(task_id=self.task_id, stage=self.stage, level=level, message=message)
        async with session_factory()() as session:
            session.add(entry)
            await session.commit()
        bus.publish(
            self.task_id,
            "log",
            {
                "id": entry.id,
                "stage": self.stage,
                "level": level,
                "message": message,
                "created_at": entry.created_at.isoformat(),
            },
        )

    async def enter_stage(self, stage: Stage) -> None:
        self.stage = stage
        async with session_factory()() as session:
            task = await session.get(Task, self.task_id)
            if task is not None:
                task.current_stage = stage
                await session.commit()
        bus.publish(self.task_id, "stage", {"stage": stage, "state": "running"})
        await self.log(f"阶段开始：{STAGE_LABELS[stage]}")

    async def leave_stage(self, stage: Stage, elapsed: float) -> None:
        await self.log(f"阶段结束：{STAGE_LABELS[stage]}，用时 {elapsed:.1f} 秒")
        bus.publish(self.task_id, "stage", {"stage": stage, "state": "done"})

    async def start_sandbox(self) -> None:
        """创建任务容器并开始资源采样；容器由 runner 在任务结束时销毁。"""
        quota = Quota(cpus=self.runtime.cpus, memory_mb=self.runtime.memory_mb, pids=self.runtime.pids)
        self.container_started = True
        container_id = await asyncio.to_thread(
            self.sandbox.create, self.task_id, self.source_dir, self.runtime.sandbox_image, quota
        )
        async with session_factory()() as session:
            task = await session.get(Task, self.task_id)
            if task is not None:
                task.container_id = container_id
                await session.commit()
        self._sampler = StatsSampler(self.sandbox, self.task_id, lambda s: bus.publish(self.task_id, "metrics", s))
        self._sampler.start()
        await self.log(
            f"沙箱容器已启动：CPU {quota.cpus:g} 核，内存 {quota.memory_mb} MB，"
            f"进程数上限 {quota.pids}，网络 {self.runtime.network_policy}"
        )

    def stop_sampler(self) -> None:
        if self._sampler is not None:
            self._sampler.stop()
            self._sampler = None

    async def update_project(self, **values: object) -> None:
        async with session_factory()() as session:
            project = await session.get(Project, self.project_id)
            if project is not None:
                for key, value in values.items():
                    setattr(project, key, value)
                await session.commit()

    async def update_task(self, **values: object) -> None:
        async with session_factory()() as session:
            task = await session.get(Task, self.task_id)
            if task is not None:
                for key, value in values.items():
                    setattr(task, key, value)
                await session.commit()
