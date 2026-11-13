"""任务调度：排队与并发上限、总时长限制、停止、收尾，以及后端启动时清理遗留任务（FR-004、FR-005、D-019）。

同时运行的任务数不超过配置的并发上限，其余保持 created 排队；任务结束后自动拉起下一个。
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from sqlalchemy import select, update

from app.core.config import get_settings
from app.core.db import session_factory, utcnow
from app.core.events import bus
from app.core.runtime import load_runtime
from app.models import Project, Task
from app.models.enums import TaskStatus
from app.pipeline.graph import build_graph
from app.pipeline.state import StopRequested, TaskContext
from app.project.ingest import IngestError
from app.sandbox.manager import SandboxError, SandboxManager, sandbox_manager

logger = logging.getLogger(__name__)

STOP_WAIT_SECONDS = 15


class PipelineRunner:
    def __init__(self, manager: SandboxManager = sandbox_manager) -> None:
        self.manager = manager
        self._running: dict[int, asyncio.Task[None]] = {}
        self._contexts: dict[int, TaskContext] = {}
        self._lock = asyncio.Lock()
        self._shutting_down = False
        self._pumps: set[asyncio.Task[None]] = set()  # 持有引用，避免后台任务被回收

    def is_running(self, task_id: int) -> bool:
        return task_id in self._running

    async def startup(self) -> None:
        """清理带本系统标签的遗留容器，把遗留的 running 任务置为 failed，再启动排队中的任务。"""
        self._shutting_down = False
        try:
            removed = await asyncio.to_thread(self.manager.cleanup_leftovers)
            if removed:
                logger.info("已清理 %s 个遗留沙箱容器", removed)
        except Exception as exc:  # Docker 未启动时不影响后端启动
            logger.warning("清理遗留沙箱失败：%s", exc)
        async with session_factory()() as session:
            result = await session.execute(
                update(Task)
                .where(Task.status == TaskStatus.RUNNING)
                .values(status=TaskStatus.FAILED, error="后端重启，任务中断", finished_at=utcnow())
            )
            await session.commit()
            if result.rowcount:
                logger.info("已将 %s 个中断的任务置为 failed", result.rowcount)
        await self.pump()

    async def shutdown(self) -> None:
        self._shutting_down = True
        tasks = list(self._running.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks, timeout=STOP_WAIT_SECONDS)

    async def pump(self) -> None:
        """按创建顺序启动排队任务，直到达到并发上限。"""
        if self._shutting_down:
            return
        async with self._lock:
            async with session_factory()() as session:
                runtime = await load_runtime(session)
                slots = runtime.max_concurrent - len(self._running)
                if slots <= 0:
                    return
                rows = (
                    await session.execute(
                        select(Task, Project)
                        .join(Project, Task.project_id == Project.id)
                        .where(Task.status == TaskStatus.CREATED)
                        .order_by(Task.id)
                        .limit(slots)
                    )
                ).all()
                now = utcnow()
                for task, _ in rows:
                    task.status = TaskStatus.RUNNING
                    task.started_at = now
                    task.quota = runtime.model_dump()
                await session.commit()
            data_dir = get_settings().resolved_data_dir
            for task, project in rows:
                ctx = TaskContext(
                    task_id=task.id,
                    project_id=project.id,
                    source_type=project.source_type,
                    source_url=project.source_url,
                    source_dir=data_dir / Path(project.source_dir),
                    runtime=runtime,
                    sandbox=self.manager,
                )
                self._contexts[task.id] = ctx
                self._running[task.id] = asyncio.create_task(self._run(ctx), name=f"assess-task-{task.id}")
                bus.publish(task.id, "status", {"status": TaskStatus.RUNNING, "error": None})

    async def stop(self, task_id: int) -> bool:
        """停止任务：排队中的直接置为 stopped；运行中的先销毁容器再取消流水线。返回是否有任务被停止。"""
        running = self._running.get(task_id)
        if running is None:
            async with session_factory()() as session:
                result = await session.execute(
                    update(Task)
                    .where(Task.id == task_id, Task.status == TaskStatus.CREATED)
                    .values(status=TaskStatus.STOPPED, finished_at=utcnow())
                )
                await session.commit()
            if result.rowcount:
                bus.publish(task_id, "status", {"status": TaskStatus.STOPPED, "error": None})
            return bool(result.rowcount)
        self._contexts[task_id].stop_event.set()
        try:
            await asyncio.to_thread(self.manager.destroy, task_id)
        except Exception as exc:
            logger.warning("停止任务 %s 时销毁容器失败：%s", task_id, exc)
        running.cancel()
        await asyncio.wait({running}, timeout=STOP_WAIT_SECONDS)
        return True

    async def _run(self, ctx: TaskContext) -> None:
        status, error = TaskStatus.COMPLETED, None
        try:
            async with asyncio.timeout(ctx.runtime.task_timeout_min * 60):
                await build_graph(ctx).ainvoke({"task_id": ctx.task_id, "stages_done": []})
        except (asyncio.CancelledError, StopRequested):
            if self._shutting_down:
                status, error = TaskStatus.FAILED, "后端关闭，任务中断"
            else:
                status = TaskStatus.STOPPED
        except TimeoutError:
            status, error = TaskStatus.FAILED, f"超过任务总时长上限（{ctx.runtime.task_timeout_min} 分钟）"
        except (IngestError, SandboxError) as exc:
            status, error = (TaskStatus.STOPPED, None) if ctx.stop_event.is_set() else (TaskStatus.FAILED, str(exc))
        except Exception as exc:
            logger.exception("任务 %s 执行异常", ctx.task_id)
            status, error = (TaskStatus.STOPPED, None) if ctx.stop_event.is_set() else (TaskStatus.FAILED, f"内部错误：{exc}")
        finally:
            await self._finish(ctx, status, error)

    async def _finish(self, ctx: TaskContext, status: TaskStatus, error: str | None) -> None:
        ctx.stop_sampler()
        # 收尾日志属于整个任务；停在哪个阶段由 task.current_stage 记录
        ctx.stage = None
        if ctx.container_started:
            try:
                await asyncio.to_thread(self.manager.destroy, ctx.task_id)
            except Exception as exc:
                logger.warning("任务 %s 收尾时销毁容器失败：%s", ctx.task_id, exc)
        try:
            if error:
                await ctx.log(error, "error")
            elif status == TaskStatus.STOPPED:
                await ctx.log("任务已被停止，容器已销毁，已产出的阶段数据保留", "warn")
            else:
                await ctx.log("全部阶段完成")
            finished = utcnow()
            await ctx.update_task(status=status, error=error, finished_at=finished)
            if status == TaskStatus.COMPLETED:
                await ctx.update_project(last_assessed_at=finished)
        except Exception:
            logger.exception("任务 %s 收尾写库失败", ctx.task_id)
        finally:
            bus.publish(ctx.task_id, "status", {"status": status, "error": error})
            self._running.pop(ctx.task_id, None)
            self._contexts.pop(ctx.task_id, None)
            if not self._shutting_down:
                pump = asyncio.get_running_loop().create_task(self.pump())
                self._pumps.add(pump)
                pump.add_done_callback(self._pumps.discard)


runner = PipelineRunner()
