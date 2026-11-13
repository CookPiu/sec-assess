"""尚未实现的阶段：只写一行日志后直接通过，保证流水线能完整跑完。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from app.pipeline.state import TaskContext


def placeholder(task_ref: str) -> Callable[[TaskContext], Awaitable[None]]:
    async def run(ctx: TaskContext) -> None:
        await ctx.log(f"本阶段尚未实现（{task_ref}），直接通过", "warn")

    return run
