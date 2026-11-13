"""LangGraph 五阶段流水线：recon → code_audit → poc_verify → exploit_chain → report_gen（D-004）。

每个阶段节点进入前检查停止信号，开始和结束都写日志并推送阶段事件。
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.models.enums import STAGE_ORDER, Stage
from app.pipeline.agents import recon
from app.pipeline.agents.placeholder import placeholder
from app.pipeline.state import PipelineState, TaskContext

StageAgent = Callable[[TaskContext], Awaitable[None]]

AGENTS: dict[Stage, StageAgent] = {
    Stage.RECON: recon.run,
    Stage.CODE_AUDIT: placeholder("T020–T023"),
    Stage.POC_VERIFY: placeholder("T024–T026"),
    Stage.EXPLOIT_CHAIN: placeholder("T035–T036"),
    Stage.REPORT_GEN: placeholder("T038–T041"),
}


def _stage_node(ctx: TaskContext, stage: Stage):
    async def node(_state: PipelineState) -> dict[str, list[str]]:
        ctx.check_stop()
        await ctx.enter_stage(stage)
        started = time.monotonic()
        await AGENTS[stage](ctx)
        await ctx.leave_stage(stage, time.monotonic() - started)
        return {"stages_done": [stage.value]}

    return node


def build_graph(ctx: TaskContext) -> CompiledStateGraph:
    graph = StateGraph(PipelineState)
    previous = START
    for stage in STAGE_ORDER:
        graph.add_node(stage.value, _stage_node(ctx, stage))
        graph.add_edge(previous, stage.value)
        previous = stage.value
    graph.add_edge(previous, END)
    return graph.compile()
