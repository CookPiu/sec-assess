"""环境侦察（DESIGN.md 5.1）：准备源码、启动沙箱、识别技术栈与代码行数。"""

from __future__ import annotations

import asyncio

from app.models.enums import SourceType
from app.pipeline.state import TaskContext
from app.project.ingest import IngestError, clone_repo, dir_size
from app.project.stack import analyze_stack


async def ensure_source(ctx: TaskContext) -> None:
    """Git 项目首次评估时克隆仓库，之后复用已克隆的源码；zip 项目在上传时已解压。"""
    if ctx.source_dir.is_dir() and any(ctx.source_dir.iterdir()):
        return
    if ctx.source_type != SourceType.GIT or not ctx.source_url:
        raise IngestError("源码目录不存在，请重新上传")
    await ctx.log(f"正在浅克隆 {ctx.source_url}")
    await asyncio.to_thread(clone_repo, ctx.source_url, ctx.source_dir)
    size_mb = await asyncio.to_thread(dir_size, ctx.source_dir) / 1024 / 1024
    await ctx.log(f"克隆完成，源码 {size_mb:.1f} MB")


def stack_summary(stack: dict) -> dict:
    """项目表只存概要，完整依赖清单在任务的侦察结果里。"""
    return {
        "primary_language": stack["primary_language"],
        "languages": stack["languages"],
        "frameworks": stack["frameworks"],
        "manifests": stack["manifests"],
        "dependency_count": len(stack["dependencies"]),
    }


async def run(ctx: TaskContext) -> None:
    await ensure_source(ctx)
    ctx.check_stop()
    await ctx.start_sandbox()
    ctx.check_stop()

    stack = await asyncio.to_thread(analyze_stack, ctx.source_dir)
    await ctx.update_task(recon={"stack": stack})
    await ctx.update_project(tech_stack=stack_summary(stack), loc=stack["loc"])

    langs = "、".join(f"{x['name']} {x['loc']} 行" for x in stack["languages"][:5]) or "未识别到源码文件"
    await ctx.log(f"语言分布：{langs}；代码行数合计 {stack['loc']}")
    if stack["frameworks"]:
        fws = "、".join(f"{f['name']} {f['version']}" if f["version"] else f["name"] for f in stack["frameworks"])
        await ctx.log(f"识别到框架：{fws}")
    if stack["manifests"]:
        await ctx.log(f"依赖清单：{'、'.join(stack['manifests'])}，共 {len(stack['dependencies'])} 项依赖")
    else:
        await ctx.log("未找到依赖清单", "warn")
    for error in stack["errors"]:
        await ctx.log(f"依赖清单解析失败：{error}", "warn")
    if stack["primary_language"] != "Python":
        await ctx.log("首版只对 Python 工程做污点分析与动态验证，后续阶段可能没有结果", "warn")
