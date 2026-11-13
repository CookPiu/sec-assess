"""环境侦察（DESIGN.md 5.1）：准备源码、启动沙箱、识别技术栈与代码行数。"""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import Any

from app.models.enums import SourceType
from app.pipeline.state import TaskContext
from app.project.flask_facts import ACCESS_LABELS, collect_flask_facts
from app.project.ingest import IngestError, clone_repo, dir_size
from app.project.pysource import ProjectIndex
from app.project.stack import analyze_stack
from app.sandbox.deps import prepare_dependencies

PASSWORD_STORAGE_LABELS = {
    "plaintext": "明文",
    "unsalted_hash": "无盐哈希",
    "salted_hash": "加盐哈希",
    "unknown": "未识别",
}


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


def facts_lines(facts: dict[str, Any]) -> list[tuple[str, str]]:
    """把侦察事实整理成工作台日志，每项一行。"""
    lines: list[tuple[str, str]] = []
    if not facts["is_flask"]:
        return [("未识别到 Flask 应用对象，动态验证无法启动工程", "warn")]
    entry = facts["entry"]
    if entry["kind"] == "run":
        debug = "，开启 debug" if entry["debug"] else ""
        lines.append((f"启动方式：{entry['file']} 第 {entry['line']} 行调用 app.run（{entry['app']}），端口 {entry['port']}{debug}", "info"))
    elif entry["kind"] == "factory":
        lines.append((f"启动方式：工厂函数 {entry['app']}，端口按默认 {entry['port']}", "info"))
    else:
        lines.append((f"启动方式：未找到 app.run，按 flask run 加载 {entry['app']}，端口 {entry['port']}", "info"))

    routes = facts["routes"]
    access = Counter(r["access"] for r in routes)
    detail = "、".join(f"{ACCESS_LABELS[k]} {access[k]}" for k in ACCESS_LABELS if access[k])
    lines.append((f"路由 {len(routes)} 条" + (f"，访问前提：{detail}" if detail else ""), "info"))

    for kind, label in (("register", "注册"), ("login", "登录")):
        ep = facts["auth"].get(kind)
        if ep:
            lines.append((f"{label}接口：{ep['method']} {ep['path']}，字段 {'、'.join(ep['fields'])}（{ep['content']}）", "info"))
        else:
            lines.append((f"未识别到{label}接口", "warn"))

    storage = facts["password_storage"]
    where = f"，{storage['file']}:{storage['line']}" if storage.get("file") else ""
    kind_text = PASSWORD_STORAGE_LABELS.get(storage["kind"], "未识别")
    detail_text = f"（{storage['detail']}{where}）" if storage.get("detail") else ""
    lines.append((f"密码存储：{kind_text}{detail_text}", "info"))

    session = facts["session"]
    if session["flask_login"]:
        lines.append(("会话：Flask-Login，登录态保存在 Flask 签名 Cookie", "info"))
    elif session["flask_session"]:
        lines.append(("会话：Flask 签名 Cookie", "info"))
    if session["jwt"]:
        lines.append(("会话：使用 JWT", "info"))

    errors = facts["parse_errors"]
    if errors:
        more = f" 等 {len(errors)} 个" if len(errors) > 3 else ""
        lines.append((f"Python 文件解析失败：{'；'.join(errors[:3])}{more}，这些文件不参与分析", "warn"))
    return lines


async def run(ctx: TaskContext) -> None:
    await ensure_source(ctx)
    ctx.check_stop()
    await ctx.start_sandbox()
    ctx.check_stop()

    stack = await asyncio.to_thread(analyze_stack, ctx.source_dir)
    index = await asyncio.to_thread(ProjectIndex, ctx.source_dir)
    facts = await asyncio.to_thread(collect_flask_facts, index) if index.modules else None
    await ctx.update_task(recon={"stack": stack, "facts": facts})
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
    if facts is not None:
        for line, level in facts_lines(facts):
            await ctx.log(line, level)
        ctx.check_stop()
        await prepare_dependencies(ctx, stack["dependencies"])
