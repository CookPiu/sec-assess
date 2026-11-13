"""补丁生成、接入报告阶段与补丁接口（T043–T045）。"""

from __future__ import annotations

import ast
import asyncio
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import session_factory
from app.core.runtime import RuntimeConfig
from app.models import AuditLog, Finding, Patch, Project, StageLog, Task
from app.models.enums import Severity, SourceType, TaskStatus, VerifyStatus
from app.patch import generate
from app.patch.diff import PatchApplyError, apply_diff, diff_stats, unified_diff
from app.patch.generate import PatchRejected, PatchTarget, SourceFile, apply_fix, locate_segment, read_source
from app.pipeline.agents import report
from app.pipeline.state import TaskContext
from app.report.render import load_report_data, render_markdown
from tests.test_chain_agent import TARGETS

SHOP = TARGETS / "shop-admin"
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="本机没有 git")


def git_apply_check(root: Path, diff: str) -> subprocess.CompletedProcess[bytes]:
    # 以字节写入，避免 Windows 文本管道改写换行符和编码
    return subprocess.run(["git", "apply", "--check", "-"], cwd=root, input=diff.encode("utf-8"), capture_output=True)


def source_of(text: str, path: str = "m.py") -> SourceFile:
    return SourceFile(path, text, ast.parse(text))


# ---------- diff ----------


@needs_git
@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("a = 1\nb = 2\nc = 3\n", "a = 1\nb = 20\nc = 3\nd = 4\n"),
        ("import os\r\n\r\ndef f(x):\r\n    return os.system(x)\r\n", "import os\r\nimport shlex\r\n\r\ndef f(x):\r\n    return os.system(shlex.quote(x))\r\n"),
        ("x = 1\ny = 2", "x = 1\ny = 3"),
    ],
    ids=["lf", "crlf", "no-newline-at-eof"],
)
def test_diff_round_trip_and_git_apply(tmp_path: Path, old: str, new: str) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "m.py").write_bytes(old.encode("utf-8"))
    diff = unified_diff("pkg/m.py", old, new)
    assert diff.startswith("diff --git a/pkg/m.py b/pkg/m.py\n--- a/pkg/m.py\n+++ b/pkg/m.py\n@@ ")
    assert apply_diff(old, diff) == new
    result = git_apply_check(tmp_path, diff)
    assert result.returncode == 0, result.stderr


def test_apply_diff_rejects_changed_source() -> None:
    diff = unified_diff("m.py", "a = 1\nb = 2\n", "a = 1\nb = 3\n")
    assert diff_stats(diff) == (1, 1)
    with pytest.raises(PatchApplyError):
        apply_diff("a = 1\nb = 5\n", diff)
    assert unified_diff("m.py", "a\n", "a\n") == ""


# ---------- 定位代码段 ----------


def test_locate_segment_function_statement_and_nested() -> None:
    admin = read_source(SHOP, "shop/admin.py")
    seg = locate_segment(admin, 27)
    assert (seg.start, seg.end, seg.indent, seg.name) == (23, 28, "", "logistics_ping")
    assert admin.lines[22].startswith('@bp.post("/logistics/ping")')

    app = read_source(SHOP, "app.py")
    assert locate_segment(app, 24) == generate.Segment(23, 24, "", None)

    src = source_of(
        "class Config:\n"
        "    DEBUG = True\n"
        "\n"
        "    def load(self):\n"
        "        def inner(x):\n"
        "            return eval(x)\n"
        "        return inner\n"
    )
    assert locate_segment(src, 2) == generate.Segment(2, 2, "    ", None)
    assert locate_segment(src, 6) == generate.Segment(5, 6, "        ", "inner")
    with pytest.raises(PatchRejected):
        locate_segment(src, 99)


def test_read_source_rejects_outside_paths() -> None:
    for rel in ("../shop-admin/app.py", "missing.py"):
        with pytest.raises(PatchRejected, match="找不到源码文件"):
            read_source(SHOP, rel)


# ---------- 校验模型输出 ----------

FIXED_PING = '''@bp.post("/logistics/ping")
@admin_required
def logistics_ping():
    host = request.form.get("host", "")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
        return jsonify({"error": "主机名不合法"}), 400
    result = subprocess.run(["ping", "-c", "1", "-W", "1", host], capture_output=True, text=True, timeout=10)
    return jsonify({"output": result.stdout + result.stderr})'''


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        ({"code": ""}, "没有给出修复后的代码"),
        ({"code": "def other():\n    pass"}, "必须是函数 logistics_ping 的一个完整定义"),
        ({"code": "def logistics_ping(:\n"}, "语法错误"),
        ({"code": FIXED_PING, "imports": ["os.system('id')"]}, "不是单条导入语句"),
        ({"code": FIXED_PING, "imports": "import re"}, "imports 必须是"),
        ({"code": FIXED_PING, "imports": ["from __future__ import annotations"]}, "__future__"),
    ],
)
def test_apply_fix_rejects_invalid_output(reply: dict[str, Any], message: str) -> None:
    admin = read_source(SHOP, "shop/admin.py")
    with pytest.raises(PatchRejected, match=message):
        apply_fix(reply, admin, locate_segment(admin, 27))


def test_apply_fix_rejects_unchanged_code() -> None:
    admin = read_source(SHOP, "shop/admin.py")
    seg = locate_segment(admin, 27)
    with pytest.raises(PatchRejected, match="与原代码相同"):
        apply_fix({"code": generate.segment_code(admin, seg)}, admin, seg)


@needs_git
def test_apply_fix_builds_patch_that_applies(tmp_path: Path) -> None:
    shutil.copytree(SHOP, tmp_path / "src")
    admin = read_source(tmp_path / "src", "shop/admin.py")
    seg = locate_segment(admin, 27)
    # 模型整体多缩进一层、包了代码块、重复导入已有模块，都能被规整
    indented = "\n".join(f"    {line}" if line else "" for line in FIXED_PING.split("\n"))
    reply = {"code": f"```python\n{indented}\n```", "imports": ["import re", "import os", "import re"], "summary": "改用列表参数"}
    new_text, summary = apply_fix(reply, admin, seg)
    assert summary == "改用列表参数"
    lines = new_text.split("\n")
    # 新导入紧跟在开头导入块之后，原有的 import os 不重复添加
    assert lines[lines.index("from shop.auth import admin_required") + 1] == "import re"
    assert new_text.count("import os\n") == 1
    assert FIXED_PING in new_text

    diff = unified_diff("shop/admin.py", admin.text, new_text)
    assert apply_diff(admin.text, diff) == new_text
    assert git_apply_check(tmp_path / "src", diff).returncode == 0

    # 模块级语句：调试模式开关
    app = read_source(SHOP, "app.py")
    fixed = 'if __name__ == "__main__":\n    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")'
    new_app, _ = apply_fix({"code": fixed, "imports": ["import os"]}, app, locate_segment(app, 24))
    assert new_app.startswith('"""shop-admin 电商后台教学靶场入口。')
    assert "from shop import admin, auth, public\nimport os\n" in new_app
    assert git_apply_check(tmp_path / "src", unified_diff("app.py", app.text, new_app)).returncode == 0


# ---------- 调用模型与重试 ----------

PATCH_PROMPT_MARK = "需要修改的代码段（"


def auto_fix(prompt: str) -> dict[str, Any]:
    """在代码段末尾加一行注释，并新增一条导入。"""
    code = prompt[prompt.index(PATCH_PROMPT_MARK) :].split("：\n", 1)[1]
    return {"code": f"{code}\n# 已修复", "imports": ["import shlex"], "summary": "测试修复"}


class FakeLLM:
    configured = True

    def __init__(self, replies: list[dict[str, Any] | None] | None = None, report_reply: dict[str, Any] | None = None):
        self.replies = list(replies or [])
        self.report_reply = report_reply
        self.patch_prompts: list[str] = []

    async def chat_json(
        self, system: str, user: str, *, enabled: bool = True, timeout: float | None = None
    ) -> dict[str, Any] | None:
        if system != generate.SYSTEM_PROMPT:
            return self.report_reply
        self.patch_prompts.append(user)
        return self.replies.pop(0) if self.replies else auto_fix(user)


def ping_target(**kwargs: Any) -> PatchTarget:
    values = {
        "finding_id": 1,
        "code": "SA-1-001",
        "category": "command_injection",
        "title": "命令注入：POST /admin/logistics/ping",
        "file": "shop/admin.py",
        "line": 27,
        "route": {"path": "/admin/logistics/ping", "methods": ["POST"], "access": "admin"},
        "reason": "主机名拼进 shell 命令",
        "steps": [("shop/admin.py", 26, 'host = request.form.get("host", "")', "读取用户输入")],
    }
    return PatchTarget(**{**values, **kwargs})


def test_generate_patch_retries_with_feedback() -> None:
    fake = FakeLLM([{"code": "def other():\n    pass"}, {"code": FIXED_PING, "imports": ["import re"], "summary": "改用列表参数"}])
    result = asyncio.run(generate.generate_patch(fake, SHOP, ping_target()))
    assert result.error is None and result.summary == "改用列表参数"
    assert diff_stats(result.diff) == (4, 1)
    first, second = fake.patch_prompts
    assert "入口路由：POST /admin/logistics/ping，访问前提：管理员" in first
    assert "参考修复方向：去掉 shell=True" in first
    assert "1. shop/admin.py:26" in first
    assert "from shop.auth import admin_required" in first
    assert '@bp.post("/logistics/lookup")' in first and "def logistics_lookup():" in first
    assert "工程自带装饰器的源码：\n--- shop/auth.py 中的 admin_required ---\ndef admin_required(view):" in first
    assert "需要修改的代码段（shop/admin.py 第 23–28 行，函数 logistics_ping）：\n@bp.post" in first
    assert second.endswith("上一次输出未通过校验：修复后的代码必须是函数 logistics_ping 的一个完整定义。请按要求重新输出。")


def test_generate_patch_gives_up_with_reason() -> None:
    result = asyncio.run(generate.generate_patch(FakeLLM([None, None]), SHOP, ping_target()))
    assert result.diff is None and result.error == "模型调用失败或输出不是 JSON"
    result = asyncio.run(generate.generate_patch(FakeLLM(), SHOP, ping_target(file="shop/missing.py")))
    assert result.error == "找不到源码文件 shop/missing.py"


# ---------- 报告阶段与接口 ----------

# (类别, 文件, 行号, 状态)
ITEMS = [
    ("command_injection", "shop/admin.py", 27, VerifyStatus.VERIFIED),
    ("sql_injection", "shop/public.py", 21, VerifyStatus.VERIFIED),
    ("debug_mode", "app.py", 24, VerifyStatus.VERIFIED),
    ("hardcoded_secret", "config.py", 10, VerifyStatus.UNVERIFIED),
]


@pytest.fixture
def patch_task(run_async, app_env) -> tuple[int, Path]:
    async def _seed() -> tuple[int, Path]:
        async with session_factory()() as session:
            project = Project(name="patch", source_type=SourceType.ZIP, source_dir="")
            session.add(project)
            await session.flush()
            project.source_dir = f"projects/patch-{project.id}/src"
            task = Task(project_id=project.id, status=TaskStatus.COMPLETED, recon={})
            session.add(task)
            await session.flush()
            for seq, (category, file, line, status) in enumerate(ITEMS, 1):
                session.add(
                    Finding(
                        task_id=task.id,
                        code=f"SA-{task.id}-{seq:03d}",
                        category=category,
                        title=category,
                        severity=Severity.HIGH,
                        file=file,
                        line=line,
                        status=status,
                    )
                )
            await session.commit()
            return task.id, app_env / project.source_dir

    task_id, root = run_async(_seed)
    shutil.copytree(SHOP, root)
    return task_id, root


def ctx_for(task_id: int, root: Path, *, llm_enabled: bool) -> TaskContext:
    return TaskContext(
        task_id=task_id,
        project_id=0,
        source_type="zip",
        source_url=None,
        source_dir=root,
        runtime=RuntimeConfig(llm_enabled=llm_enabled),
        sandbox=None,
    )


async def task_patches(task_id: int) -> dict[str, Patch]:
    async with session_factory()() as session:
        rows = await session.execute(
            select(Finding.code, Patch).join(Patch, Patch.finding_id == Finding.id).where(Finding.task_id == task_id)
        )
        return dict(rows.all())


async def task_logs(task_id: int) -> list[str]:
    async with session_factory()() as session:
        return list((await session.execute(select(StageLog.message).where(StageLog.task_id == task_id))).scalars())


async def finding_id(code: str) -> int:
    async with session_factory()() as session:
        return await session.scalar(select(Finding.id).where(Finding.code == code))


def render(run_async, task_id: int) -> str:
    async def _render() -> str:
        return render_markdown(await load_report_data(task_id))

    return run_async(_render)


def test_report_stage_skips_patches_without_model(run_async, patch_task) -> None:
    task_id, root = patch_task
    run_async(report.run, ctx_for(task_id, root, llm_enabled=False))
    assert run_async(task_patches, task_id) == {}
    assert "大模型已在配置页关闭，跳过 3 条已验证漏洞的补丁生成" in run_async(task_logs, task_id)
    assert "暂无修复补丁。" in render(run_async, task_id)


@needs_git
def test_report_stage_generates_patches(run_async, patch_task, monkeypatch) -> None:
    task_id, root = patch_task
    fake = FakeLLM()
    monkeypatch.setattr(report, "get_llm", lambda: fake)
    run_async(report.run, ctx_for(task_id, root, llm_enabled=True))

    patches = run_async(task_patches, task_id)
    assert set(patches) == {f"SA-{task_id}-001", f"SA-{task_id}-002", f"SA-{task_id}-003"}
    for patch in patches.values():
        assert not patch.adopted
        assert git_apply_check(root, patch.diff).returncode == 0
    messages = run_async(task_logs, task_id)
    assert "交给大模型为 3 条已验证漏洞生成修复补丁，并发 4" in messages
    assert f"SA-{task_id}-001 补丁已生成：测试修复（shop/admin.py，+2 -0）" in messages
    assert "补丁生成完成：3 条已验证漏洞中 3 条生成补丁" in messages
    markdown = render(run_async, task_id)
    assert markdown.count("采纳状态：未采纳") == 3 and "```diff\ndiff --git a/shop/admin.py" in markdown


@needs_git
def test_patch_api(client: TestClient, login, run_async, patch_task, monkeypatch) -> None:
    task_id, root = patch_task
    monkeypatch.setattr(report, "get_llm", lambda: FakeLLM())
    run_async(report.run, ctx_for(task_id, root, llm_enabled=True))
    fid = run_async(finding_id, f"SA-{task_id}-001")
    engineer, developer, admin = login("engineer"), login("developer"), login("admin")

    body = client.get(f"/api/findings/{fid}/patch", headers=engineer).json()
    original = (root / "shop/admin.py").read_text(encoding="utf-8")
    assert body["finding_code"] == f"SA-{task_id}-001" and body["file"] == "shop/admin.py"
    assert body["original"] == original and body["patched"] == apply_diff(original, body["diff"])
    assert "# 已修复" in body["patched"] and (body["added"], body["removed"]) == (2, 0)
    assert body["adopted"] is False and body["adopted_by"] is None

    resp = client.get(f"/api/findings/{fid}/patch/download", headers=admin)
    assert resp.status_code == 200 and resp.text == body["diff"]
    assert resp.headers["content-disposition"] == f'attachment; filename="SA-{task_id}-001.patch"'

    for headers in (engineer, admin):
        assert client.post(f"/api/findings/{fid}/patch/adopt", headers=headers).status_code == 403
    adopted = client.post(f"/api/findings/{fid}/patch/adopt", headers=developer)
    assert adopted.status_code == 200, adopted.text
    assert adopted.json()["adopted"] is True and adopted.json()["adopted_by"] == "developer"
    again = client.post(f"/api/findings/{fid}/patch/adopt", headers=developer)
    assert again.status_code == 409 and again.json()["detail"] == "补丁已经采纳"

    async def audits() -> list[AuditLog]:
        async with session_factory()() as session:
            rows = await session.execute(
                select(AuditLog).where(AuditLog.action == "patch_adopt", AuditLog.target_id == str(fid))
            )
            return list(rows.scalars())

    [entry] = run_async(audits)
    assert entry.username == "developer" and entry.detail == {"finding_code": f"SA-{task_id}-001", "file": "shop/admin.py"}
    assert "采纳状态：已采纳，采纳人 developer，采纳时间 " in render(run_async, task_id)

    unverified = run_async(finding_id, f"SA-{task_id}-004")
    missing = client.get(f"/api/findings/{unverified}/patch", headers=engineer)
    assert missing.status_code == 404 and missing.json()["detail"] == "该漏洞没有修复补丁"
    assert client.get("/api/findings/999999/patch", headers=engineer).status_code == 404

    # 源码文件变化后补丁对不上，只返回 diff
    (root / "shop/admin.py").write_text("changed = True\n", encoding="utf-8")
    body = client.get(f"/api/findings/{fid}/patch", headers=engineer).json()
    assert body["original"] is None and body["patched"] is None and body["diff"]
