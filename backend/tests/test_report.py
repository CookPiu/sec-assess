"""报告渲染、报告 Agent 与报告接口（T039–T041）。"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.core.db import session_factory
from app.models import AuditLog, Evidence, Finding, Report, StageLog, TaintStep, Task
from app.models.enums import Stage, TaskStatus, VerifyStatus
from app.pipeline.agents import chain, report
from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex
from app.report import pdf
from app.report.render import load_report_data, markdown_to_html, md_code, md_fence, render_markdown

from tests.test_chain_agent import SHOP, TARGETS, logs, make_ctx, seed


@pytest.fixture(scope="module")
def shop_facts() -> dict[str, Any]:
    return collect_flask_facts(ProjectIndex(TARGETS / "shop-admin"))


SECTIONS = [
    "## 一、项目概况与执行信息",
    "### 多 Agent 执行摘要",
    "## 二、安全评分与风险大盘",
    "### CVSS 分布矩阵",
    "### 漏洞类型占比",
    "## 三、已验证漏洞清单",
    "## 四、多步攻击路径推演",
    "## 五、安全整改建议",
]


def complete(run_async, task_id: int, *, sqli_response: str = "HTTP/1.1 200 OK\r\n\r\n5.7.0") -> None:
    """补上污点步骤、证据、阶段日志并把任务置为已完成。"""

    async def _complete() -> None:
        async with session_factory()() as session:
            sqli = (
                await session.execute(
                    select(Finding).where(Finding.task_id == task_id, Finding.category == "sql_injection")
                )
            ).scalar_one_or_none()
            if sqli is not None:
                sqli.cvss_score, sqli.severity = 9.8, "critical"
                sqli.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                session.add_all(
                    [
                        TaintStep(finding_id=sqli.id, seq=1, file="shop/orders.py", line=10, snippet="kw = request.args['q']", note="读取查询参数"),
                        TaintStep(finding_id=sqli.id, seq=2, file="shop/orders.py", line=12, snippet="db.execute(f\"...{kw}\")", note="拼进 SQL"),
                        Evidence(
                            finding_id=sqli.id,
                            case={},
                            request_raw="GET /orders/search?q=%27 HTTP/1.1",
                            response_raw=sqli_response,
                            matched="响应中出现数据库版本",
                            hit=True,
                        ),
                    ]
                )
            for stage in (Stage.RECON, Stage.CODE_AUDIT, Stage.POC_VERIFY):
                session.add(StageLog(task_id=task_id, stage=stage, message=f"阶段开始：{stage}"))
            await session.execute(update(Task).where(Task.id == task_id).values(status=TaskStatus.COMPLETED))
            await session.commit()

    run_async(_complete)


@pytest.fixture
def shop_task(run_async, shop_facts) -> int:
    task_id = seed(run_async, shop_facts)
    run_async(chain.run, make_ctx(task_id))
    complete(run_async, task_id)
    return task_id


def render(run_async, task_id: int) -> str:
    async def _render() -> str:
        return render_markdown(await load_report_data(task_id))

    return run_async(_render)


def test_markdown_filters() -> None:
    assert md_code("a`b") == "``a`b``"
    assert md_code("`x`") == "`` `x` ``"
    assert md_fence("x\n```\ny", "http") == "````http\nx\n```\ny\n````"


def test_markdown_has_all_sections(run_async, shop_task) -> None:
    markdown = render(run_async, shop_task)
    positions = [markdown.index(title) for title in SECTIONS]
    assert positions == sorted(positions)
    # SQL 注入 CVSS 9.8 且位于执行代码路径上
    assert "综合安全等级：**极高危**，安全评分：**0** / 100" in markdown
    assert f"存在 CVSS ≥ 9.0 的已验证漏洞（SA-{shop_task}-002）；存在能到达执行代码的多步攻击路径" in markdown
    assert "| 严重（9.0–10.0） | 1 | 0 | 1 |" in markdown
    assert "![漏洞类型占比饼图](data:image/svg+xml;base64," in markdown
    assert "1. `shop/orders.py:10` 读取查询参数：`kw = request.args['q']`" in markdown
    assert "命中特征：响应中出现数据库版本" in markdown
    assert "共推演出 8 条多步攻击路径，其中 8 条可到达执行代码。" in markdown
    assert "### P1 立即修复" in markdown and "### P4 排期加固" in markdown
    # 整改建议按优先级排序：SQL 注入排第一，疑似的硬编码密钥排最后
    first = markdown.index(f"1. **SA-{shop_task}-002")
    last = markdown.index(f"**SA-{shop_task}-007")
    assert first < last
    assert "改用参数化查询" in markdown


def test_html_escapes_target_content(run_async, shop_facts) -> None:
    task_id = seed(run_async, shop_facts)
    run_async(chain.run, make_ctx(task_id))
    complete(run_async, task_id, sqli_response="HTTP/1.1 200 OK\r\n\r\n<script>alert(1)</script>```<img src=x>")
    markdown = render(run_async, task_id)
    html = markdown_to_html(markdown, "报告")
    assert "<script>alert(1)" not in html and "<img src=x>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert '<img src="data:image/svg+xml;base64,' in html
    assert html.count("<h2>") == 5


def test_report_without_findings(run_async, shop_facts) -> None:
    task_id = seed(run_async, shop_facts, [])
    complete(run_async, task_id)
    markdown = render(run_async, task_id)
    assert "综合安全等级：**安全**，安全评分：**100** / 100" in markdown
    assert "本次评估没有发现漏洞，也没有可推演的攻击路径。" in markdown
    assert "本次评估没有已验证漏洞。" in markdown
    assert "本次评估没有已验证漏洞，不生成攻击路径。" in markdown
    assert "本次评估没有需要整改的漏洞。" in markdown


def test_report_explains_missing_multi_step_path(run_async, shop_facts) -> None:
    only_admin = [(1, "command_injection", "/admin/logistics/ping", "admin", VerifyStatus.VERIFIED)]
    task_id = seed(run_async, shop_facts, only_admin)
    run_async(chain.run, make_ctx(task_id))
    complete(run_async, task_id)
    assert "已验证漏洞获得的能力无法衔接到“执行代码”或“读他人数据”" in render(run_async, task_id)


async def saved_report(task_id: int) -> Report | None:
    async with session_factory()() as session:
        return (await session.execute(select(Report).where(Report.task_id == task_id))).scalar_one_or_none()


def test_agent_template_text(run_async, shop_task) -> None:
    run_async(report.run, make_ctx(shop_task))
    run_async(report.run, make_ctx(shop_task))  # 重复执行只保留一份
    saved = run_async(saved_report, shop_task)
    assert saved.written_by == "template" and saved.actions == {}
    assert saved.conclusion.startswith("本次评估共发现 8 条问题，其中已验证 7 条、疑似 1 条。")
    messages = run_async(logs, shop_task)
    assert any(m.startswith("安全评分 0，综合安全等级：极高危") for m in messages)
    assert "大模型未启用，评估结论按统计数据生成，整改行动采用漏洞类别的默认指引" in messages
    assert "报告已生成：5 个章节，已验证漏洞 7 条、多步攻击路径 8 条、整改建议 8 条，可在报告中心预览与导出" in messages


class FakeLLM:
    configured = True

    def __init__(self, reply: dict[str, Any] | None) -> None:
        self.reply = reply
        self.prompts: list[str] = []

    async def chat_json(
        self, system: str, user: str, *, enabled: bool = True, timeout: float | None = None
    ) -> dict[str, Any] | None:
        self.prompts.append(user)
        return self.reply


def test_agent_model_text_and_fallback(run_async, shop_task, monkeypatch) -> None:
    code = f"SA-{shop_task}-002"
    fake = FakeLLM({"conclusion": "模型写的结论", "actions": {code: "模型写的整改行动", "SA-0-999": "不存在的编号", f"SA-{shop_task}-003": " "}})
    monkeypatch.setattr(report, "get_llm", lambda **_: fake)
    run_async(report.run, make_ctx(shop_task, llm_enabled=True))
    # 补丁生成也会调用模型，这里只看撰写报告文字的那一次
    prompts = [p for p in fake.prompts if p.startswith("综合安全等级")]
    assert len(prompts) == 1
    assert "综合安全等级：极高危" in prompts[0] and f"- {code} [P1 立即修复] SQL 注入" in prompts[0]
    saved = run_async(saved_report, shop_task)
    assert saved.written_by == "model" and saved.conclusion == "模型写的结论"
    assert saved.actions == {code: "模型写的整改行动"}
    assert "7 条漏洞没有拿到模型写的整改行动，改用类别默认指引" in run_async(logs, shop_task)
    markdown = render(run_async, shop_task)
    assert "模型写的结论" in markdown and "模型写的整改行动" in markdown

    fake.reply = {"conclusion": "", "actions": []}
    run_async(report.run, make_ctx(shop_task, llm_enabled=True))
    assert run_async(saved_report, shop_task).written_by == "template"
    assert "模型输出不可用，评估结论改用按统计数据生成的文字" in run_async(logs, shop_task)


def test_report_api(client: TestClient, login, run_async, shop_task, shop_facts) -> None:
    engineer = login("engineer")
    listed = client.get("/api/reports", headers=login("admin")).json()
    item = next(r for r in listed if r["task_id"] == shop_task)
    assert item["level"] == "极高危" and item["score"] == 0 and item["counts"]["critical"] == 1

    running = seed(run_async, shop_facts, SHOP[:1])
    assert all(r["task_id"] != running for r in listed)
    assert client.get(f"/api/tasks/{running}/report", headers=engineer).status_code == 409
    assert client.get("/api/tasks/99999/report", headers=engineer).status_code == 404
    assert client.get(f"/api/tasks/{shop_task}/report").status_code == 401

    preview = client.get(f"/api/tasks/{shop_task}/report", headers=login("developer")).json()
    assert preview["title"] == "chain 安全评估报告" and preview["level"] == "极高危"
    assert preview["html"].startswith("<!doctype html>") and "<h2>五、安全整改建议</h2>" in preview["html"]

    md = client.get(f"/api/tasks/{shop_task}/report/export", params={"format": "md"}, headers=engineer)
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert md.text.startswith("# chain 安全评估报告")
    disposition = md.headers["content-disposition"]
    assert f'filename="report-task-{shop_task}.md"' in disposition and "filename*=UTF-8''chain%20" in disposition

    html = client.get(f"/api/tasks/{shop_task}/report/export", params={"format": "html"}, headers=login("developer"))
    assert html.status_code == 200 and "<h2>三、已验证漏洞清单</h2>" in html.text
    # 三种格式由同一份 Markdown 生成
    assert preview["html"].split("<h1>")[1].split("报告生成时间")[0] == html.text.split("<h1>")[1].split("报告生成时间")[0]

    assert client.get(f"/api/tasks/{shop_task}/report/export", params={"format": "md"}, headers=login("admin")).status_code == 403
    assert client.get(f"/api/tasks/{shop_task}/report/export", params={"format": "doc"}, headers=engineer).status_code == 422

    async def exports() -> list[tuple[str, dict]]:
        async with session_factory()() as session:
            rows = await session.execute(
                select(AuditLog.username, AuditLog.detail).where(
                    AuditLog.action == "report_export", AuditLog.target_id == str(shop_task)
                )
            )
            return [(name, detail["format"]) for name, detail in rows]

    assert run_async(exports) == [("engineer", "md"), ("developer", "html")]


def test_pdf_export(client: TestClient, login, run_async, shop_task, monkeypatch) -> None:
    try:
        sample = pdf.html_to_pdf("<!doctype html><meta charset='utf-8'><p>测试</p>")
    except pdf.PdfUnavailable:
        pytest.skip("本机没有可用的 Chromium 内核浏览器")
    assert sample.startswith(b"%PDF")
    resp = client.get(f"/api/tasks/{shop_task}/report/export", params={"format": "pdf"}, headers=login("engineer"))
    assert resp.status_code == 200 and resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF") and len(resp.content) > 20_000

    def unavailable(html: str) -> bytes:
        raise pdf.PdfUnavailable("没有可用的 Chromium 内核浏览器")

    monkeypatch.setattr(pdf, "html_to_pdf", unavailable)
    resp = client.get(f"/api/tasks/{shop_task}/report/export", params={"format": "pdf"}, headers=login("engineer"))
    assert resp.status_code == 503 and resp.json()["detail"] == "没有可用的 Chromium 内核浏览器"
