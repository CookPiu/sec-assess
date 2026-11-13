"""源码审计阶段：大模型研判（用假模型）、回退默认向量、发给模型的内容范围。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from textwrap import dedent

from app.core.llm import MAX_INPUT_CHARS
from app.models.enums import Category, JudgedBy, Severity
from app.pipeline.agents import audit
from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex

APP = """
import sqlite3

from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "hardcoded-dev-secret"


def unrelated_helper():
    return "UNRELATED_MARKER"


@app.get("/search")
def search():
    q = request.args.get("q", "")
    return str(sqlite3.connect("x.db").execute(f"SELECT * FROM t WHERE name = '{q}'").fetchall())


@app.get("/files")
def files():
    with open("data/" + request.args["name"]) as fh:
        return fh.read()


if __name__ == "__main__":
    app.run(debug=True)
"""


class FakeLLM:
    """按候选类别返回预设结论，并记录收到的内容和最大并发数。"""

    def __init__(self, replies: dict[str, dict | None]) -> None:
        self.replies = replies
        self.prompts: list[str] = []
        self.active = 0
        self.peak = 0

    @property
    def configured(self) -> bool:
        return True

    async def chat_json(self, system: str, user: str, *, enabled: bool = True):
        assert len(system) + len(user) <= MAX_INPUT_CHARS
        self.prompts.append(user)
        self.active += 1
        self.peak = max(self.peak, self.active)
        await asyncio.sleep(0.01)
        self.active -= 1
        category = next(c for c in self.replies if f"（{c}）" in user)
        return self.replies[category]


def prepare(tmp_path: Path):
    (tmp_path / "app.py").write_text(dedent(APP), encoding="utf-8")
    index = ProjectIndex(tmp_path)
    candidates, counts = audit.collect_candidates(index, collect_flask_facts(index))
    return index, candidates, counts


def test_collects_candidates_from_all_rules(tmp_path: Path) -> None:
    _, candidates, counts = prepare(tmp_path)
    assert counts == {"taint": 2, "authz": 0, "secrets": 2}
    assert sorted(c.category for c in candidates) == sorted(
        [Category.SQL_INJECTION, Category.PATH_TRAVERSAL, Category.HARDCODED_SECRET, Category.DEBUG_MODE]
    )


def test_falls_back_to_default_vectors_without_model(tmp_path: Path) -> None:
    index, candidates, _ = prepare(tmp_path)

    class Unconfigured(FakeLLM):
        configured = False

    llm = Unconfigured({})
    judgements = asyncio.run(audit.judge_all(index, candidates, llm, enabled=True, concurrency=4))
    assert llm.prompts == []
    assert all(j.judged_by == JudgedBy.DEFAULT and not j.false_positive for j in judgements)
    assert all("未经模型研判" in j.reason for j in judgements)
    sql = judgements[[c.category for c in candidates].index(Category.SQL_INJECTION)]
    assert sql.vector == audit.cvss.default_vector(Category.SQL_INJECTION)
    assert sql.severity in (Severity.CRITICAL, Severity.HIGH)

    # 配置页关闭模型时同样不发请求
    configured = FakeLLM({})
    asyncio.run(audit.judge_all(index, candidates, configured, enabled=False, concurrency=4))
    assert configured.prompts == []


def test_model_judgements_and_fallbacks(tmp_path: Path) -> None:
    index, candidates, _ = prepare(tmp_path)
    llm = FakeLLM(
        {
            Category.SQL_INJECTION: {
                "false_positive": False,
                "category": "sql_injection",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "reason": "查询参数 q 直接拼进 SQL",
            },
            Category.PATH_TRAVERSAL: {"false_positive": True, "category": "path_traversal",
                                      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                      "reason": "演示用误报"},  # fmt: skip
            Category.HARDCODED_SECRET: {"false_positive": False, "cvss_vector": "not a vector", "reason": "密钥写死"},
            Category.DEBUG_MODE: None,
        }
    )
    judgements = asyncio.run(audit.judge_all(index, candidates, llm, enabled=True, concurrency=2))
    by_cat = {c.category: j for c, j in zip(candidates, judgements, strict=True)}

    sql = by_cat[Category.SQL_INJECTION]
    assert (sql.judged_by, sql.score, sql.severity, sql.false_positive) == (JudgedBy.MODEL, 9.8, Severity.CRITICAL, False)
    assert sql.reason == "查询参数 q 直接拼进 SQL"
    assert by_cat[Category.PATH_TRAVERSAL].false_positive is True
    secret = by_cat[Category.HARDCODED_SECRET]
    assert secret.judged_by == JudgedBy.MODEL and secret.vector == audit.cvss.default_vector(Category.HARDCODED_SECRET)
    assert "向量无效" in secret.reason
    debug = by_cat[Category.DEBUG_MODE]
    assert debug.judged_by == JudgedBy.DEFAULT and "模型调用失败" in debug.reason

    assert len(llm.prompts) == 4 and llm.peak <= 2
    sql_prompt = next(p for p in llm.prompts if "（sql_injection）" in p)
    assert "def search():" in sql_prompt and "UNRELATED_MARKER" not in sql_prompt
    assert "路由：GET /search，访问前提：匿名" in sql_prompt
    secret_prompt = next(p for p in llm.prompts if "（hardcoded_secret）" in p)
    assert 'SECRET_KEY = "hardcoded-dev-secret"' in secret_prompt


def test_prompt_is_capped_for_huge_functions(tmp_path: Path) -> None:
    body = "\n".join(f"    x{i} = {i}" for i in range(3000))
    (tmp_path / "app.py").write_text(
        dedent("""
            import os
            from flask import Flask, request

            app = Flask(__name__)


            @app.post("/run")
            def run():
            """) + body + '\n    os.system("echo " + request.form["v"])\n',
        encoding="utf-8",
    )
    index = ProjectIndex(tmp_path)
    candidates, _ = audit.collect_candidates(index, collect_flask_facts(index))
    functions = {fn.qualname: fn for fn in index.functions.values()}
    prompt = audit.build_prompt(index, candidates[0], functions)
    assert len(prompt) <= audit.MAX_PROMPT_CHARS + audit.MAX_FUNCTION_CHARS
    assert len(audit.SYSTEM_PROMPT) + len(prompt) <= MAX_INPUT_CHARS
