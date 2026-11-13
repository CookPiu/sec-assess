"""污点引擎：每个用例是一小段 Flask 处理函数，检查是否报出候选以及轨迹。"""

from pathlib import Path
from textwrap import dedent

import pytest

from app.models.enums import Category
from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex
from app.taint.engine import find_taint_candidates

HEADER = """
import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, render_template_string, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
db = sqlite3.connect(":memory:")
COLUMNS = {"price": "price", "time": "created_at"}
"""


def analyze(tmp_path: Path, files: dict[str, str]):
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(dedent(text), encoding="utf-8")
    index = ProjectIndex(tmp_path)
    return find_taint_candidates(index, collect_flask_facts(index)["routes"])


def single(tmp_path: Path, handler: str):
    return analyze(tmp_path, {"app.py": HEADER + dedent(handler)})


FLAGGED = [
    (
        Category.SQL_INJECTION,
        """
        @app.get("/a")
        def a():
            q = request.args.get("q", "")
            sql = f"SELECT * FROM t WHERE name = '{q}'"
            return str(db.execute(sql).fetchall())
        """,
    ),
    (
        Category.SQL_INJECTION,
        """
        @app.get("/a")
        def a():
            sql = "SELECT * FROM t ORDER BY %s" % request.args["sort"]
            return str(db.execute(sql).fetchall())
        """,
    ),
    (
        Category.SQL_INJECTION,
        """
        @app.get("/a")
        def a():
            sql = "SELECT * FROM t WHERE id = {}".format(request.args["id"])
            return str(db.execute(sql).fetchall())
        """,
    ),
    (
        Category.SQL_INJECTION,
        """
        @app.get("/a/<name>")
        def a(name):
            sql = "SELECT * FROM t WHERE name = '"
            sql += name + "'"
            return str(db.execute(sql).fetchall())
        """,
    ),
    (
        Category.COMMAND_INJECTION,
        """
        @app.post("/a")
        def a():
            host = request.form["host"].strip()
            return subprocess.check_output("ping -c 1 " + host, shell=True)
        """,
    ),
    (
        Category.COMMAND_INJECTION,
        """
        @app.post("/a")
        def a():
            os.system("nslookup " + request.json["domain"])
            return "ok"
        """,
    ),
    (
        Category.TEMPLATE_INJECTION,
        """
        @app.post("/a")
        def a():
            return render_template_string("<p>" + request.form.get("body", "") + "</p>")
        """,
    ),
    (
        Category.DESERIALIZATION,
        """
        @app.post("/a")
        def a():
            raw = request.files["backup"].read()
            return str(pickle.loads(raw))
        """,
    ),
    (
        Category.DESERIALIZATION,
        """
        @app.post("/a")
        def a():
            return str(yaml.load(request.get_data()))
        """,
    ),
    (
        Category.PATH_TRAVERSAL,
        """
        @app.post("/a")
        def a():
            f = request.files["image"]
            f.save(os.path.join("static/uploads", f.filename))
            return "ok"
        """,
    ),
    (
        Category.PATH_TRAVERSAL,
        """
        @app.get("/files/<path:name>")
        def a(name):
            with open(os.path.join("files", name)) as fh:
                return fh.read()
        """,
    ),
    (
        Category.PATH_TRAVERSAL,
        """
        @app.get("/a")
        def a():
            return send_file("reports/" + request.args["f"])
        """,
    ),
]


@pytest.mark.parametrize(("category", "handler"), FLAGGED)
def test_flags_tainted_sinks(tmp_path: Path, category: Category, handler: str) -> None:
    candidates = single(tmp_path, handler)
    assert [c.category for c in candidates] == [category], candidates
    cand = candidates[0]
    assert cand.route is not None and cand.route["path"].startswith(("/a", "/files"))
    assert cand.function == "app.a"
    assert cand.steps[0].note.startswith(("读取用户输入", "URL 参数"))
    assert cand.steps[-1].line == cand.line and "进入" in cand.steps[-1].note
    assert all(s.file == "app.py" and s.snippet for s in cand.steps)


SAFE = [
    """
    @app.get("/a")
    def a():
        q = request.args.get("q", "")
        return str(db.execute("SELECT * FROM t WHERE name = ?", (q,)).fetchall())
    """,
    """
    @app.get("/a")
    def a():
        column = COLUMNS.get(request.args.get("sort"), "id")
        return str(db.execute("SELECT * FROM t ORDER BY " + column).fetchall())
    """,
    """
    @app.get("/a")
    def a():
        column = request.args.get("sort", "id")
        if column not in ("id", "price"):
            return "bad", 400
        return str(db.execute("SELECT * FROM t ORDER BY %s" % column).fetchall())
    """,
    """
    @app.get("/a")
    def a():
        sort = "price" if request.args.get("sort") == "price" else "id"
        return str(db.execute("SELECT * FROM t ORDER BY " + sort).fetchall())
    """,
    """
    @app.get("/a/<item_id>")
    def a(item_id):
        return str(db.execute("SELECT * FROM t WHERE id = " + str(int(item_id))).fetchall())
    """,
    """
    @app.post("/a")
    def a():
        host = request.form["host"]
        return subprocess.run(["ping", "-c", "1", host], capture_output=True).stdout
    """,
    """
    @app.post("/a")
    def a():
        f = request.files["image"]
        f.save(os.path.join("static/uploads", secure_filename(f.filename)))
        return "ok"
    """,
    """
    @app.post("/a")
    def a():
        return str(yaml.load(request.get_data(), Loader=yaml.SafeLoader))
    """,
    """
    @app.get("/a")
    def a():
        return render_template_string("<p>{{ name }}</p>", name=request.args["name"])
    """,
]


@pytest.mark.parametrize("handler", SAFE)
def test_ignores_safe_patterns(tmp_path: Path, handler: str) -> None:
    assert single(tmp_path, handler) == []


def test_cross_file_calls_up_to_three_levels(tmp_path: Path) -> None:
    candidates = analyze(
        tmp_path,
        {
            "app.py": HEADER + dedent("""
                from services import report, deep


                @app.post("/report")
                def make_report():
                    return report(request.form["name"])


                @app.post("/deep")
                def make_deep():
                    return deep(request.form["name"])
            """),
            "services.py": """
                from repo import query, level2


                def build(name):
                    return "SELECT * FROM r WHERE name = '" + name + "'"


                def report(name):
                    return query(build(name))


                def deep(name):
                    return level2(name)
            """,
            "repo.py": """
                import sqlite3


                def query(sql):
                    return sqlite3.connect("x.db").execute(sql).fetchall()


                def level2(v):
                    return level3(v)


                def level3(v):
                    return query(v)
            """,
        },
    )
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.category == Category.SQL_INJECTION
    assert cand.file == "repo.py" and cand.function == "repo.query"
    assert cand.route == {"path": "/report", "methods": ["POST"], "access": "anonymous"}
    assert cand.functions == ["app.make_report", "services.report", "repo.query"]
    files = [s.file for s in cand.steps]
    assert files[0] == "app.py" and "services.py" in files and files[-1] == "repo.py"
    notes = " / ".join(s.note for s in cand.steps)
    assert "build() 的返回值" in notes and "作为参数 sql 传入 query()" in notes
    # /deep 需要第 4 层（level3 → query）才到达 Sink，超出追踪深度


def test_helper_reading_request_directly_is_found_without_route(tmp_path: Path) -> None:
    candidates = analyze(
        tmp_path,
        {
            "tools.py": """
                import os

                from flask import request


                def run_backup():
                    os.system("tar czf /tmp/b.tgz " + request.args["dir"])
            """
        },
    )
    assert [(c.category, c.route) for c in candidates] == [(Category.COMMAND_INJECTION, None)]
