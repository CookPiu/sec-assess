"""漏洞查询接口：列表排序、详情中的污点步骤与证据、源码读取的路径限制（T032）。"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from app.api.findings import SourceError, read_source_file
from app.models import Evidence, Finding, Project, TaintStep, Task
from app.models.enums import Severity, SourceType, TaskStatus, VerifyStatus

APP_SOURCE = "from flask import Flask\n\napp = Flask(__name__)\n"


@pytest.fixture
def seeded(app_env, client: TestClient, run_async) -> dict[str, int]:
    """直接写库：一个项目、一个任务、三条漏洞（已验证、疑似、模型判定误报）。"""

    async def _seed() -> dict[str, int]:
        from app.core.db import session_factory

        async with session_factory()() as session:
            project = Project(name="seeded", source_type=SourceType.ZIP, source_dir="")
            session.add(project)
            await session.flush()
            project.source_dir = f"projects/{project.id}/src"
            src = app_env / project.source_dir
            (src / "pkg").mkdir(parents=True)
            (src / "app.py").write_bytes(APP_SOURCE.encode())
            (src / "pkg" / "db.py").write_text("def q(sql):\n    return sql\n", encoding="utf-8")
            (src / "blob.bin").write_bytes(b"\x00\x01\x02")
            (app_env / "projects" / str(project.id) / "secret.txt").write_text("outside", encoding="utf-8")

            task = Task(project_id=project.id, status=TaskStatus.COMPLETED)
            session.add(task)
            await session.flush()

            def finding(seq: int, **kw) -> Finding:
                base = dict(
                    task_id=task.id,
                    code=f"SA-{task.id}-{seq:03d}",
                    category="sql_injection",
                    title=f"漏洞 {seq}",
                    severity=Severity.HIGH,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cvss_score=7.5,
                    file="app.py",
                    line=3,
                    route={"path": "/search", "methods": ["GET"], "access": "anonymous"},
                    status=VerifyStatus.UNVERIFIED,
                    judged_by="default",
                    reason="未经模型研判",
                )
                base.update(kw)
                return Finding(**base)

            medium = finding(1, severity=Severity.MEDIUM, cvss_score=9.8)
            critical = finding(2, severity=Severity.CRITICAL, cvss_score=9.8, status=VerifyStatus.VERIFIED)
            false_positive = finding(3, severity=Severity.LOW, cvss_score=3.1, model_false_positive=True, route=None)
            session.add_all([medium, critical, false_positive])
            await session.flush()
            session.add_all(
                [
                    TaintStep(finding_id=critical.id, seq=2, file="pkg/db.py", line=2, snippet="return sql", note="Sink"),
                    TaintStep(finding_id=critical.id, seq=1, file="app.py", line=3, snippet="q(x)", note="Source"),
                    Evidence(
                        finding_id=critical.id,
                        case={"method": "GET", "path": "/search", "replay": "python runner.py"},
                        request_raw="GET /search HTTP/1.1",
                        response_raw="HTTP/1.1 200 OK\r\n\r\n3.45.1",
                        matched="sqlite_version",
                        hit=True,
                    ),
                ]
            )
            await session.commit()
            return {
                "task": task.id,
                "medium": medium.id,
                "critical": critical.id,
                "false_positive": false_positive.id,
            }

    return run_async(_seed)


def test_list_findings_sorted_by_severity(client: TestClient, login, seeded) -> None:
    resp = client.get(f"/api/tasks/{seeded['task']}/findings", headers=login("developer"))
    assert resp.status_code == 200, resp.text
    items = resp.json()
    assert [x["id"] for x in items] == [seeded["critical"], seeded["medium"], seeded["false_positive"]]
    assert items[0]["status"] == "verified" and items[0]["model_false_positive"] is False
    assert items[2]["model_false_positive"] is True and items[2]["route"] is None
    assert "reason" not in items[0]
    assert client.get("/api/tasks/99999/findings", headers=login("developer")).status_code == 404


def test_finding_detail_has_steps_and_evidence(client: TestClient, login, seeded) -> None:
    headers = login("engineer")
    body = client.get(f"/api/findings/{seeded['critical']}", headers=headers).json()
    assert body["task_id"] == seeded["task"]
    assert body["reason"] == "未经模型研判"
    assert [(s["seq"], s["file"]) for s in body["steps"]] == [(1, "app.py"), (2, "pkg/db.py")]
    [evidence] = body["evidence"]
    assert evidence["hit"] is True and evidence["matched"] == "sqlite_version"
    assert evidence["case"]["replay"] == "python runner.py"
    assert evidence["response_raw"].endswith("3.45.1")

    empty = client.get(f"/api/findings/{seeded['medium']}", headers=headers).json()
    assert empty["steps"] == [] and empty["evidence"] == []
    assert client.get("/api/findings/99999", headers=headers).status_code == 404


def test_source_file_content_and_path_checks(client: TestClient, login, seeded) -> None:
    headers = login("admin")
    url = f"/api/tasks/{seeded['task']}/source"
    ok = client.get(url, headers=headers, params={"path": "app.py"})
    assert ok.status_code == 200, ok.text
    assert ok.json() == {"path": "app.py", "content": APP_SOURCE}
    assert client.get(url, headers=headers, params={"path": "pkg/db.py"}).json()["content"].startswith("def q")
    assert client.get(url, headers=headers, params={"path": "pkg\\db.py"}).status_code == 200

    for bad in ("../secret.txt", "pkg/../../secret.txt", "/etc/passwd", "C:/Windows/win.ini", "a\0b"):
        resp = client.get(url, headers=headers, params={"path": bad})
        assert resp.status_code == 400, (bad, resp.text)
    assert client.get(url, headers=headers, params={"path": "missing.py"}).status_code == 404
    assert client.get(url, headers=headers, params={"path": "pkg"}).status_code == 404
    assert client.get(url, headers=headers, params={"path": "blob.bin"}).status_code == 415
    assert client.get("/api/tasks/99999/source", headers=headers, params={"path": "app.py"}).status_code == 404


def test_source_rejects_large_files_and_outside_symlinks(tmp_path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    (root / "big.py").write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(SourceError) as exc:
        read_source_file(root, "big.py")
    assert exc.value.status == 413

    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    try:
        os.symlink(outside, root / "link.txt")
    except OSError:
        pytest.skip("当前系统不允许创建符号链接")
    with pytest.raises(SourceError) as exc:
        read_source_file(root, "link.txt")
    assert exc.value.status == 400


def test_findings_require_login(client: TestClient, seeded) -> None:
    assert client.get(f"/api/tasks/{seeded['task']}/findings").status_code == 401
    assert client.get(f"/api/findings/{seeded['critical']}").status_code == 401
    assert client.get(f"/api/tasks/{seeded['task']}/source", params={"path": "app.py"}).status_code == 401
