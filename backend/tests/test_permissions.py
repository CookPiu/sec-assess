"""接口权限矩阵（T050）：未登录一律 401；受限接口只对指定角色开放，其他角色 403。"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.pipeline.runner import runner
from tests.test_settings_api import ImageSandbox

MISSING_ID = 999999
PUBLIC = {("POST", "/api/auth/login"), ("GET", "/api/health")}
# 只对部分角色开放的接口；其余接口登录即可访问
RESTRICTED = {
    ("GET", "/api/settings"): {"admin"},
    ("PUT", "/api/settings"): {"admin"},
    ("GET", "/api/audit-logs"): {"admin"},
    ("POST", "/api/tasks"): {"engineer"},
    ("POST", "/api/tasks/{task_id}/stop"): {"engineer"},
    ("POST", "/api/findings/{finding_id}/patch/adopt"): {"developer"},
    ("GET", "/api/tasks/{task_id}/report/export"): {"engineer", "developer"},
}
ROLES = ("admin", "engineer", "developer")


@pytest.fixture(autouse=True)
def no_docker(monkeypatch) -> None:
    # 配置接口会查询本机镜像，权限测试不依赖真实 Docker
    monkeypatch.setattr(runner, "manager", ImageSandbox())


def api_endpoints() -> list[tuple[str, str]]:
    # FastAPI 0.162 起 app.routes 里是未展开的子路由，从 OpenAPI 文档取完整的路径表
    return sorted(
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        if path.startswith("/api/")
        for method in operations
    )


def concrete(path: str) -> str:
    """路径参数填一个不存在的编号，允许访问的角色拿到 404 而不会改动已有数据。"""
    return re.sub(r"\{[^}]+\}", str(MISSING_ID), path)


def call(client: TestClient, method: str, path: str, headers: dict[str, str] | None = None):
    kwargs = {"json": {}} if method == "PUT" else {}
    return client.request(method, concrete(path), headers=headers, **kwargs)


def test_restricted_table_matches_routes() -> None:
    endpoints = set(api_endpoints())
    assert set(RESTRICTED) <= endpoints
    assert PUBLIC <= endpoints


@pytest.mark.parametrize(("method", "path"), [e for e in api_endpoints() if e not in PUBLIC])
def test_requires_login(client: TestClient, method: str, path: str) -> None:
    assert call(client, method, path).status_code == 401
    assert call(client, method, path, {"Authorization": "Bearer not-a-token"}).status_code == 401


@pytest.mark.parametrize(("method", "path"), sorted(RESTRICTED))
def test_role_matrix(client: TestClient, login, method: str, path: str) -> None:
    for role in ROLES:
        status = call(client, method, path, login(role)).status_code
        if role in RESTRICTED[(method, path)]:
            assert status not in (401, 403), f"{role} {method} {path} -> {status}"
        else:
            assert status == 403, f"{role} {method} {path} -> {status}"


def test_admin_reads_settings_and_audit_logs(client: TestClient, login) -> None:
    headers = login("admin")
    assert client.get("/api/settings", headers=headers).status_code == 200
    assert client.get("/api/audit-logs", headers=headers).status_code == 200
