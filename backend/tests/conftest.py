from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient

# 仅用于测试的临时账号密码与签名密钥，测试库建在 pytest 临时目录里
TEST_PASSWORD = "test-only-password"


@pytest.fixture(scope="session")
def app_env(tmp_path_factory: pytest.TempPathFactory):
    data_dir = tmp_path_factory.mktemp("data")
    os.environ["DATA_DIR"] = str(data_dir)
    os.environ.pop("DATABASE_URL", None)
    os.environ["SEED_PASSWORD"] = TEST_PASSWORD
    os.environ["JWT_SECRET"] = "test-only-jwt-secret-0123456789abcdef"
    os.environ.pop("LLM_API_KEY", None)
    from app.core.config import Settings, get_settings

    # 测试不读取开发者本机的 .env，避免真实配置（如 LLM_API_KEY）影响结果
    Settings.model_config["env_file"] = None
    get_settings.cache_clear()
    return data_dir


@pytest.fixture(scope="session")
def client(app_env) -> Iterator[TestClient]:
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def login(client: TestClient) -> Callable[[str], dict[str, str]]:
    def _login(username: str) -> dict[str, str]:
        resp = client.post("/api/auth/login", json={"username": username, "password": TEST_PASSWORD})
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['token']}"}

    return _login


@pytest.fixture
def run_async(client: TestClient):
    """在应用所在的事件循环里执行协程，用于直接读写数据库。"""

    def _run(fn, *args):
        return client.portal.call(fn, *args)

    return _run
