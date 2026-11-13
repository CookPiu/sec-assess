"""进程级配置：从项目根目录的 .env 和环境变量读取，启动后不变。

可在配置页修改的运行参数（配额、超时、并发等）见 runtime.py。
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_host: str = "127.0.0.1"
    api_port: int = 8010

    data_dir: Path | None = None
    database_url: str = ""

    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 720
    seed_password: str = ""

    llm_model: str = ""
    llm_api_key: str = ""
    llm_base_url: str = "https://api.deepseek.com"
    llm_timeout_seconds: float = 60

    sandbox_image: str = "sec-assess/sandbox-python:3.12"

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir or PROJECT_ROOT / "data"

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        db_path = self.resolved_data_dir / "sec_assess.db"
        return f"sqlite+aiosqlite:///{db_path.as_posix()}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
