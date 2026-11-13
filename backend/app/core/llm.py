"""大模型客户端：DeepSeek 的 OpenAI 兼容接口（D-011）。

调用方只传入代码片段（漏洞所在函数和污点轨迹涉及的代码），不传整个仓库。
任何失败都返回 None，由调用方走规则默认值，评估不因模型不可用而失败。
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from typing import Any

from openai import AsyncOpenAI, OpenAIError

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# 单次请求的输入上限（字符），防止误把大文件或整个仓库发给模型
MAX_INPUT_CHARS = 16_000

_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


class InputTooLarge(ValueError):
    pass


def parse_json_reply(text: str) -> dict[str, Any] | None:
    """解析模型返回的 JSON，容忍 ```json 代码块包裹；不是 JSON 对象时返回 None。"""
    cleaned = _FENCE.sub("", text.strip())
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


class LLMClient:
    """模型名、接口地址和超时可由配置页覆盖（不传时取 .env）；密钥和重试次数只取 .env。"""

    def __init__(self, model: str | None = None, base_url: str | None = None, timeout: float | None = None) -> None:
        settings = get_settings()
        self._model = model or settings.llm_model
        self._timeout = timeout or settings.llm_timeout_seconds
        self._client: AsyncOpenAI | None = None
        if settings.llm_api_key and self._model:
            self._client = AsyncOpenAI(
                api_key=settings.llm_api_key,
                base_url=base_url or settings.llm_base_url,
                timeout=self._timeout,
                max_retries=settings.llm_max_retries,
            )

    @property
    def configured(self) -> bool:
        return self._client is not None

    async def chat_json(
        self, system: str, user: str, *, enabled: bool = True, timeout: float | None = None
    ) -> dict[str, Any] | None:
        """要求模型输出 JSON 对象。未配置、被关闭、超时或输出不合法时返回 None。

        timeout 为单次请求超时的下限（秒），输出较长的调用（如补丁）用它放宽；配置的超时更长时取配置值。
        """
        if not enabled or self._client is None:
            return None
        if len(system) + len(user) > MAX_INPUT_CHARS:
            raise InputTooLarge(f"发给模型的内容超过 {MAX_INPUT_CHARS} 字符，请只传代码片段")
        try:
            resp = await self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                response_format={"type": "json_object"},
                temperature=0,
                **({"timeout": max(timeout, self._timeout)} if timeout else {}),
            )
        except OpenAIError as exc:
            logger.warning("大模型调用失败：%s", type(exc).__name__)
            return None
        content = resp.choices[0].message.content if resp.choices else None
        result = parse_json_reply(content or "")
        if result is None:
            logger.warning("大模型输出不是合法的 JSON 对象")
        return result


@lru_cache(maxsize=8)
def get_llm(model: str | None = None, base_url: str | None = None, timeout: float | None = None) -> LLMClient:
    """同一组参数复用一个客户端；各阶段按任务快照里的大模型参数取用（RuntimeConfig.llm_options）。"""
    return LLMClient(model, base_url, timeout)
