"""污点轨迹与候选漏洞的数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import Category

MAX_STEPS = 30


@dataclass(frozen=True)
class Step:
    file: str
    line: int
    snippet: str
    note: str


@dataclass(frozen=True)
class Taint:
    """一个被污染的值：来源到当前位置的步骤，以及已被净化的漏洞类别。"""

    steps: tuple[Step, ...]
    sanitized: frozenset[Category] = frozenset()

    def extend(self, step: Step) -> Taint:
        last = self.steps[-1] if self.steps else None
        if last is not None and last.file == step.file and last.line == step.line:
            # 同一行上的连续动作合并成一步，轨迹更紧凑
            if step.note in last.note:
                return self
            merged = Step(last.file, last.line, last.snippet, f"{last.note}，{step.note}")
            return Taint((*self.steps[:-1], merged), self.sanitized)
        steps = (*self.steps, step)
        if len(steps) > MAX_STEPS:
            steps = (*steps[:2], *steps[-(MAX_STEPS - 2) :])
        return Taint(steps, self.sanitized)

    def sanitize(self, categories: frozenset[Category]) -> Taint:
        return Taint(self.steps, self.sanitized | categories)


@dataclass
class Candidate:
    category: Category
    file: str
    line: int
    function: str  # 触发点所在函数的限定名
    message: str
    steps: list[Step]
    route: dict[str, Any] | None = None  # 入口路由：path、methods、access
    # 从入口到触发点经过的函数，研判时把这些函数的源码发给模型
    functions: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.category, self.file, self.line)
