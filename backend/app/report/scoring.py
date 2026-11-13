"""安全评分、综合安全等级与整改优先级（DESIGN.md 5.5、SPEC.md“假设”）。

“模型判定误报”不计入评分、等级和整改建议。
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

from app.models.enums import Severity

# 每条已验证漏洞按严重等级扣分，疑似漏洞扣一半
DEDUCTION: dict[str, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
# 没有 CVSS 分数时按严重等级取区间下限参与等级判定
SEVERITY_FLOOR: dict[str, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 0.1,
    Severity.INFO: 0.0,
}

LEVEL_CRITICAL = "极高危"
LEVEL_HIGH = "高危"
LEVEL_MEDIUM = "中危"
LEVEL_SAFE = "安全"

PRIORITY_LABELS = ("P1 立即修复", "P2 尽快修复", "P3 计划修复", "P4 排期加固")


@dataclass(frozen=True)
class ScoreItem:
    code: str
    severity: str
    cvss: float | None
    verified: bool
    false_positive: bool = False

    @property
    def effective_cvss(self) -> float:
        return self.cvss if self.cvss is not None else SEVERITY_FLOOR.get(self.severity, 0.0)


def counted(items: Iterable[ScoreItem]) -> list[ScoreItem]:
    return [item for item in items if not item.false_positive]


def security_score(items: Iterable[ScoreItem]) -> int:
    """100 减去扣分，向下取整，最低 0 分。"""
    total = sum(DEDUCTION.get(i.severity, 0) * (1 if i.verified else 0.5) for i in counted(items))
    return max(0, math.floor(100 - total))


def overall_level(items: Iterable[ScoreItem], reaches_code_execution: bool) -> tuple[str, str]:
    """返回综合安全等级与判定依据。"""
    items = counted(items)
    verified = [i for i in items if i.verified]
    critical = [i.code for i in verified if i.effective_cvss >= 9.0]
    if critical or reaches_code_execution:
        reasons = []
        if critical:
            reasons.append(f"存在 CVSS ≥ 9.0 的已验证漏洞（{'、'.join(critical)}）")
        if reaches_code_execution:
            reasons.append("存在能到达执行代码的多步攻击路径")
        return LEVEL_CRITICAL, "；".join(reasons)
    high = [i.code for i in verified if i.effective_cvss >= 7.0]
    if high:
        return LEVEL_HIGH, f"存在 CVSS 7.0–8.9 的已验证漏洞（{'、'.join(high)}）"
    if verified:
        return LEVEL_MEDIUM, "已验证漏洞的 CVSS 均低于 7.0"
    if items:
        return LEVEL_MEDIUM, "没有已验证漏洞，只有未经动态验证的疑似漏洞"
    return LEVEL_SAFE, "没有发现漏洞"


def priority(item: ScoreItem, on_code_execution_path: bool) -> int:
    """整改优先级下标，对应 PRIORITY_LABELS。"""
    if item.verified and (item.effective_cvss >= 9.0 or on_code_execution_path):
        return 0
    if item.verified and item.effective_cvss >= 7.0:
        return 1
    if item.verified:
        return 2
    return 3


def remediation_order(items: Iterable[ScoreItem], code_execution_codes: set[str]) -> list[tuple[int, ScoreItem]]:
    """按优先级、CVSS 从高到低、编号排序。"""
    ranked = [(priority(i, i.code in code_execution_codes), i) for i in counted(items)]
    return sorted(ranked, key=lambda pair: (pair[0], -pair[1].effective_cvss, pair[1].code))
