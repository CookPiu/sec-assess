"""安全评分、综合等级与整改优先级（T038）。"""

from __future__ import annotations

from app.report.scoring import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_MEDIUM,
    LEVEL_SAFE,
    ScoreItem,
    overall_level,
    remediation_order,
    security_score,
)


def item(code: str, severity: str, cvss: float | None, verified: bool = True, fp: bool = False) -> ScoreItem:
    return ScoreItem(code=code, severity=severity, cvss=cvss, verified=verified, false_positive=fp)


def test_score_deducts_by_severity_and_halves_unverified() -> None:
    assert security_score([]) == 100
    assert security_score([item("A", "critical", 9.8)]) == 75
    assert security_score([item("A", "high", 7.5), item("B", "medium", 5.3)]) == 77
    # 疑似高危扣 7.5 分，向下取整
    assert security_score([item("A", "high", 7.5, verified=False)]) == 92
    assert security_score([item("A", "low", 3.1, verified=False), item("B", "info", None)]) == 98
    # 模型判定误报不扣分
    assert security_score([item("A", "critical", 9.8, fp=True)]) == 100
    assert security_score([item(str(i), "critical", 9.8) for i in range(5)]) == 0


def test_level_rules() -> None:
    assert overall_level([], False) == (LEVEL_SAFE, "没有发现漏洞")
    assert overall_level([item("A", "critical", 9.8, fp=True)], False)[0] == LEVEL_SAFE

    level, reason = overall_level([item("A", "critical", 9.8), item("B", "high", 8.8)], False)
    assert level == LEVEL_CRITICAL and reason == "存在 CVSS ≥ 9.0 的已验证漏洞（A）"
    level, reason = overall_level([item("B", "high", 7.2)], True)
    assert level == LEVEL_CRITICAL and reason == "存在能到达执行代码的多步攻击路径"

    assert overall_level([item("B", "high", 7.0), item("C", "medium", 6.5)], False) == (
        LEVEL_HIGH,
        "存在 CVSS 7.0–8.9 的已验证漏洞（B）",
    )
    # 疑似漏洞分数再高也只到中危
    assert overall_level([item("A", "critical", 9.8, verified=False), item("C", "medium", 6.5)], False) == (
        LEVEL_MEDIUM,
        "已验证漏洞的 CVSS 均低于 7.0",
    )
    assert overall_level([item("A", "critical", 9.8, verified=False)], False)[1] == "没有已验证漏洞，只有未经动态验证的疑似漏洞"
    # 缺少 CVSS 分数时按严重等级的区间下限判定
    assert overall_level([item("A", "critical", None)], False)[0] == LEVEL_CRITICAL


def test_remediation_order() -> None:
    items = [
        item("U1", "critical", 9.1, verified=False),
        item("V1", "medium", 5.3),
        item("V2", "high", 7.2),
        item("V3", "high", 8.1),
        item("V4", "critical", 9.8),
        item("F1", "critical", 9.8, fp=True),
    ]
    ranked = remediation_order(items, code_execution_codes={"V2"})
    # V2 位于执行代码路径上，与 CVSS ≥ 9.0 的 V4 同为 P1；误报不进入整改清单
    assert [(p, i.code) for p, i in ranked] == [(0, "V4"), (0, "V2"), (1, "V3"), (2, "V1"), (3, "U1")]
