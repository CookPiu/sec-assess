"""CVSS 3.1 基础分：由向量按规范公式计算分数和严重等级（D-015）。

模型只给出向量，分数一律由这里计算；模型不可用时用各类别的默认向量。
公式与取整规则见 FIRST《CVSS v3.1 Specification》第 7 节与附录 A。
"""

from __future__ import annotations

import math

from app.models.enums import Category, Severity

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# 权限要求的权重随影响范围变化
_PR_WEIGHTS = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

DEFAULT_VECTORS: dict[Category, str] = {
    Category.SQL_INJECTION: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    Category.COMMAND_INJECTION: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    Category.TEMPLATE_INJECTION: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    Category.DESERIALIZATION: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    Category.PATH_TRAVERSAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    Category.IDOR: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    Category.MISSING_AUTH: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    Category.DEBUG_MODE: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    Category.CONFIG_EXPOSURE: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    Category.HARDCODED_SECRET: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    Category.WEAK_PASSWORD_STORAGE: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


class CvssError(ValueError):
    pass


def parse_vector(vector: str) -> dict[str, str]:
    """解析 3.1（兼容 3.0）向量，返回 8 个基础指标；时间与环境指标忽略。"""
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.1", "CVSS:3.0"):
        raise CvssError(f"不是 CVSS 3.x 向量：{vector}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or key in metrics:
            raise CvssError(f"向量格式错误：{vector}")
        metrics[key] = value
    base = {}
    for key in BASE_METRICS:
        value = metrics.get(key)
        valid = ("U", "C") if key == "S" else ("N", "L", "H") if key == "PR" else _WEIGHTS[key]
        if value not in valid:
            raise CvssError(f"向量缺少或含非法的 {key} 指标：{vector}")
        base[key] = value
    return base


def roundup(value: float) -> float:
    """规范附录 A 的向上取整到一位小数，避免浮点误差导致多进一位。"""
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000
    return (math.floor(integer / 10_000) + 1) / 10


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - _WEIGHTS["C"][m["C"]]) * (1 - _WEIGHTS["I"][m["I"]]) * (1 - _WEIGHTS["A"][m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = (
        8.22 * _WEIGHTS["AV"][m["AV"]] * _WEIGHTS["AC"][m["AC"]] * _PR_WEIGHTS[m["S"]][m["PR"]] * _WEIGHTS["UI"][m["UI"]]
    )
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return roundup(min(total, 10))


def severity_of(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def score(vector: str) -> tuple[float, Severity]:
    value = base_score(vector)
    return value, severity_of(value)


def default_vector(category: Category | str) -> str:
    return DEFAULT_VECTORS[Category(category)]


EXPLOITABILITY_METRICS = ("AV", "AC", "PR", "UI")
# 路由访问前提对应的权限要求
ACCESS_PRIVILEGES = {"anonymous": "N", "user": "L", "admin": "H"}


def anchor_vector(vector: str, category: Category | str, access: str | None = None) -> str:
    """可利用性指标取类别默认向量，权限要求按路由访问前提；影响范围与三项影响沿用 vector（D-029）。

    模型给出的向量在多次评估间会变动，固定可利用性指标后，同一漏洞的分数只随影响判断变化。
    """
    metrics = parse_vector(vector)
    fixed = parse_vector(default_vector(category))
    metrics.update({key: fixed[key] for key in EXPLOITABILITY_METRICS})
    if access in ACCESS_PRIVILEGES:
        metrics["PR"] = ACCESS_PRIVILEGES[access]
    return "CVSS:3.1/" + "/".join(f"{key}:{metrics[key]}" for key in BASE_METRICS)
