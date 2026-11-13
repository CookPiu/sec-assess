import pytest

from app.core.cvss import CvssError, DEFAULT_VECTORS, base_score, parse_vector, score, severity_of
from app.models.enums import Category, Severity


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        # 数值与 FIRST 官方计算器一致
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
        ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.2),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score(vector: str, expected: float) -> None:
    assert base_score(vector) == expected


def test_severity_bands() -> None:
    assert severity_of(9.0) is Severity.CRITICAL
    assert severity_of(8.9) is Severity.HIGH
    assert severity_of(7.0) is Severity.HIGH
    assert severity_of(6.9) is Severity.MEDIUM
    assert severity_of(4.0) is Severity.MEDIUM
    assert severity_of(3.9) is Severity.LOW
    assert severity_of(0.1) is Severity.LOW
    assert severity_of(0.0) is Severity.INFO


def test_ignores_temporal_metrics_and_accepts_30() -> None:
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O") == 9.8
    assert parse_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["AV"] == "N"


@pytest.mark.parametrize(
    "vector",
    [
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_invalid_vectors(vector: str) -> None:
    with pytest.raises(CvssError):
        base_score(vector)


def test_every_category_has_valid_default_vector() -> None:
    assert set(DEFAULT_VECTORS) == set(Category)
    for vector in DEFAULT_VECTORS.values():
        value, _ = score(vector)
        assert 0 < value <= 10
