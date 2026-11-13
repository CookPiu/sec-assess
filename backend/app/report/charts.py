"""报告中的图表：服务端生成 SVG，以 data URI 图片嵌入 Markdown，HTML 与 PDF 沿用同一张图。"""

from __future__ import annotations

import base64
import math
from xml.sax.saxutils import escape

DATA_URI_PREFIX = "data:image/svg+xml;base64,"
# 分类色按固定顺序取用，相邻两色在常见色觉障碍下仍可区分；超过 8 类时尾部并入灰色的“其他”
PALETTE = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948")
OTHER_COLOR = "#8f8e88"
SURFACE = "#ffffff"
TEXT_PRIMARY = "#1f2329"
TEXT_SECONDARY = "#52514e"
FONT = "Microsoft YaHei, PingFang SC, Noto Sans CJK SC, sans-serif"


def fold_parts(parts: list[tuple[str, int]], limit: int = len(PALETTE)) -> list[tuple[str, int, str]]:
    """按传入顺序配色；超过 limit 类时保留前 limit - 1 类，其余合并为“其他”。"""
    parts = [(name, n) for name, n in parts if n > 0]
    if len(parts) <= limit:
        return [(name, n, PALETTE[i]) for i, (name, n) in enumerate(parts)]
    head, tail = parts[: limit - 1], parts[limit - 1 :]
    folded = [(name, n, PALETTE[i]) for i, (name, n) in enumerate(head)]
    return [*folded, ("其他", sum(n for _, n in tail), OTHER_COLOR)]


def _point(cx: float, cy: float, r: float, angle: float) -> tuple[float, float]:
    rad = math.radians(angle - 90)
    return cx + r * math.cos(rad), cy + r * math.sin(rad)


def pie_svg(parts: list[tuple[str, int]]) -> str:
    """饼图加右侧图例（名称、数量、占比）；扇区之间留 2px 底色缝隙。"""
    slices = fold_parts(parts)
    total = sum(n for _, n, _ in slices)
    if not total:
        return ""
    width, row = 460, 26
    height = max(200, row * len(slices) + 32)
    r, cx, cy = 84, 100, height / 2
    marks: list[str] = []
    if len(slices) == 1:
        marks.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{slices[0][2]}"/>')
    else:
        start = 0.0
        for _, n, color in slices:
            sweep = 360 * n / total
            x1, y1 = _point(cx, cy, r, start)
            x2, y2 = _point(cx, cy, r, start + sweep)
            large = 1 if sweep > 180 else 0
            marks.append(
                f'<path d="M{cx:.2f},{cy:.2f} L{x1:.2f},{y1:.2f} A{r},{r} 0 {large} 1 {x2:.2f},{y2:.2f} Z" '
                f'fill="{color}" stroke="{SURFACE}" stroke-width="2" stroke-linejoin="round"/>'
            )
            start += sweep
    top = cy - row * len(slices) / 2
    for i, (name, n, color) in enumerate(slices):
        y = top + row * i + row / 2
        share = f"{n} 条 · {n / total * 100:.1f}%"
        marks.append(f'<rect x="216" y="{y - 6:.1f}" width="12" height="12" rx="3" fill="{color}"/>')
        marks.append(
            f'<text x="236" y="{y:.1f}" dominant-baseline="central" fill="{TEXT_PRIMARY}">{escape(name)}</text>'
        )
        marks.append(
            f'<text x="{width - 8}" y="{y:.1f}" dominant-baseline="central" text-anchor="end" '
            f'fill="{TEXT_SECONDARY}">{escape(share)}</text>'
        )
    body = "".join(marks)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height:.0f}" '
        f'viewBox="0 0 {width} {height:.0f}" font-family="{FONT}" font-size="13">'
        f'<rect width="100%" height="100%" fill="{SURFACE}"/>{body}</svg>'
    )


def data_uri(svg: str) -> str:
    return DATA_URI_PREFIX + base64.b64encode(svg.encode("utf-8")).decode("ascii")
