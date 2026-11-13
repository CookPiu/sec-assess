from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, utcnow


class Report(Base):
    """报告阶段写下的文字；评分、等级和各章节数据在预览或导出时从各表现取。"""

    __tablename__ = "report"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("task.id", ondelete="CASCADE"), unique=True)
    # 评估结论（风险大盘下的一段总述）
    conclusion: Mapped[str] = mapped_column(Text)
    # 漏洞编号 → 整改行动；缺少的编号按漏洞类别的默认指引
    actions: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    # 结论的文字来源：model / template
    written_by: Mapped[str] = mapped_column(String(8))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
