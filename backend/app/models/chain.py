from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class ChainNode(Base):
    __tablename__ = "chain_node"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("task.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(12))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("finding.id", ondelete="CASCADE"))
    label: Mapped[str] = mapped_column(String(100))


class ChainEdge(Base):
    __tablename__ = "chain_edge"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("task.id", ondelete="CASCADE"), index=True)
    src_id: Mapped[int] = mapped_column(ForeignKey("chain_node.id", ondelete="CASCADE"))
    dst_id: Mapped[int] = mapped_column(ForeignKey("chain_node.id", ondelete="CASCADE"))
    # 所用的能力或推导规则，显示在拓扑图的边上
    reason: Mapped[str] = mapped_column(String(200))


class AttackPath(Base):
    __tablename__ = "attack_path"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("task.id", ondelete="CASCADE"), index=True)
    node_ids: Mapped[list[int]] = mapped_column(JSON)
    target: Mapped[str] = mapped_column(String(100))
    summary: Mapped[str | None] = mapped_column(Text)
    impact: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON)
