"""SQLAlchemy models."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, utcnow


class Monitor(Base):
    __tablename__ = "monitors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    show_url: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Current state, denormalised for cheap reads.
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_response_ms: Mapped[int | None] = mapped_column(Integer)
    last_status_code: Mapped[int | None] = mapped_column(Integer)
    last_error: Mapped[str | None] = mapped_column(String(200))

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, onupdate=utcnow
    )

    checks: Mapped[list[Check]] = relationship(
        back_populates="monitor", cascade="all, delete-orphan", passive_deletes=True
    )


class Check(Base):
    __tablename__ = "checks"
    __table_args__ = (Index("ix_checks_monitor_time", "monitor_id", "checked_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitor_id: Mapped[int] = mapped_column(
        ForeignKey("monitors.id", ondelete="CASCADE"), nullable=False
    )
    checked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    response_ms: Mapped[int | None] = mapped_column(Integer)
    status_code: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(String(200))

    monitor: Mapped[Monitor] = relationship(back_populates="checks")


class DailyStat(Base):
    """Per-day rollup so 90-day history stays cheap after raw checks are pruned."""

    __tablename__ = "daily_stats"

    monitor_id: Mapped[int] = mapped_column(
        ForeignKey("monitors.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    total_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    up_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Up checks made while the monitor was degraded (elevated latency).
    degraded_checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    degraded_ms_sum: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    response_ms_sum: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_ms_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_monitor_started", "monitor_id", "started_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitor_id: Mapped[int] = mapped_column(
        ForeignKey("monitors.id", ondelete="CASCADE"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    # "down" (checks fail) or "degraded" (checks pass, but much slower than usual).
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="down", server_default="down")
    error: Mapped[str | None] = mapped_column(String(200))


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    # SHA-256 of the session token; the raw token only ever lives in the cookie.
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)


class SiteSetting(Base):
    __tablename__ = "site_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class LegalPage(Base):
    """Imprint and privacy policy. A page exists publicly only while it has a row."""

    __tablename__ = "legal_pages"

    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    title: Mapped[str | None] = mapped_column(String(80))
    content: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
