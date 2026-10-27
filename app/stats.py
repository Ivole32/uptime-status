"""Aggregation of monitor data into the public status payload."""

from __future__ import annotations

import threading
import time
from datetime import date, timedelta

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from .config import Settings
from .db import utcnow
from .models import Check, DailyStat, Incident, Monitor, SiteSetting
from .schemas import iso_utc

HISTORY_DAYS = 90
OVERALL_MONTHS = 12
PAST_INCIDENT_DAYS = 90
PAST_INCIDENT_LIMIT = 50
DEFAULT_SITE = {"title": "Status", "description": None}
STALE_GRACE = timedelta(seconds=60)

# Error categories that are safe and useful to show publicly. Everything else
# (timeouts, refused or blocked connections) collapses into one message so the
# public page cannot be used to tell open, closed and filtered ports apart.
_PUBLIC_ERRORS = {
    "DNS resolution failed",
    "TLS certificate invalid",
    "TLS handshake failed",
    "Invalid HTTP response",
    "Too many redirects",
}


def public_error(error: str | None) -> str | None:
    if error is None:
        return None
    if error.startswith("HTTP ") or error in _PUBLIC_ERRORS:
        return error
    return "Service unreachable"


def _public_status(monitor: Monitor, now) -> str:
    """Report "unknown" when checks have stopped arriving, instead of a stale state."""
    if monitor.status in {"up", "down"} and monitor.last_checked_at is not None:
        expected = timedelta(seconds=2 * monitor.interval_seconds + monitor.timeout_seconds)
        if now - monitor.last_checked_at > expected + STALE_GRACE:
            return "unknown"
    return monitor.status


def get_site_settings(db: Session) -> dict[str, str | None]:
    values: dict[str, str | None] = dict(DEFAULT_SITE)
    for row in db.scalars(select(SiteSetting)):
        if row.key in values:
            values[row.key] = row.value or None
    return values


def _pct(up: int, total: int) -> float | None:
    return round(up * 100.0 / total, 3) if total else None


def _overall_status(statuses: list[str]) -> str:
    known = [s for s in statuses if s in {"up", "down"}]
    if not known:
        return "unknown"
    down = sum(1 for s in known if s == "down")
    if down == 0:
        return "operational"
    return "major_outage" if down == len(known) else "partial_outage"


def build_status(db: Session, settings: Settings) -> dict:
    now = utcnow()
    today = now.date()
    history_start = today - timedelta(days=HISTORY_DAYS - 1)
    overall_start = date(today.year - 1, today.month, 1)

    monitors = db.scalars(
        select(Monitor)
        .where(Monitor.enabled.is_(True), Monitor.is_public.is_(True))
        .order_by(Monitor.sort_order, Monitor.name, Monitor.id)
    ).all()
    ids = [m.id for m in monitors]
    statuses = {m.id: _public_status(m, now) for m in monitors}

    daily: dict[int, dict[date, DailyStat]] = {mid: {} for mid in ids}
    overall: dict[date, list[int]] = {}
    if ids:
        for stat in db.scalars(
            select(DailyStat).where(DailyStat.monitor_id.in_(ids), DailyStat.day >= overall_start)
        ):
            daily[stat.monitor_id][stat.day] = stat
            bucket = overall.setdefault(stat.day, [0, 0])
            bucket[0] += stat.up_checks
            bucket[1] += stat.total_checks

    since = now - timedelta(hours=24)
    last_24h: dict[int, tuple[int, int, float | None]] = {}
    sparklines: dict[int, list[dict]] = {mid: [] for mid in ids}
    if ids:
        ok_int = case((Check.ok.is_(True), 1), else_=0)
        ok_ms = case((Check.ok.is_(True), Check.response_ms), else_=None)
        for mid, total, up, avg_ms in db.execute(
            select(Check.monitor_id, func.count(), func.sum(ok_int), func.avg(ok_ms))
            .where(Check.monitor_id.in_(ids), Check.checked_at >= since)
            .group_by(Check.monitor_id)
        ):
            last_24h[mid] = (int(total), int(up or 0), avg_ms)

        hour = func.strftime("%Y-%m-%dT%H:00:00Z", Check.checked_at)
        for mid, bucket, avg_ms, total, up in db.execute(
            select(Check.monitor_id, hour, func.avg(ok_ms), func.count(), func.sum(ok_int))
            .where(Check.monitor_id.in_(ids), Check.checked_at >= since)
            .group_by(Check.monitor_id, hour)
            .order_by(Check.monitor_id, hour)
        ):
            sparklines[mid].append(
                {
                    "t": bucket,
                    "ms": round(avg_ms) if avg_ms is not None else None,
                    "uptime": _pct(int(up or 0), int(total)),
                }
            )

    out_monitors = []
    for m in monitors:
        stats = daily[m.id]
        days = []
        for offset in range(HISTORY_DAYS):
            day = history_start + timedelta(days=offset)
            stat = stats.get(day)
            days.append(
                {
                    "date": day.isoformat(),
                    "uptime": _pct(stat.up_checks, stat.total_checks) if stat else None,
                    "avg_ms": round(stat.response_ms_sum / stat.response_ms_count)
                    if stat and stat.response_ms_count
                    else None,
                    "down_checks": (stat.total_checks - stat.up_checks) if stat else 0,
                }
            )

        def window(days_back: int) -> float | None:
            first = today - timedelta(days=days_back - 1)
            selected = [s for d, s in stats.items() if d >= first]
            return _pct(sum(s.up_checks for s in selected), sum(s.total_checks for s in selected))

        total24, up24, avg24 = last_24h.get(m.id, (0, 0, None))
        out_monitors.append(
            {
                "id": m.id,
                "name": m.name,
                "description": m.description,
                "url": m.url if m.show_url else None,
                "status": statuses[m.id],
                "last_checked_at": iso_utc(m.last_checked_at),
                "last_response_ms": m.last_response_ms,
                "avg_response_ms_24h": round(avg24) if avg24 is not None else None,
                "uptime": {
                    "24h": _pct(up24, total24),
                    "7d": window(7),
                    "30d": window(30),
                    "90d": window(90),
                },
                "days": days,
                "response_24h": sparklines[m.id],
            }
        )

    names = {m.id: m.name for m in monitors}

    def incident_out(inc: Incident) -> dict:
        return {
            "id": inc.id,
            "monitor_id": inc.monitor_id,
            "monitor_name": names[inc.monitor_id],
            "started_at": iso_utc(inc.started_at),
            "resolved_at": iso_utc(inc.resolved_at),
            "error": public_error(inc.error),
        }

    active, past = [], []
    if ids:
        base = select(Incident).where(Incident.monitor_id.in_(ids))
        active = [
            incident_out(inc)
            for inc in db.scalars(
                base.where(Incident.resolved_at.is_(None)).order_by(Incident.started_at.desc())
            )
        ]
        past = [
            incident_out(inc)
            for inc in db.scalars(
                base.where(Incident.resolved_at >= now - timedelta(days=PAST_INCIDENT_DAYS))
                .order_by(Incident.started_at.desc())
                .limit(PAST_INCIDENT_LIMIT)
            )
        ]

    return {
        "site": get_site_settings(db),
        "generated_at": iso_utc(now),
        "refresh_seconds": settings.public_refresh_seconds,
        "overall_status": _overall_status(list(statuses.values())),
        "monitors": out_monitors,
        "overall_days": [
            {"date": d.isoformat(), "uptime": _pct(up, total)}
            for d, (up, total) in sorted(overall.items())
        ],
        "incidents": {"active": active, "past": past},
    }


class StatusCache:
    """Tiny TTL cache so the public endpoint is cheap under load."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._payload: dict | None = None
        self._expires = 0.0

    def get(self, db: Session, settings: Settings) -> dict:
        with self._lock:
            if self._payload is None or time.monotonic() >= self._expires:
                self._payload = build_status(db, settings)
                self._expires = time.monotonic() + settings.public_cache_seconds
            return self._payload

    def invalidate(self) -> None:
        with self._lock:
            self._payload = None


status_cache = StatusCache()
