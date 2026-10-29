"""Background scheduler that runs due checks and maintains derived state."""

from __future__ import annotations

import asyncio
import functools
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .checker import ProbeResult, probe
from .config import Settings, get_settings
from .db import session_scope, utcnow
from .models import AdminSession, Check, DailyStat, Incident, Monitor

log = logging.getLogger("uptime.scheduler")

TICK_SECONDS = 1.0
MAINTENANCE_INTERVAL = timedelta(hours=1)
RETRY_DELAY_SECONDS = 2.0
INCIDENT_RETENTION = timedelta(days=400)
# Latency degradation: the last few checks must all be slow, so one spike is not an alert,
# and the usual latency must be known from enough checks before anything counts as slow.
DEGRADED_CHECKS = 3
BASELINE_DAYS = 7
BASELINE_MIN_CHECKS = 20


def _elevated_latency(db: Session, monitor_id: int, today: date, settings: Settings) -> str | None:
    """Describe the elevated latency if the recent checks are much slower than usual."""
    if not settings.degraded_factor:
        return None
    # Checks made while degraded are left out, so a long slowdown does not become the norm.
    total_ms, count = db.execute(
        select(
            func.sum(DailyStat.response_ms_sum - DailyStat.degraded_ms_sum),
            func.sum(DailyStat.response_ms_count - DailyStat.degraded_checks),
        ).where(
            DailyStat.monitor_id == monitor_id,
            DailyStat.day > today - timedelta(days=BASELINE_DAYS),
        )
    ).one()
    if not count or count < BASELINE_MIN_CHECKS:
        return None
    usual = total_ms / count
    threshold = max(usual * settings.degraded_factor, usual + settings.degraded_min_ms)
    recent = db.execute(
        select(Check.ok, Check.response_ms)
        .where(Check.monitor_id == monitor_id)
        .order_by(Check.checked_at.desc(), Check.id.desc())
        .limit(DEGRADED_CHECKS)
    ).all()
    if len(recent) < DEGRADED_CHECKS or not all(
        ok and ms is not None and ms > threshold for ok, ms in recent
    ):
        return None
    return f"Elevated latency: {recent[0].response_ms} ms (usually {round(usual)} ms)"


def record_result(monitor_id: int, result: ProbeResult, settings: Settings | None = None) -> None:
    """Persist a check and update monitor state, daily rollup and incidents."""
    settings = settings or get_settings()
    now = utcnow()
    with session_scope() as db:
        monitor = db.get(Monitor, monitor_id)
        if monitor is None:  # deleted while the check was running
            return
        db.add(
            Check(
                monitor_id=monitor_id,
                checked_at=now,
                ok=result.ok,
                response_ms=result.response_ms,
                status_code=result.status_code,
                error=result.error,
            )
        )

        stat = db.get(DailyStat, (monitor_id, now.date()))
        if stat is None:
            stat = DailyStat(
                monitor_id=monitor_id,
                day=now.date(),
                total_checks=0,
                up_checks=0,
                degraded_checks=0,
                degraded_ms_sum=0,
                response_ms_sum=0,
                response_ms_count=0,
            )
            db.add(stat)
        stat.total_checks += 1
        if result.ok:
            stat.up_checks += 1
        if result.ok and result.response_ms is not None:
            stat.response_ms_sum += result.response_ms
            stat.response_ms_count += 1
        db.flush()  # the latency check below reads this check and rollup back

        if result.ok:
            slow = _elevated_latency(db, monitor_id, now.date(), settings)
            kind, reason = ("degraded", slow) if slow else (None, None)
        else:
            kind, reason = "down", result.error

        # One open incident per monitor. A change between down and degraded closes the
        # old incident and opens a new one, so each keeps its own start and reason.
        open_incident = db.scalar(
            select(Incident)
            .where(Incident.monitor_id == monitor_id, Incident.resolved_at.is_(None))
            .order_by(Incident.started_at.desc())
            .limit(1)
        )
        if open_incident is not None and open_incident.kind != kind:
            open_incident.resolved_at = now
            open_incident = None
        if kind is not None and open_incident is None:
            db.add(Incident(monitor_id=monitor_id, started_at=now, kind=kind, error=reason))

        if kind == "degraded":
            stat.degraded_checks += 1
            stat.degraded_ms_sum += result.response_ms
        monitor.status = kind or "up"
        monitor.last_checked_at = now
        monitor.last_response_ms = result.response_ms
        monitor.last_status_code = result.status_code
        monitor.last_error = result.error


def run_maintenance(settings: Settings) -> None:
    now = utcnow()
    with session_scope() as db:
        db.execute(delete(Check).where(Check.checked_at < now - timedelta(days=settings.raw_retention_days)))
        db.execute(delete(AdminSession).where(AdminSession.expires_at <= now))
        db.execute(delete(Incident).where(Incident.resolved_at < now - INCIDENT_RETENTION))


class Scheduler:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._semaphore = asyncio.Semaphore(settings.check_concurrency)
        # Probes get their own threads so slow targets can never starve the
        # default executor that database work runs on.
        self._probe_pool = ThreadPoolExecutor(
            max_workers=settings.check_concurrency, thread_name_prefix="probe"
        )
        # DNS lookups run here so a check can stop waiting at its deadline.
        self._dns_pool = ThreadPoolExecutor(
            max_workers=settings.check_concurrency, thread_name_prefix="dns"
        )
        self._in_flight: set[int] = set()
        self._tasks: set[asyncio.Task] = set()
        self._wake = asyncio.Event()
        self._stopping = False
        self._last_maintenance = utcnow() - MAINTENANCE_INTERVAL

    def wake(self) -> None:
        """Re-evaluate due monitors immediately (e.g. after an edit)."""
        self._wake.set()

    def _due_monitors(self, in_flight: frozenset[int]) -> list[tuple[int, str, int]]:
        now = utcnow()
        with session_scope() as db:
            monitors = db.scalars(select(Monitor).where(Monitor.enabled.is_(True))).all()
            return [
                (m.id, m.url, m.timeout_seconds)
                for m in monitors
                if m.id not in in_flight
                and (
                    m.last_checked_at is None
                    or m.last_checked_at + timedelta(seconds=m.interval_seconds) <= now
                )
            ]

    async def _run_check(self, monitor_id: int, url: str, timeout: int) -> None:
        try:
            async with self._semaphore:
                loop = asyncio.get_running_loop()
                run_probe = functools.partial(
                    probe,
                    url,
                    timeout,
                    allow_private=self.settings.allow_private_targets,
                    allowed_ports=self.settings.allowed_ports,
                    blocked=self.settings.blocked_networks,
                    resolver=self._dns_pool,
                )
                result = await loop.run_in_executor(self._probe_pool, run_probe)
                for _ in range(self.settings.check_retries):
                    if result.ok or self._stopping:
                        break
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                    result = await loop.run_in_executor(self._probe_pool, run_probe)
                await asyncio.to_thread(record_result, monitor_id, result, self.settings)
        except Exception:
            log.exception("Check for monitor %s failed unexpectedly", monitor_id)
        finally:
            self._in_flight.discard(monitor_id)

    async def run(self) -> None:
        log.info("Scheduler started")
        while not self._stopping:
            try:
                for monitor_id, url, timeout in await asyncio.to_thread(
                    self._due_monitors, frozenset(self._in_flight)
                ):
                    self._in_flight.add(monitor_id)
                    task = asyncio.create_task(self._run_check(monitor_id, url, timeout))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
                if utcnow() - self._last_maintenance >= MAINTENANCE_INTERVAL:
                    self._last_maintenance = utcnow()
                    await asyncio.to_thread(run_maintenance, self.settings)
            except Exception:
                log.exception("Scheduler tick failed")
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), TICK_SECONDS)
            except TimeoutError:
                pass

    async def stop(self) -> None:
        self._stopping = True
        self._wake.set()
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._probe_pool.shutdown(wait=False, cancel_futures=True)
        self._dns_pool.shutdown(wait=False, cancel_futures=True)
