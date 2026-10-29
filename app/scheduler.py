"""Background scheduler that runs due checks and maintains derived state."""

from __future__ import annotations

import asyncio
import functools
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import delete, select

from .checker import ProbeResult, probe
from .config import Settings
from .db import session_scope, utcnow
from .models import AdminSession, Check, DailyStat, Incident, Monitor

log = logging.getLogger("uptime.scheduler")

TICK_SECONDS = 1.0
MAINTENANCE_INTERVAL = timedelta(hours=1)
RETRY_DELAY_SECONDS = 2.0
INCIDENT_RETENTION = timedelta(days=400)


def record_result(monitor_id: int, result: ProbeResult) -> None:
    """Persist a check and update monitor state, daily rollup and incidents."""
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

        open_incident = db.scalar(
            select(Incident)
            .where(Incident.monitor_id == monitor_id, Incident.resolved_at.is_(None))
            .order_by(Incident.started_at.desc())
            .limit(1)
        )
        if result.ok and open_incident is not None:
            open_incident.resolved_at = now
        elif not result.ok and open_incident is None:
            db.add(Incident(monitor_id=monitor_id, started_at=now, error=result.error))

        monitor.status = "up" if result.ok else "down"
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
                await asyncio.to_thread(record_result, monitor_id, result)
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
