"""Push alerts for outages, sent through a Pushgate server.

An incident is alerted once it has lasted the configured number of minutes (per monitor, or the
default from the alert settings), so short blips never wake anyone. When an alerted incident is
resolved, a recovery notice follows. Sending runs in the scheduler as its own task, so a slow or
unreachable Pushgate never delays checks. Failed sends are retried with a growing pause.

Pushgate API: POST {url}/api/v1/notifications with a per-service bearer key.
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import threading
import unicodedata
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .config import Settings
from .db import session_scope, utcnow
from .models import Incident, Monitor, SiteSetting

log = logging.getLogger("uptime.alerts")

SWEEP_INTERVAL = timedelta(seconds=10)
REQUEST_TIMEOUT_SECONDS = 10
# A recovery older than this is not announced any more (e.g. after Pushgate was unreachable
# for a day, or recovery notices were switched on again).
RECOVERY_WINDOW = timedelta(hours=24)
# More alerts than this in one sweep (say, the host lost its connection) become one summary.
GROUP_THRESHOLD = 3
BACKOFF_MIN_SECONDS = 30
BACKOFF_MAX_SECONDS = 600
MAX_ALERT_AFTER_MINUTES = 1440

PRIORITIES = ("low", "normal", "high")
KEY_PATTERN = re.compile(r"^pgk_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$")
TITLE_MAX = 150  # Pushgate allows 200 and prefixes the key's name
MESSAGE_MAX = 1800  # Pushgate allows 2000


# ---------- Settings (stored in site_settings, edited in the admin panel) ----------


@dataclass
class AlertConfig:
    enabled: bool = False
    after_minutes: int = 5
    on_recovery: bool = True
    on_degraded: bool = False
    priority: str = "high"


_PREFIX = "alert_"


def get_alert_config(db: Session) -> AlertConfig:
    cfg = AlertConfig()
    rows = db.scalars(select(SiteSetting).where(SiteSetting.key.startswith(_PREFIX)))
    for row in rows:
        name = row.key.removeprefix(_PREFIX)
        default = getattr(cfg, name, None)
        try:
            if isinstance(default, bool):
                setattr(cfg, name, row.value == "1")
            elif isinstance(default, int):
                setattr(cfg, name, max(0, min(int(row.value), MAX_ALERT_AFTER_MINUTES)))
            elif name == "priority" and row.value in PRIORITIES:
                cfg.priority = row.value
        except ValueError:
            continue
    return cfg


def save_alert_config(db: Session, cfg: AlertConfig) -> None:
    for name, value in asdict(cfg).items():
        text = ("1" if value else "0") if isinstance(value, bool) else str(value)
        row = db.get(SiteSetting, _PREFIX + name)
        if row is None:
            db.add(SiteSetting(key=_PREFIX + name, value=text))
        else:
            row.value = text


# ---------- Delivery state, shown in the admin panel ----------


@dataclass
class AlertStatus:
    last_sent_at: datetime | None = None
    last_error: str | None = None
    last_error_at: datetime | None = None
    failures: int = 0
    retry_at: datetime | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def succeeded(self, now: datetime) -> None:
        with self._lock:
            self.last_sent_at, self.failures, self.retry_at = now, 0, None
            self.last_error = self.last_error_at = None

    def failed(self, now: datetime, message: str, retry_after: float | None = None, backoff: bool = True) -> None:
        with self._lock:
            self.last_error, self.last_error_at = message, now
            if backoff:
                self.failures += 1
                delay = retry_after or BACKOFF_MIN_SECONDS * 2 ** (self.failures - 1)
                self.retry_at = now + timedelta(seconds=min(delay, BACKOFF_MAX_SECONDS))

    def reset(self) -> None:
        with self._lock:
            self.last_sent_at = self.last_error = self.last_error_at = self.retry_at = None
            self.failures = 0


alert_status = AlertStatus()


# ---------- Pushgate client ----------


class PushgateError(Exception):
    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would resend the API key somewhere else, so it is an error instead."""

    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


_HINTS = {
    (401, None): "the API key was rejected (unknown, revoked or expired)",
    (403, "forbidden"): "this server's address is not in Pushgate's TRUSTED_CIDRS",
    (403, "insufficient_scope"): "the API key may not send this priority; grant it "
    "notifications:send:high or choose a lower priority",
    (429, None): "rate limited by Pushgate",
    (503, None): "sending is paused or disabled in Pushgate",
    (502, None): "Pushgate could not deliver to any device",
}


class PushgateClient:
    def __init__(self, url: str | None, key: str | None = None, key_file=None) -> None:  # noqa: ANN001
        self.url = url
        self._key = key
        self._key_file = key_file
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect)

    @classmethod
    def from_settings(cls, settings: Settings) -> PushgateClient:
        return cls(settings.pushgate_url, settings.pushgate_key, settings.pushgate_key_file)

    def problem(self) -> str | None:
        """Why alerts cannot be sent, or None when the client is configured."""
        if not self.url:
            return "UPTIME_PUSHGATE_URL is not set"
        try:
            self._read_key()
        except PushgateError as exc:
            return str(exc)
        return None

    def _read_key(self) -> str:
        # Read on every send, so a rotated key applies without a restart.
        key = self._key
        if not key:
            if self._key_file is None:
                raise PushgateError("No Pushgate API key configured")
            try:
                key = self._key_file.read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                raise PushgateError(
                    f"No Pushgate API key: set UPTIME_PUSHGATE_KEY or create {self._key_file}"
                ) from None
            except OSError as exc:
                raise PushgateError(f"Cannot read {self._key_file}: {exc.strerror}") from None
        if not KEY_PATTERN.fullmatch(key):
            # Never log the value itself.
            raise PushgateError("The configured Pushgate API key has the wrong format (expected pgk_…)")
        return key

    def send(self, title: str, message: str, priority: str = "normal", tag: str | None = None) -> dict:
        if not self.url:
            raise PushgateError("UPTIME_PUSHGATE_URL is not set")
        body: dict = {"title": _line(title, TITLE_MAX), "message": _text(message, MESSAGE_MAX), "priority": priority}
        if tag:
            body["tag"] = tag
        request = urllib.request.Request(
            self.url + "/api/v1/notifications",
            data=json.dumps(body).encode(),
            method="POST",
            headers={
                "Authorization": "Bearer " + self._read_key(),
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "uptime-status",
            },
        )
        try:
            with self._opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as res:
                return _json(res.read(65536))
        except urllib.error.HTTPError as exc:
            code = (_json(exc.read(65536)).get("error") or {}).get("code") if exc.fp else None
            hint = _HINTS.get((exc.code, code)) or _HINTS.get((exc.code, None))
            if 300 <= exc.code < 400:
                hint = "Pushgate redirected the request; check UPTIME_PUSHGATE_URL"
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            raise PushgateError(
                f"Pushgate answered HTTP {exc.code}" + (f" ({code})" if code else "") + (f": {hint}" if hint else ""),
                float(retry_after) if retry_after and retry_after.isdigit() else None,
            ) from None
        except urllib.error.URLError as exc:
            raise PushgateError(f"Pushgate is unreachable: {exc.reason}") from None
        except (TimeoutError, OSError) as exc:
            raise PushgateError(f"Pushgate is unreachable: {exc}") from None


def _json(raw: bytes) -> dict:
    try:
        value = json.loads(raw or b"{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


# Pushgate rejects control, invisible-format and line/paragraph separator characters.
_REJECTED = {"Cc", "Cf", "Zl", "Zp"}


def _line(value: str, limit: int) -> str:
    text = "".join(" " if unicodedata.category(ch) in _REJECTED else ch for ch in value)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _text(value: str, limit: int) -> str:
    text = "\n".join(_line(line, limit) for line in value.split("\n")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------- What to send ----------


@dataclass
class Notice:
    title: str
    message: str
    priority: str
    tag: str | None
    # Incident ids to mark, and which column ("alert_sent_at" or "recovery_sent_at").
    incident_ids: list[int]
    column: str


@dataclass
class _Due:
    incident_id: int
    monitor_id: int
    name: str
    kind: str
    error: str | None
    started_at: datetime
    resolved_at: datetime | None
    status: str


def fmt_duration(delta: timedelta) -> str:
    minutes = max(0, int(delta.total_seconds() // 60))
    if minutes < 1:
        return "less than a minute"
    days, rest = divmod(minutes, 1440)
    hours, mins = divmod(rest, 60)
    parts = [f"{days} d" if days else "", f"{hours} h" if hours else "", f"{mins} min" if mins and not days else ""]
    return " ".join(p for p in parts if p)


def _due(db: Session, cfg: AlertConfig, now: datetime) -> tuple[list[_Due], list[_Due]]:
    kinds = ["down", "degraded"] if cfg.on_degraded else ["down"]
    columns = (Incident, Monitor)
    base = select(*columns).join(Monitor, Monitor.id == Incident.monitor_id).where(Monitor.alerts_enabled.is_(True))

    def row(inc: Incident, mon: Monitor) -> _Due:
        return _Due(inc.id, mon.id, mon.name, inc.kind, inc.error, inc.started_at, inc.resolved_at, mon.status)

    outages = []
    for inc, mon in db.execute(
        base.where(
            Incident.resolved_at.is_(None),
            Incident.alert_sent_at.is_(None),
            Incident.kind.in_(kinds),
            Monitor.enabled.is_(True),
        ).order_by(Incident.started_at)
    ):
        delay = cfg.after_minutes if mon.alert_after_minutes is None else mon.alert_after_minutes
        if inc.started_at + timedelta(minutes=delay) <= now:
            outages.append(row(inc, mon))

    recoveries = []
    if cfg.on_recovery:
        recoveries = [
            row(inc, mon)
            for inc, mon in db.execute(
                base.where(
                    Incident.resolved_at >= now - RECOVERY_WINDOW,
                    Incident.alert_sent_at.is_not(None),
                    Incident.recovery_sent_at.is_(None),
                ).order_by(Incident.resolved_at)
            )
        ]
    return outages, recoveries


def build_notices(cfg: AlertConfig, outages: list[_Due], recoveries: list[_Due], now: datetime) -> list[Notice]:
    notices: list[Notice] = []
    recovery_priority = "low" if cfg.priority == "low" else "normal"

    if len(outages) > GROUP_THRESHOLD:
        lines = [f"- {d.name}: {d.error or ('slow' if d.kind == 'degraded' else 'down')}" for d in outages]
        notices.append(
            Notice(
                f"{len(outages)} services have problems",
                _summary(lines),
                cfg.priority,
                None,
                [d.incident_id for d in outages],
                "alert_sent_at",
            )
        )
    else:
        for d in outages:
            since = d.started_at.strftime("%H:%M UTC")
            if d.kind == "degraded":
                title = f"{d.name} is slow"
                message = f"Slow for {fmt_duration(now - d.started_at)} (since {since})."
            else:
                title = f"{d.name} is down"
                message = f"Down for {fmt_duration(now - d.started_at)} (since {since})."
            if d.error:
                message += f"\n{d.error}"
            tag = f"uptime-{d.monitor_id}"
            notices.append(Notice(title, message, cfg.priority, tag, [d.incident_id], "alert_sent_at"))

    if len(recoveries) > GROUP_THRESHOLD:
        lines = [f"- {d.name} (after {fmt_duration(d.resolved_at - d.started_at)})" for d in recoveries]
        notices.append(
            Notice(
                f"{len(recoveries)} services recovered",
                _summary(lines),
                recovery_priority,
                None,
                [d.incident_id for d in recoveries],
                "recovery_sent_at",
            )
        )
    else:
        for d in recoveries:
            took = fmt_duration(d.resolved_at - d.started_at)
            if d.kind == "degraded":
                title, message = f"{d.name} is fast again", f"Response times are back to normal after {took}."
            else:
                title, message = f"{d.name} is back up", f"Recovered after {took} of downtime."
                if d.status == "degraded":
                    message += "\nIt is still slower than usual."
            notices.append(
                Notice(title, message, recovery_priority, f"uptime-{d.monitor_id}", [d.incident_id], "recovery_sent_at")
            )
    return notices


def _summary(lines: list[str]) -> str:
    out: list[str] = []
    for i, line in enumerate(lines):
        if sum(len(x) + 1 for x in out) + len(line) > MESSAGE_MAX - 40:
            out.append(f"… and {len(lines) - i} more")
            break
        out.append(line)
    return "\n".join(out)


# ---------- The sweep ----------


def run_alerts(settings: Settings, client: PushgateClient | None = None, now: datetime | None = None) -> int:
    """Send every alert that is due. Returns the number of notifications sent."""
    now = now or utcnow()
    if alert_status.retry_at and now < alert_status.retry_at:
        return 0
    with session_scope() as db:
        cfg = get_alert_config(db)
        if not cfg.enabled:
            return 0
        outages, recoveries = _due(db, cfg, now)
    if not outages and not recoveries:
        return 0

    client = client or PushgateClient.from_settings(settings)
    sent = 0
    for notice in build_notices(cfg, outages, recoveries, now):
        try:
            result = client.send(notice.title, notice.message, notice.priority, notice.tag)
        except PushgateError as exc:
            log.warning("Could not send alert %r: %s", notice.title, exc)
            alert_status.failed(utcnow(), str(exc), exc.retry_after)
            break  # Pushgate is probably unavailable; try the rest after the pause
        sent += 1
        alert_status.succeeded(utcnow())
        if result.get("status") in {"no_devices", "filtered"}:
            log.warning("Alert %r reached no device (Pushgate status %s)", notice.title, result.get("status"))
        else:
            log.info("Sent alert %r", notice.title)
        column = getattr(Incident, notice.column)
        with session_scope() as db:
            db.execute(
                update(Incident).where(Incident.id.in_(notice.incident_ids), column.is_(None)).values({column: now})
            )
    return sent


def send_test(settings: Settings, priority: str) -> dict:
    client = PushgateClient.from_settings(settings)
    now = utcnow()
    try:
        result = client.send(
            "Test alert",
            "Push alerts from your status page work. You will be notified like this when a service is down.",
            priority,
        )
    except PushgateError as exc:
        alert_status.failed(now, str(exc), backoff=False)
        raise
    alert_status.succeeded(now)
    return result
