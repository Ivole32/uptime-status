"""Pydantic request/response models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    field_validator,
    model_validator,
)

from .checker import TargetError, normalize_target
from .config import get_settings


def iso_utc(value: datetime | None) -> str | None:
    """Serialise a naive-UTC datetime as ISO 8601 with a trailing Z."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC, microsecond=0).isoformat().replace("+00:00", "Z")


UTCDateTime = Annotated[datetime, PlainSerializer(iso_utc, return_type=str)]


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    value = "".join(ch for ch in value if ch in "\n\t" or ord(ch) >= 32).strip()
    return value or None


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginIn(BaseModel):
    # No automatic stripping here: whitespace is a legitimate part of a password.
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("username")
    @classmethod
    def _strip_username(cls, value: str) -> str:
        return value.strip()


class MonitorBase(_Strict):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    url: str = Field(min_length=1, max_length=2048)
    interval_seconds: int = Field(default=60, ge=10, le=86_400)
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    enabled: bool = True
    is_public: bool = True
    show_url: bool = False
    sort_order: int = Field(default=0, ge=-10_000, le=10_000)

    @field_validator("name", "description")
    @classmethod
    def _text(cls, value: str | None) -> str | None:
        return _clean_text(value)

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        try:
            settings = get_settings()
            return normalize_target(
                value,
                allow_private=settings.allow_private_targets,
                allowed_ports=settings.allowed_ports,
            )
        except TargetError as exc:
            raise ValueError(str(exc)) from exc

    @model_validator(mode="after")
    def _timeout_below_interval(self) -> MonitorBase:
        if self.name is None:
            raise ValueError("Name must not be empty")
        if self.timeout_seconds >= self.interval_seconds:
            raise ValueError("Timeout must be shorter than the check interval")
        return self


class MonitorIn(MonitorBase):
    pass


class MonitorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    url: str
    interval_seconds: int
    timeout_seconds: int
    enabled: bool
    is_public: bool
    show_url: bool
    sort_order: int
    status: str
    last_checked_at: UTCDateTime | None
    last_response_ms: int | None
    last_status_code: int | None
    last_error: str | None


class CheckOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    checked_at: UTCDateTime
    ok: bool
    response_ms: int | None
    status_code: int | None
    error: str | None


class IncidentOut(BaseModel):
    id: int
    monitor_id: int
    monitor_name: str
    started_at: UTCDateTime
    resolved_at: UTCDateTime | None
    error: str | None


class SiteSettingsIn(_Strict):
    title: str = Field(min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=300)

    @field_validator("title", "description")
    @classmethod
    def _text(cls, value: str | None) -> str | None:
        return _clean_text(value)

    @model_validator(mode="after")
    def _title_required(self) -> SiteSettingsIn:
        if not self.title:
            raise ValueError("Title must not be empty")
        return self
