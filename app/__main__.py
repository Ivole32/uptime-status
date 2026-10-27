"""Container entry point: apply migrations, then serve with uvicorn."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import uvicorn
from alembic import command
from alembic.config import Config

ROOT = Path(__file__).resolve().parent.parent


def migrate() -> None:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.attributes["skip_logging"] = True  # keep the app's logging configuration
    command.upgrade(cfg, "head")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    migrate()
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("UPTIME_HOST", "0.0.0.0"),  # noqa: S104 - inside the container
        port=int(os.environ.get("UPTIME_PORT", "8000")),
        workers=1,  # the scheduler must run in exactly one process
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("UPTIME_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        server_header=False,
        date_header=False,
        access_log=os.environ.get("UPTIME_ACCESS_LOG", "true").lower() in {"1", "true", "yes"},
        timeout_keep_alive=5,
        limit_concurrency=500,
        h11_max_incomplete_event_size=16 * 1024,
    )


if __name__ == "__main__":
    main()
