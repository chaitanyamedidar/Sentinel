from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, time, timedelta

from sentinel.config import Settings
from sentinel.db.duckdb import SentinelStore
from sentinel.enrichment.mcpscan import run_mcp_scan

LOGGER = logging.getLogger("sentinel.scheduler")


async def daily_mcp_scan(settings: Settings, store: SentinelStore) -> None:
    while True:
        await asyncio.sleep(_seconds_until_next_midnight_utc())
        try:
            await run_mcp_scan("daily-cron", ["."], store, settings.home)
        except Exception:
            LOGGER.exception("daily mcp-scan failed")


def _seconds_until_next_midnight_utc(now: datetime | None = None) -> float:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    tomorrow = (current + timedelta(days=1)).date()
    target = datetime.combine(tomorrow, time.min, tzinfo=UTC)
    return max(1.0, (target - current).total_seconds())
