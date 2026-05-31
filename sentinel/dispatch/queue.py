from __future__ import annotations
import asyncio
from collections import defaultdict
from sentinel.config import Settings
from sentinel.db.duckdb import SentinelStore
from sentinel.dispatch.discord import send_discord_alert
from sentinel.dispatch.slack import send_slack_alert
from sentinel.models import utc_now_iso
from sentinel.scoring.scorer import Alert

class DebounceDispatcher:
    def __init__(self, settings: Settings, store: SentinelStore) -> None:
        self.settings, self.store = settings, store
        self._pending: defaultdict[str, list[Alert]] = defaultdict(list)
        self._tasks: dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    async def enqueue(self, alert: Alert) -> None:
        if not alert.bypass_dedup and await self.store.dedup_seen(alert.commit_sha, alert.actor_login, alert.vector_type):
            return
        if not alert.bypass_dedup:
            await self.store.remember_dedup(alert.commit_sha, alert.actor_login, alert.vector_type)
        await self.store.insert("alert_events", {"commit_sha": alert.commit_sha, "actor_login": alert.actor_login, "vector_type": alert.vector_type, "score": alert.score, "severity": alert.severity, "detection_provider": alert.detection_provider, "summary": alert.summary, "created_at": utc_now_iso()}, lock_key=alert.commit_sha)
        async with self._lock:
            self._pending[alert.commit_sha].append(alert)
            if alert.commit_sha not in self._tasks:
                self._tasks[alert.commit_sha] = asyncio.create_task(self._flush_later(alert.commit_sha))

    async def _flush_later(self, commit_sha: str) -> None:
        await asyncio.sleep(self.settings.debounce_window_seconds)
        async with self._lock:
            alerts = self._pending.pop(commit_sha, [])
            self._tasks.pop(commit_sha, None)
        await asyncio.gather(
            send_discord_alert(self.settings, commit_sha, alerts),
            send_slack_alert(self.settings, commit_sha, alerts),
        )
