from __future__ import annotations

from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta


class AlertRateEscalator:
    def __init__(self, threshold: int = 40, window_seconds: int = 600) -> None:
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._events: dict[str, deque[datetime]] = defaultdict(deque)
        self._escalated_until: dict[str, datetime] = {}

    def record(self, repository: str) -> bool:
        repo = repository or "unknown"
        now = datetime.now(UTC)
        events = self._events[repo]
        events.append(now)
        while events and now - events[0] > self.window:
            events.popleft()
        if len(events) < self.threshold:
            return False
        if self._escalated_until.get(repo, datetime.min.replace(tzinfo=UTC)) > now:
            return False
        self._escalated_until[repo] = now + self.window
        return True
