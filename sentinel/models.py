from __future__ import annotations
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    actor_login: str
    action: str
    repository: str
    head_sha: str
    ip_address: str
    created_at: str
    raw_payload: str
    ci_exfiltration_detected: bool = False
    self_hosted_first_actor: bool = False
    force_push_after_approval: bool = False
    unsigned_maintainer_commit: bool = False
    action_typosquat_detected: bool = False
    orphan_pkg_owner_change: bool = False

    def as_row(self) -> dict[str, Any]:
        return self.__dict__.copy()
