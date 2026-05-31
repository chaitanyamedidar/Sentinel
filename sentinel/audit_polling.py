from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from sentinel.config import Settings
from sentinel.db.duckdb import SentinelStore
from sentinel.security import redacted_json

LOGGER = logging.getLogger("sentinel.audit_polling")


async def github_audit_poll_loop(settings: Settings, store: SentinelStore) -> None:
    if settings.github_access_tier != "teams" or not settings.github_org or not settings.github_token:
        return
    cursor: str | None = None
    while True:
        try:
            cursor = await poll_github_audit_log(settings, store, cursor)
        except Exception:
            LOGGER.exception("GitHub audit-log poll failed")
        await asyncio.sleep(300)


async def poll_github_audit_log(settings: Settings, store: SentinelStore, cursor: str | None = None) -> str | None:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {settings.github_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params: dict[str, Any] = {"per_page": 100, "order": "asc"}
    if cursor:
        params["after"] = cursor
    else:
        params["phrase"] = f"created:>={_created_since()}"
    async with httpx.AsyncClient(base_url="https://api.github.com", headers=headers, timeout=20) as client:
        response = await client.get(f"/orgs/{settings.github_org}/audit-log", params=params)
        response.raise_for_status()
        rows = response.json()
    if not isinstance(rows, list):
        return cursor
    latest = cursor
    for row in rows:
        if not isinstance(row, dict):
            continue
        event = _normalize_audit_row(settings.github_org, row)
        await store.insert("audit_events", event, lock_key=event["event_id"])
        latest = str(row.get("@timestamp") or row.get("created_at") or latest or "")
    return latest


def _normalize_audit_row(org: str, row: dict[str, Any]) -> dict[str, str]:
    created_at = str(row.get("@timestamp") or row.get("created_at") or datetime.now(UTC).isoformat())
    repository = str(row.get("repo") or row.get("repository") or org)
    return {
        "event_id": str(row.get("_document_id") or row.get("id") or f"audit:{row.get('action')}:{created_at}"),
        "actor_login": str(row.get("actor") or row.get("user") or "unknown"),
        "action": str(row.get("action") or "audit_log"),
        "repository": repository,
        "head_sha": str(row.get("head_sha") or ""),
        "ip_address": str(row.get("actor_ip") or row.get("ip_address") or ""),
        "created_at": created_at,
        "raw_payload": redacted_json(row),
    }


def _created_since() -> str:
    return (datetime.now(UTC) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
