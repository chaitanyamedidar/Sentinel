from __future__ import annotations
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
import httpx
from sentinel.db.duckdb import SentinelStore
from sentinel.models import utc_now_iso
POPULAR_PACKAGES = {"react","lodash","express","typescript","vite","next","pytest","fastapi","requests","numpy","pandas","django","flask","httpx","pydantic","ruff"}

async def enrich_packages(commit_sha: str, packages: list[Mapping[str, str]], store: SentinelStore) -> None:
    async with httpx.AsyncClient(timeout=20) as client:
        for package in packages:
            try: row = await _enrich_one(client, commit_sha, package)
            except httpx.HTTPError: continue
            await store.insert("enriched_packages", row, lock_key=commit_sha)

async def _enrich_one(client: httpx.AsyncClient, commit_sha: str, package: Mapping[str, str]) -> dict[str, Any]:
    metadata = await (_pypi(client, package["name"], package["version"]) if package.get("ecosystem") in {"pypi","python"} else _npm(client, package["name"], package["version"]))
    return {"commit_sha": commit_sha, "package_name": package["name"], "package_age_hours": metadata["package_age_hours"], "maintainer_age_days": metadata.get("maintainer_age_days", 9999), "has_postinstall": metadata.get("has_postinstall", False), "name_edit_distance": min(_levenshtein(package["name"], candidate) for candidate in POPULAR_PACKAGES), "source_repo_present": metadata.get("source_repo_present", False), "written_at": utc_now_iso()}

async def _npm(client: httpx.AsyncClient, name: str, version: str) -> dict[str, Any]:
    response = await client.get(f"https://registry.npmjs.org/{name}")
    response.raise_for_status()
    payload = response.json()
    version_payload = (payload.get("versions") or {}).get(version) or {}
    return {"package_age_hours": _age_hours((payload.get("time") or {}).get(version) or (payload.get("time") or {}).get("created")), "has_postinstall": "postinstall" in (version_payload.get("scripts") or {}), "source_repo_present": bool(version_payload.get("repository") or payload.get("repository"))}

async def _pypi(client: httpx.AsyncClient, name: str, version: str) -> dict[str, Any]:
    response = await client.get(f"https://pypi.org/pypi/{name}/json"); response.raise_for_status(); payload = response.json()
    release = ((payload.get("releases") or {}).get(version) or [{}])[0]
    urls = (payload.get("info") or {}).get("project_urls") or {}
    return {"package_age_hours": _age_hours(release.get("upload_time_iso_8601") or release.get("upload_time")), "has_postinstall": False, "source_repo_present": bool(urls.get("Source") or urls.get("Homepage"))}

def _age_hours(timestamp: str | None) -> float:
    if not timestamp: return 999999.0
    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if dt.tzinfo is None: dt = dt.replace(tzinfo=UTC)
    return max(0.0, (datetime.now(UTC) - dt).total_seconds() / 3600)

def _levenshtein(left: str, right: str) -> int:
    previous = list(range(len(right)+1))
    for i, lc in enumerate(left, 1):
        current = [i]
        for j, rc in enumerate(right, 1): current.append(min(previous[j]+1, current[j-1]+1, previous[j-1]+(lc != rc)))
        previous = current
    return previous[-1]
