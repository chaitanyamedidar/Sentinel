from __future__ import annotations
from collections.abc import Mapping
import httpx
from sentinel.db.duckdb import SentinelStore
from sentinel.models import utc_now_iso

async def scan_osv(commit_sha: str, packages: list[Mapping[str, str]], store: SentinelStore) -> None:
    async with httpx.AsyncClient(timeout=20) as client:
        for package in packages:
            ecosystem = "PyPI" if package.get("ecosystem") in {"pypi", "python"} else "npm"
            response = await client.post("https://api.osv.dev/v1/query", json={"package": {"name": package["name"], "ecosystem": ecosystem}, "version": package["version"]})
            response.raise_for_status()
            for vuln in response.json().get("vulns") or []:
                await store.insert("osv_findings", {"commit_sha": commit_sha, "package_name": package["name"], "vuln_id": vuln.get("id", ""), "severity": _severity(vuln), "ecosystem": ecosystem, "written_at": utc_now_iso()}, lock_key=commit_sha)

def _severity(vuln: Mapping) -> str:
    severities = vuln.get("severity") or []
    if severities and isinstance(severities[0], Mapping):
        score = str(severities[0].get("score") or "")
        return "CRITICAL" if score.startswith(("9", "10")) else "HIGH"
    return str((vuln.get("database_specific") or vuln.get("databaseSpecific") or {}).get("severity") or "UNKNOWN").upper()
