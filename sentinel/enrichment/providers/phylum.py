from __future__ import annotations
from collections.abc import Mapping
from urllib.parse import quote
import httpx
from sentinel.config import Settings
PHYLUM_BASE_URL = "https://api.phylum.io/api/v0"

async def scan(packages: list[Mapping[str, str]], settings: Settings) -> list[dict]:
    if not packages or not settings.phylum_api_key:
        return []
    rows = []
    headers = {"Authorization": f"Bearer {settings.phylum_api_key}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        for package in packages:
            ecosystem = "pypi" if package.get("ecosystem") in {"pypi", "python"} else package.get("ecosystem", "npm")
            response = await client.get(f"{PHYLUM_BASE_URL}/data/packages/{ecosystem}/{quote(str(package['name']), safe='')}/{quote(str(package['version']), safe='')}")
            response.raise_for_status()
            rows.extend(_findings(response.json(), package))
    return rows

def _findings(payload: Mapping, package: Mapping[str, str]) -> list[dict]:
    issues = payload.get("issues") or []
    if isinstance(issues, dict): issues = list(issues.values())
    risk = payload.get("riskScores", {}).get("total") if isinstance(payload.get("riskScores"), Mapping) else 35
    return [{"package_name": package["name"], "version": package["version"], "ecosystem": package.get("ecosystem", "npm"), "issue_type": (i.get("type") or i.get("title") or "phylum_issue") if isinstance(i, Mapping) else str(i), "severity": str(i.get("severity") if isinstance(i, Mapping) else "MEDIUM").upper(), "risk_score": float(risk or 35)} for i in issues]
