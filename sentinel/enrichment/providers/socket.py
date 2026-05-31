from __future__ import annotations
from collections.abc import Mapping
from urllib.parse import quote
import httpx
from sentinel.config import Settings
SOCKET_BASE_URL = "https://api.socket.dev/v0"

async def scan(packages: list[Mapping[str, str]], settings: Settings) -> list[dict]:
    if not packages or not settings.socket_api_key or not settings.socket_org_slug:
        return []
    purls = [_purl(package) for package in packages]
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(f"{SOCKET_BASE_URL}/orgs/{settings.socket_org_slug}/purl", params={"alerts": "true", "summary": "true"}, auth=(settings.socket_api_key, ""), json={"coordinates": purls})
        response.raise_for_status()
        payload = response.json()
    return _findings(payload, packages)

def _purl(package: Mapping[str, str]) -> str:
    ecosystem = "pypi" if package.get("ecosystem", "npm").lower() in {"python", "pypi"} else package.get("ecosystem", "npm").lower()
    return f"pkg:{ecosystem}/{quote(str(package['name']), safe='@/')}@{quote(str(package['version']), safe='')}"

def _findings(payload: object, packages: list[Mapping[str, str]]) -> list[dict]:
    candidates = []
    if isinstance(payload, dict):
        for key in ("data", "results", "packages", "rows"):
            if isinstance(payload.get(key), list): candidates.extend(payload[key])
        if not candidates and any(k in payload for k in ("alerts", "issues", "score")): candidates.append(payload)
    elif isinstance(payload, list):
        candidates = payload
    rows = []
    fallback = packages[0] if len(packages) == 1 else {}
    for item in candidates:
        if not isinstance(item, dict): continue
        package = {"name": item.get("name") or item.get("package") or fallback.get("name", "unknown"), "version": item.get("version") or fallback.get("version", ""), "ecosystem": item.get("ecosystem") or fallback.get("ecosystem", "npm")}
        alerts = item.get("alerts") or item.get("issues") or []
        if isinstance(alerts, dict): alerts = list(alerts.values())
        if not alerts and _score(item) > 0: alerts = [{"type": "risk_score", "severity": item.get("severity", "MEDIUM")}]
        for alert in alerts:
            alert = alert if isinstance(alert, dict) else {"type": str(alert)}
            rows.append({"package_name": package["name"], "version": package["version"], "ecosystem": package["ecosystem"], "issue_type": alert.get("type") or alert.get("key") or "socket_alert", "severity": str(alert.get("severity") or "MEDIUM").upper(), "risk_score": _score(alert) or _score(item) or 35})
    return rows

def _score(item: Mapping) -> float:
    for key in ("risk_score", "riskScore", "score", "supplyChainRisk"):
        if isinstance(item.get(key), (int, float)): return float(item[key])
    return 0.0
