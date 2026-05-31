from __future__ import annotations
import re
import httpx
from sentinel.config import Settings
from sentinel.scoring.scorer import Alert

async def send_discord_alert(settings: Settings, commit_sha: str, alerts: list[Alert]) -> None:
    if not settings.discord_webhook_url or not alerts:
        return
    if len(alerts) == 1:
        title, description = f"{alerts[0].severity}: {alerts[0].vector_type}", alerts[0].summary
    else:
        counts = {}
        for alert in alerts: counts[alert.vector_type] = counts.get(alert.vector_type, 0) + 1
        title = f"HIGH: {len(alerts)} findings in commit {commit_sha[:7]}"
        description = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    provider = next((a.detection_provider for a in alerts if a.detection_provider), "sentinel")
    evidence = next((a.evidence_url for a in alerts if a.evidence_url), "")
    commit_value = f"[{commit_sha[:12]}]({_commit_url(commit_sha, alerts)})" if _commit_url(commit_sha, alerts) else (commit_sha[:12] or "unknown")
    evidence_value = f"[Open evidence]({evidence})" if evidence else commit_value
    payload = {
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": 15158332,
                "fields": [
                    {"name": "commit", "value": commit_value, "inline": True},
                    {"name": "provider", "value": provider, "inline": True},
                    {"name": "evidence", "value": evidence_value, "inline": False},
                ],
            }
        ]
    }
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(settings.discord_webhook_url, json=payload)
        response.raise_for_status()


def _commit_url(commit_sha: str, alerts: list[Alert]) -> str:
    repository = next((alert.repository for alert in alerts if alert.repository), "")
    if repository and re.fullmatch(r"[0-9a-fA-F]{12,40}", commit_sha or ""):
        return f"https://github.com/{repository}/commit/{commit_sha}"
    return ""
