from __future__ import annotations

import httpx

from sentinel.config import Settings
from sentinel.scoring.scorer import Alert


async def send_slack_alert(settings: Settings, commit_sha: str, alerts: list[Alert]) -> None:
    if not settings.slack_bot_token or not settings.slack_channel_id or not alerts:
        return
    headers = {"Authorization": f"Bearer {settings.slack_bot_token}", "Content-Type": "application/json; charset=utf-8"}
    payload = _payload(settings.slack_channel_id, commit_sha, alerts)
    async with httpx.AsyncClient(timeout=15, headers=headers) as client:
        response = await client.post("https://slack.com/api/chat.postMessage", json=payload)
        response.raise_for_status()
        body = response.json()
        if not body.get("ok"):
            raise RuntimeError(f"Slack chat.postMessage failed: {body.get('error', 'unknown_error')}")


def _payload(channel_id: str, commit_sha: str, alerts: list[Alert]) -> dict:
    provider = next((alert.detection_provider for alert in alerts if alert.detection_provider), "sentinel")
    if len(alerts) == 1:
        title = f"{alerts[0].severity}: {alerts[0].vector_type}"
        summary = alerts[0].summary
    else:
        counts: dict[str, int] = {}
        for alert in alerts:
            counts[alert.vector_type] = counts.get(alert.vector_type, 0) + 1
        title = f"HIGH: {len(alerts)} findings in commit {commit_sha[:7]}"
        summary = ", ".join(f"{kind}={count}" for kind, count in sorted(counts.items()))
    evidence = next((alert.evidence_url for alert in alerts if alert.evidence_url), "")
    commit_text = f"<{evidence}|{commit_sha[:12]}>" if evidence else f"`{commit_sha[:12] or 'unknown'}`"
    return {
        "channel": channel_id,
        "text": f"SENTINEL {title}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"SENTINEL {title}", "emoji": False}},
            {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*commit:* {commit_text}"},
                    {"type": "mrkdwn", "text": f"*provider:* `{provider}`"},
                ],
            },
        ],
    }
