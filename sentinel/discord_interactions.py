from __future__ import annotations

from typing import Any

from sentinel.config import Settings

PING = 1
APPLICATION_COMMAND = 2
PONG_RESPONSE = 1
CHANNEL_MESSAGE_RESPONSE = 4
EPHEMERAL = 1 << 6


def verify_discord_signature(public_key: str, body: bytes, timestamp: str | None, signature: str | None) -> bool:
    if not public_key or not timestamp or not signature:
        return False
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        return False
    try:
        VerifyKey(bytes.fromhex(public_key)).verify(timestamp.encode("utf-8") + body, bytes.fromhex(signature))
        return True
    except (BadSignatureError, ValueError):
        return False


def extract_query(payload: dict[str, Any]) -> str:
    data = payload.get("data") or {}
    for option in data.get("options") or []:
        if isinstance(option, dict) and option.get("name") in {"query", "text"}:
            return str(option.get("value") or "").strip()
    return str(data.get("query") or data.get("text") or "").strip()


def is_security_team_member(payload: dict[str, Any], settings: Settings) -> bool:
    role_id = settings.discord_security_role_id
    if not role_id:
        return False
    member = payload.get("member") or {}
    return role_id in {str(role) for role in member.get("roles") or []}


def interaction_message(content: str, *, ephemeral: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {"content": content[:1900]}
    if ephemeral:
        data["flags"] = EPHEMERAL
    return {"type": CHANNEL_MESSAGE_RESPONSE, "data": data}


def ping_response() -> dict[str, int]:
    return {"type": PONG_RESPONSE}
