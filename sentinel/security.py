from __future__ import annotations
import hashlib, hmac, json, re
from collections.abc import Mapping, Sequence
from typing import Any

SECRET_KEY_RE = re.compile(r"(token|secret|password|api[_-]?key|authorization|credential)", re.I)
SECRET_VALUE_RE = re.compile(r"(ghp_[A-Za-z0-9_]{8,}|sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{8,}|Bearer\s+[A-Za-z0-9._-]{8,}|password=\S+|token=\S+|api_key=\S+|secret=\S+)", re.I)


def verify_github_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", signature_header)


def contains_secret(text: str | None) -> bool:
    return bool(text and SECRET_VALUE_RE.search(text))


def redact_text(value: str) -> str:
    return SECRET_VALUE_RE.sub("[REDACTED]", value)


def redact_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: "[REDACTED]" if SECRET_KEY_RE.search(str(k)) else redact_payload(v) for k, v in value.items()}
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [redact_payload(item) for item in value]
    return value


def redacted_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(redact_payload(payload), separators=(",", ":"), sort_keys=True)
