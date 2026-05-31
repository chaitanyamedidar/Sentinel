import hashlib
import hmac
from sentinel.security import redact_payload, verify_github_signature


def test_verify_github_signature_accepts_valid_header():
    body = b'{"ok":true}'
    secret = "secret"
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_github_signature(secret, body, f"sha256={digest}")


def test_verify_github_signature_rejects_missing_header():
    assert not verify_github_signature("secret", b"{}", None)


def test_redact_payload_masks_secret_keys_and_values():
    redacted = redact_payload({"token": "abc", "body": "password=hunter2"})
    assert redacted["token"] == "[REDACTED]"
    assert "hunter2" not in redacted["body"]
