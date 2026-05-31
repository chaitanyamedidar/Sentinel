from sentinel.audit_polling import _normalize_audit_row


def test_normalize_audit_row_redacts_secret_payload():
    row = {
        "_document_id": "doc1",
        "actor": "alice",
        "action": "org.oauth_application_grant",
        "repo": "org/repo",
        "actor_ip": "10.0.0.1",
        "@timestamp": "2026-05-31T00:00:00Z",
        "token": "DEMO_FAKE_TOKEN_1234567890",
    }

    event = _normalize_audit_row("org", row)

    assert event["event_id"] == "doc1"
    assert event["actor_login"] == "alice"
    assert event["repository"] == "org/repo"
    assert "DEMO_FAKE_TOKEN_1234567890" not in event["raw_payload"]
