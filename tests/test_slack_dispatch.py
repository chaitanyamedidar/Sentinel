from sentinel.dispatch.slack import _payload
from sentinel.scoring.scorer import Alert


def test_slack_payload_aggregates_findings():
    alerts = [
        Alert("abcdef123456", "alice", "credential_in_pr_body", 90, "CRITICAL", "socket", "credential found"),
        Alert("abcdef123456", "alice", "supply_chain_malicious_package", 95, "CRITICAL", "socket", "package found"),
    ]

    payload = _payload("C123", "abcdef123456", alerts)

    assert payload["channel"] == "C123"
    assert "2 findings" in payload["text"]
    assert "credential_in_pr_body=1" in payload["blocks"][1]["text"]["text"]
    assert "provider:* `socket`" in payload["blocks"][2]["elements"][1]["text"]


def test_slack_payload_links_evidence_when_available():
    alerts = [
        Alert("abcdef123456", "alice", "credential_in_pr_body", 90, "CRITICAL", "sentinel", "credential found", evidence_url="https://github.com/org/repo/pull/1"),
    ]

    payload = _payload("C123", "abcdef123456", alerts)

    assert "<https://github.com/org/repo/pull/1|abcdef123456>" in payload["blocks"][2]["elements"][0]["text"]
