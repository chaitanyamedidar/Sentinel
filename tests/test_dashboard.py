import json

from sentinel.dashboard import _milestone_rows, _pull_request_rows


def test_dashboard_admin_rows_include_pr_risk_and_milestones():
    audit_events = [
        {
            "actor_login": "alice",
            "action": "pr_opened",
            "repository": "org/repo",
            "head_sha": "abc1234",
            "created_at": "2026-05-31T10:00:00Z",
            "raw_payload": json.dumps(
                {
                    "number": 42,
                    "pull_request": {
                        "number": 42,
                        "title": "Release hardening",
                        "html_url": "https://github.com/org/repo/pull/42",
                        "milestone": {"title": "v1.0", "due_on": "2026-06-15", "state": "open"},
                    },
                }
            ),
        }
    ]
    alerts_by_commit = {"abc1234": [{"severity": "CRITICAL"}]}
    vulnerabilities_by_commit = {"abc1234": [{"vuln_id": "OSV-1"}]}

    prs = _pull_request_rows(audit_events, alerts_by_commit, vulnerabilities_by_commit)
    milestones = _milestone_rows(prs)

    assert prs[0]["number"] == "42"
    assert prs[0]["risk_level"] == "critical"
    assert prs[0]["status"] == "blocked"
    assert prs[0]["vulnerabilities"] == 1
    assert milestones[0]["name"] == "v1.0"
    assert milestones[0]["status"] == "blocked"
