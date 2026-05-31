from sentinel.main import _discord_brief


def test_discord_brief_includes_issue_vector_and_evidence_link():
    message = _discord_brief(
        "are we safe to release?",
        "vw_release_blockers.sql",
        [
            {
                "repository": "org/repo",
                "commit_sha": "91441f6c1c9f69a378c576ec5fbe7d3438ac2be4",
                "actor_login": "alice",
                "vector_type": "credential_in_pr_body",
                "score": 90,
                "severity": "CRITICAL",
                "summary": "Credential-like token detected in pull request metadata.",
            }
        ],
        "https://sentinel.example",
    )

    assert "SENTINEL Release Risk" in message
    assert "Credential In Pr Body" in message
    assert "Credential-like token detected" in message
    assert "https://github.com/org/repo/commit/91441f6c1c9f69a378c576ec5fbe7d3438ac2be4" in message
