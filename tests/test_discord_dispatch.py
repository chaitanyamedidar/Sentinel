from sentinel.dispatch.discord import _commit_url
from sentinel.scoring.scorer import Alert


def test_commit_url_uses_repository_and_full_sha():
    alert = Alert(
        "91441f6c1c9f69a378c576ec5fbe7d3438ac2be4",
        "alice",
        "credential_in_pr_body",
        90,
        "CRITICAL",
        "sentinel",
        "credential found",
        repository="org/repo",
    )

    assert _commit_url(alert.commit_sha, [alert]) == "https://github.com/org/repo/commit/91441f6c1c9f69a378c576ec5fbe7d3438ac2be4"
