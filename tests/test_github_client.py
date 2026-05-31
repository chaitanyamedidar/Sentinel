from sentinel.github_client import pull_request_number, pull_request_ref


def test_pull_request_context_helpers():
    payload = {"number": 42, "pull_request": {"head": {"sha": "abc123", "ref": "feature"}}}

    assert pull_request_number(payload) == 42
    assert pull_request_ref(payload, "fallback") == "abc123"


def test_pull_request_context_helpers_handle_missing_values():
    assert pull_request_number({}) is None
    assert pull_request_ref({}, "fallback") == "fallback"
