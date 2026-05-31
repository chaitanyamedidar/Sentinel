from sentinel.scoring.scorer import BYPASS_BUFFER, SCORING_RULES, score_findings


def test_first_time_contributor_pushes_socket_finding_over_threshold():
    alerts = score_findings("abc1234", "alice", [{"severity": "HIGH", "issue_type": "malicious", "provider": "socket"}], [], [], first_time_contributor=True, threshold=60)
    assert alerts
    assert alerts[0].vector_type == "supply_chain_malicious_package"
    assert alerts[0].detection_provider == "socket"


def test_bot_allowlist_suppresses_alerts():
    alerts = score_findings("abc1234", "dependabot[bot]", [{"severity": "CRITICAL", "issue_type": "malicious", "provider": "socket"}], [], [], first_time_contributor=True, threshold=60)
    assert alerts == []


def test_delta_attack_vector_rules_are_registered():
    for vector in {
        "unsigned_commit_core_maintainer",
        "ci_exfiltration_script_detected",
        "orphan_pkg_recent_owner_change",
        "first_time_actor_self_hosted",
        "force_push_after_approval",
        "action_typosquat_distance_lte_2",
    }:
        assert vector in SCORING_RULES
    assert "ci_exfiltration_script_detected" in BYPASS_BUFFER
    assert "unsigned_commit_core_maintainer" in BYPASS_BUFFER


def test_boolean_event_flags_map_to_scoring_rules():
    alerts = score_findings("abc1234", "alice", [], [], [], event_flags={"ci_exfiltration_detected": True}, first_time_contributor=True, threshold=60)
    assert alerts
    assert alerts[0].vector_type == "ci_exfiltration_script_detected"
