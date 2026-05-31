from sentinel.dispatch.escalation import AlertRateEscalator


def test_alert_rate_escalator_triggers_once_per_window():
    escalator = AlertRateEscalator(threshold=3, window_seconds=600)

    assert not escalator.record("org/repo")
    assert not escalator.record("org/repo")
    assert escalator.record("org/repo")
    assert not escalator.record("org/repo")
