SELECT
  alerts.commit_sha,
  alerts.actor_login,
  alerts.vector_type,
  alerts.score,
  alerts.severity,
  alerts.detection_provider,
  alerts.summary,
  alerts.created_at,
  audit.repository
FROM sentinel.alert_events alerts
LEFT JOIN sentinel.audit_events audit
  ON audit.head_sha = alerts.commit_sha
WHERE alerts.vector_type IN (
  'workflow_permission_escalation',
  'unpinned_external_action',
  'ci_exfiltration_script_detected',
  'first_time_actor_self_hosted',
  'action_typosquat_distance_lte_2'
)
ORDER BY alerts.created_at DESC
LIMIT 100
