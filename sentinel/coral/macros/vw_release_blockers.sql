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
WHERE alerts.score >= 60
  OR vector_type IN (
    'unsigned_commit_core_maintainer',
    'ci_exfiltration_script_detected',
    'orphan_pkg_recent_owner_change',
    'first_time_actor_self_hosted',
    'force_push_after_approval',
    'action_typosquat_distance_lte_2'
  )
ORDER BY alerts.created_at DESC
LIMIT 100
