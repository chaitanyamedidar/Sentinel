SELECT actor, tier, sent_at, channel, status
FROM sentinel.brief_deliveries
ORDER BY sent_at DESC
LIMIT 100
