from __future__ import annotations
from sentinel.db.duckdb import SentinelStore
from sentinel.models import utc_now_iso

CONTRIBUTOR_BRIEF = """Hey @{actor}, welcome to the repo!

<details>
<summary>Optional: 5-minute local security checklist</summary>

Protects your local environment from supply chain attacks. SENTINEL scans every PR automatically regardless.

- [ ] `uvx mcp-scan@latest --skills` - check AI agent skills
- [ ] `uvx mcp-scan@latest` - check MCP server configs
- [ ] Audit IDE extensions - remove unknown publishers
- [ ] `git ls-files | grep .env` - no tracked secrets
</details>
"""

async def record_brief(store: SentinelStore, actor: str, tier: str, channel: str = "log", status: str = "sent") -> None:
    await store.insert("brief_deliveries", {"actor": actor, "tier": tier, "sent_at": utc_now_iso(), "channel": channel, "status": status})
