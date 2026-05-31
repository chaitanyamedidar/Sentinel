# SENTINEL Demo Scenario

1. Replay a PR with a young postinstall package and verify a high supply-chain alert with `provider: socket`.
2. If Phylum access is available, set `SUPPLY_CHAIN_PROVIDER=phylum` and replay the same fixture.
3. Replay a PR modifying `SKILL.md`; verify mcp-scan runs before scoring.
4. Replay a credential pattern in PR description; verify high alert without triage delay.
5. Replay two credential fixtures with the same commit; verify one aggregated Discord embed.
6. Replay workflow permissions fixture; verify delayed triage behavior.
7. Replay first-time contributor fixture; verify `brief_deliveries` row.
8. Run `/sentinel "are we safe to release?"`; verify it maps to `vw_release_blockers.sql`.
