# SENTINEL

SENTINEL is an async, read-only security agent for open-source repositories. It watches pull requests, package changes, workflow files, AI-agent configs, Slack/Jira approval context, and local findings, then turns that evidence into deterministic Discord and Slack alerts.

It is built for the Coral hackathon formula: real problem, multiple data sources, meaningful joins, working demo, and a clear story.

## What Problem We Solve

Open-source maintainers now review more than code. A normal pull request can hide a leaked credential, a risky dependency, a workflow permission escalation, a poisoned AI-agent skill, or a GitHub Action typo that changes who gets trusted inside CI.
<img width="2048" height="1117" alt="13" src="https://github.com/user-attachments/assets/f0c42a16-5dfa-4cf3-a983-015c99d9ba1a" />

This is already happening:

- Vercel / Context.ai incident: attackers reportedly abused over-permissioned third-party AI access into Google Workspace, with stolen data allegedly listed for about USD 2M.
  Source: https://www.tomshardware.com/tech-industry/cyber-security/vercel-breached-after-employee-grants-ai-tool-unrestricted-access-to-google-workspace
- `tj-actions/changed-files` compromise: a trusted GitHub Action affected 23,000+ repositories and exposed CI/CD secrets in workflow logs.
  Source: https://arstechnica.com/information-technology/2025/03/supply-chain-attack-exposing-credentials-affects-23k-users-of-tj-actions/
- Nx S1ngularity attack: malicious npm packages were published after a GitHub Actions weakness led to token theft, turning developer tooling into a supply-chain blast radius.
  Source: https://nx.dev/blog/s1ngularity-postmortem

SENTINEL focuses on the maintainer gap: CI may pass, but the repository attack surface has changed.

## What We Built
<img width="2048" height="1117" alt="16" src="https://github.com/user-attachments/assets/b71b433e-c2e6-45ed-b9dd-3d9b463aad6a" />



SENTINEL is a FastAPI service with:

- Signed GitHub webhook ingestion.
- DuckDB as the canonical local security database.
- JSONL mirrors so Coral can query SENTINEL data as read-only file-backed sources.
- Socket.dev or Phylum supply-chain enrichment.
- OSV.dev vulnerability enrichment.
- npm and PyPI package metadata enrichment.
- mcp-scan plus deterministic AI-agent skill poisoning checks.
- Deterministic scoring for release-risk vectors.
- Debounced Discord and Slack alert delivery with clickable evidence links.
- Jira and Slack approval context for human-in-the-loop review.
- A local dashboard for demo and triage.
- A role-gated Discord `/sentinel` command that maps natural language to fixed Coral SQL macros.

SENTINEL does not block CI. It watches, correlates, scores, and routes evidence fast.

## How We Used Coral
<img width="2048" height="1117" alt="14" src="https://github.com/user-attachments/assets/fe21f52b-cf50-47a2-bb53-dd02b3a85c5c" />

Coral is the query layer.

SENTINEL writes operational data into DuckDB and mirrors queryable rows into `runtime/coral-data/*.jsonl`. The app-local Coral source spec at `sentinel/sources/sentinel_findings.yaml` exposes those JSONL files as Coral tables.

Natural language never becomes arbitrary SQL. Instead:

1. A user asks `/sentinel query: are we safe to release?`.
2. `sentinel/coral/query.py` maps that intent to a fixed macro file.
3. Coral executes the approved SQL macro, for example `sentinel/coral/macros/vw_release_blockers.sql`.
4. SENTINEL returns a concise security brief with evidence links.

This gives us meaningful joins over repo events, findings, approvals, tickets, package intelligence, and file-backed evidence without turning the LLM into a query author.

## Connected Data Sources

Core demo sources:

- GitHub webhooks: pull requests, pushes, changed files, commit SHAs, actor identity.
- DuckDB: canonical SENTINEL findings and alert history.
- JSONL files: Coral-readable mirror of DuckDB tables.
- Socket.dev: package and supply-chain intelligence.
- OSV.dev: known vulnerability data.
- npm and PyPI registries: package age, postinstall scripts, source repository metadata.
- mcp-scan: AI-agent skill and MCP configuration scan results.
- Slack: alert delivery and approval convention.
- Jira: approval/change-ticket lookup.
- Discord: alert delivery and `/sentinel` query surface.

Optional / enterprise sources:

- Phylum for paid supply-chain intelligence.
- GitHub Teams/Enterprise audit log polling.
- Google Workspace Admin SDK audit logs.

## Demo Attack Surfaces

Live demo PRs are available in `chaitanyamedidar/sentinel-demo-repo`:

- PR #1: supply-chain risk.
- PR #2: credential exposure in PR metadata.
- PR #3: poisoned AI-agent `SKILL.md`.
- PR #4: workflow permission escalation fixture.
- PR #5: CI exfiltration fixture.
- PR #6: GitHub Action typosquat fixture.

SENTINEL also includes dashboard demo scenarios for identity/audit vectors that are difficult to reproduce safely on GitHub Free.
<img width="1474" height="854" alt="Screen Recording 2026-05-31 234746(1)" src="https://github.com/user-attachments/assets/96d48f96-889c-447b-8735-fcc865dd7bda" />


## Architecture

```text
GitHub Webhooks
  -> FastAPI ingestor
  -> DuckDB canonical store
  -> JSONL mirror
  -> Coral source spec
  -> fixed Coral SQL macros
  -> deterministic scorer
  -> Discord / Slack / dashboard
```

Enrichment runs asynchronously and fail-open:

```text
Socket / Phylum
OSV.dev
npm / PyPI
mcp-scan
Jira / Slack approval context
```

## Setup

```powershell
cd E:\Files\Projects\SENTINEL
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn sentinel.main:app --reload --host 127.0.0.1 --port 8787
```

Dashboard:

```text
http://127.0.0.1:8787/
```

## Coral Setup

```powershell
python -m sentinel.scripts.init_runtime
$env:SENTINEL_CORAL_DATA_DIR = "file:///E:/Files/Projects/SENTINEL/runtime/coral-data/"
coral source lint sentinel/sources/sentinel_findings.yaml
coral source add --file sentinel/sources/sentinel_findings.yaml
coral source test sentinel
coral sql --format json "$(Get-Content -Raw sentinel/coral/macros/vw_release_blockers.sql)"
```

## Discord Slash Command

Register `/sentinel`:

```powershell
.\.venv\Scripts\python.exe -m sentinel.scripts.register_discord_command
```

Example:

```text
/sentinel query: are we safe to release?
```

The command is role-gated using `DISCORD_SECURITY_ROLE_ID`.

## Slack Approval Convention

For SENTINEL to correlate approvals, messages in `#security-approvals` must follow:

```text
Approved: @github_username
```

Free-form messages are treated as unapproved.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt
coral source lint sentinel\sources\sentinel_findings.yaml
coral source test sentinel
```

## What's Next

- Persist richer evidence links for exact files and PR comments.
- Add GitHub Teams/Enterprise audit-log polling for full identity governance.
- Add Google Workspace Admin SDK audit ingestion for enterprise tenants.
- Add a hosted dashboard deployment profile.
- Add more provider adapters behind the same findings schema.
- Add release-note generation from Coral macro results.
