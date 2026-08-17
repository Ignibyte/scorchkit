# Codex plugin

ScorchKit ships a Codex-first plugin at `plugins/scorchkit`. The package contains five focused
skills and a local stdio MCP descriptor. It does not change the engine's authorization model and is
usable by another MCP-capable host that follows the same tool contracts.

## Package boundary

The plugin starts an installed `scorchkit` binary with the `serve` argument. It does not embed a
binary, target, engagement, database URL, token, or credential. ScorchKit loads `scorchkit.toml` or
`config.toml` from the host workspace through its normal discovery order. Missing engagement policy
causes every effectful operation to fail closed.

`DATABASE_URL` is the only variable named for inheritance by the package. Without it, stateless scan
jobs work for the lifetime of the MCP server process. Projects, targets, findings, schedules, and
resources require PostgreSQL.

The repository provides plugin source, not a marketplace installation. A marketplace owner can
reference `plugins/scorchkit` as a trusted local source. The repository does not modify personal
Codex configuration or store a marketplace entry.

## Skills

| Skill | Responsibility | Effect boundary |
|---|---|---|
| `prepare-security-engagement` | Select or create project and target inventory | No reconnaissance or scan |
| `plan-security-engagement` | Gather authorized recon, validate modules, and return a reviewable plan | Stops before planned scan execution |
| `run-security-engagement` | Execute an approved persisted scan or stateless durable job | Requires exact user direction and engine authorization |
| `report-security-findings` | Read evidence, posture, correlation, and optional AI interpretation | Read-only; never changes finding status |
| `verify-security-remediation` | Run one focused follow-up project scan and compare finding evidence | Marks verified only after comparable evidence supports it |

Every operational skill uses ScorchKit MCP tools and resources directly. If the MCP server is not
available, the skill stops and reports the setup problem. It does not fall back to a terminal-driven
scan. A project, registered target, prompt, plan, or prior job remains context rather than
authorization; the configured engine engagement is authoritative.

## Planning and persisted scans

`plan_scan` returns validated module recommendations. `project_scan` accepts optional `modules` and
`skip` selectors in addition to the authorized profile, so Codex can persist the approved plan
without broadening it. Stateless work uses `scan_job_start` and `scan_job_status`; cancellation and
resume require user direction and retain attempt identities.

The current server exposes generated JSON Schemas for tool input and returns JSON content through
MCP text blocks. Native MCP `structuredContent`, tool annotations, read/state/effect grouping, and
principal context are intentionally deferred to SK-032.

## Validation

`bash bin/codex-plugin-contract.sh --selftest` verifies the package manifest, stdio descriptor,
five-skill inventory, phase ownership, safety language, and absence of raw command workflows. The
canonical quality gate runs the same repository-owned check. Development also validates the package
and each skill with Codex's plugin and skill validators.

Automated execution evidence uses only authorized loopback targets. ScorchKit does not ship remote
MCP transport, and the plugin must not be wrapped in an unauthenticated remote bridge.
