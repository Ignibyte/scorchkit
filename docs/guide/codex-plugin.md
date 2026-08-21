# Codex plugin

ScorchKit ships a Codex-first plugin at `plugins/scorchkit`. The package contains six focused skills
and a local stdio MCP descriptor. It does not change the engine's authorization model. The new
application-security workflow consumes provider-neutral MCP contracts that remain usable by another
host; Codex Security is a preferred semantic-analysis capability at the plugin layer.

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
| `run-application-security-workflow` | Coordinate commit, PR, staging, release, deep, or focused-remediation application review | Codex Security is labeled host analysis; ScorchKit MCP owns deterministic effects and evidence |
| `report-security-findings` | Read evidence, posture, correlation, and optional AI interpretation | Read-only; never changes finding status |
| `verify-security-remediation` | Run one focused follow-up project scan and compare finding evidence | Marks verified only after comparable evidence supports it |

Every operational skill uses ScorchKit MCP tools and resources directly. If the MCP server is not
available, the skill stops and reports the setup problem. It does not fall back to a terminal-driven
scan. A project, registered target, prompt, plan, or prior job remains context rather than
authorization; the configured engine engagement is authoritative.

The execution skill also understands the ordered application supply-chain routes. It checks typed
cache status before an explicit local source or artifact scan, preserves complete/incomplete/degraded
coverage, and never turns a registry, daemon, or remote image into a local target. Provider refresh
requires a separate user request and the complete digest-pinned refresh contract; it is never an
implicit preflight step.

## Planning and persisted scans

`plan_scan` returns validated module recommendations. `project_scan` accepts optional `modules` and
`skip` selectors in addition to the authorized profile, so Codex can persist the approved plan
without broadening it. Stateless work uses `scan_job_start` and `scan_job_status`; cancellation and
resume require user direction and retain attempt identities.

The server exposes generated input schemas and a shared versioned output schema. Each routed call
returns native `structuredContent` with the exact tool name, read/local-state/external-effect class,
local principal context, outcome, and result or error. Skills prefer that object and use the
unchanged text payload only when talking to an older server. Tool annotations are conservative
hints; the engine engagement remains authoritative. Client name/version are untrusted attribution,
not a grant.

The reporting workflow treats `correlate_findings.attack_paths` as the evidence-backed contract.
It may explain suspected, reachable, reproduced, mitigated, or regressed paths, but it must preserve
the returned gaps and transition conditions. `legacy_unverified_attack_chains` can supply a
compatibility hint only. Focused selections describe an exact possible follow-up and do not
authorize the plugin or Codex to execute it.

## Application-security profiles

The coordinator calls `application_context` and `plan_appsec_workflow` before execution. Commit and
pull-request semantic review is bound to one declared immutable Git change set and uses Codex
Security change review. Pull requests may add an explicitly broad fast ScorchKit root scan; staging
adds registered-target application DAST; release adds repository review, deep deterministic source
and dependency analysis, declared artifacts, and project correlation; deep adds repeated complete
repository review. Every engine step retains its independent target, capability, and exact effect
requirements.

Codex Security output remains host analysis. It cannot become ScorchKit scanner evidence, target
registration, policy authorization, or a finding transition. When a correlated focused selector is
not enforceable through the public tool contract, the skill reports the gap and stops. It never
substitutes a broad module, profile, repository, runtime, or mutation scan. See
[application-security workflow profiles](../architecture/appsec-workflows.md).

## Validation

`bash bin/codex-plugin-contract.sh --selftest` verifies the package manifest, stdio descriptor,
six-skill inventory, structured-result guidance, Codex Security scan-class mapping, focused-stop
behavior, phase ownership, safety language, and absence of raw command workflows. The
canonical quality gate runs the same repository-owned check. Development also validates the package
and each skill with Codex's plugin and skill validators.

Automated execution evidence uses only authorized loopback targets. ScorchKit does not ship remote
MCP transport, and the plugin must not be wrapped in an unauthenticated remote bridge.
