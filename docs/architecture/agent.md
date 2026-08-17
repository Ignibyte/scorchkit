# Agent integration

ScorchKit treats an agent as a reasoning host around a deterministic security engine. Codex is the
preferred host, but the MCP protocol, manifest, engagement policy, evidence, and repository workflow
are vendor-neutral.

## Boundary

An agent may propose targets, profiles, modules, priorities, explanations, and remediation. It cannot
grant itself scope or effects. Every effectful MCP, CLI, autonomous-runner, project, and schedule path
constructs the policy-gated `Engine` from the configured `Engagement`.

The `authorized_targets` field in `AgentConfig` is retained as a declared-target hint for host
compatibility. It is not authorization. Project target registration is also inventory, not
authorization. The engine checks the canonical target, capability, and effect class again.

## Source layout

```text
src/agent/
  config.rs   host-facing operational hints
  prompt.rs   host-neutral PTES workflow instructions
  runner.rs   local recon → plan → scan → analyze → report adapter
  mod.rs      JSON manifest generation
```

## Manifest

`generate_manifest(&AgentConfig)` returns JSON for an MCP-capable host. It names Codex as preferred,
declares stdio MCP startup, embeds the host-neutral prompt, and states that
`engine_engagement_policy` is the authorization source.

```json
{
  "host": {
    "preferred": "codex",
    "interface": "mcp",
    "vendor_lock_in": false
  },
  "mcp_server": {
    "command": "scorchkit",
    "args": ["serve"],
    "transport": "stdio"
  },
  "safety": {
    "authorization_source": "engine_engagement_policy",
    "scope_enforcement": "fail_closed",
    "exploitation": "requires_explicit_engagement_grant"
  }
}
```

The manifest does not contain the serialized engagement and does not create a grant. The server
loads that grant from `AppConfig` when it starts.

## `AgentConfig`

`AgentConfig` controls host behavior such as declared targets, maximum requested profile, project
preference, analysis preference, concurrency, delay, and database location. Its default depth is
`standard`, but a standard scan still fails unless the engine engagement grants the target,
`DastScan`, and `intrusive` effect.

```rust
use scorchkit::agent::config::AgentConfig;
use scorchkit::agent::generate_manifest;

let hints = AgentConfig::new(vec!["owned.example".to_string()])
    .with_depth("quick")
    .with_project("authorized-assessment");
let manifest = generate_manifest(&hints);
```

## Local autonomous adapter

`agent::runner::run_autonomous` is an in-process convenience path. It runs quick reconnaissance,
optional provider planning, the authorized profile, optional analysis, reporting, and optional
project persistence. It uses the same engine and provider configuration as the CLI. AI failure is
non-fatal and falls back to the selected deterministic profile. Provider planning and analysis use
the versioned `scorchkit.ai/v1` task contract. Agent prompts cannot bypass that typed boundary.

## MCP transport

The supported transport is local stdio. ScorchKit does not ship remote MCP transport. A future remote
transport must bind an authenticated principal to an engagement and define host validation and TLS
termination before it can execute scans.

## Codex plugin

`plugins/scorchkit` is the preferred host package. Its standard plugin manifest points to the local
stdio MCP server and bundles five phase-specific skills for preparation, planning, execution,
reporting, and remediation verification. The skills call MCP tools directly and stop when that
interface is unavailable; they do not teach Codex a second command-driven execution path.

The package contains no engagement or credential values and does not create a marketplace entry.
Its `DATABASE_URL` declaration is a named environment pass-through, not a stored value. Runtime
configuration and authorization still come from `AppConfig`. The package is therefore an adapter
over the host-neutral MCP boundary, not a dependency of `engine`, `runner`, `storage`, or `ai`.

The plugin consumes generated MCP input schemas and prefers the versioned native structured result
envelope. The server retains the legacy text payload for older hosts. Every tool advertises a
read/local-state/external-effect class and complete conservative annotations. Local process
principal data and self-asserted client attribution are returned for traceability but never grant
authorization; remote authenticated binding remains SK-037.
See [the Codex plugin guide](../guide/codex-plugin.md) for the operator-facing workflow.

## Development host

Codex discovers `.agents/skills/scorchkit-pipeline/SKILL.md` for repository changes. That skill is a
thin adapter to `bin/pipeline.sh`; it does not own phase state. Claude and other agents follow
`AGENTS.md`, `CONSTITUTION.md`, `SECURITY.md`, and the same scripts.
