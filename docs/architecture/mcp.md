# MCP server

ScorchKit exposes its local security engine through MCP over stdio. Codex is the preferred client,
but the server uses standard MCP types and has no vendor-specific authorization path.

The current `mcp` Cargo feature implies the storage code is compiled, but local scan operation does
not require a database. With no configured database URL, the server starts with process-local jobs;
project, schedule, finding, resource, and migration operations fail explicitly.

## Process and trust boundary

```text
local MCP host
      |
  stdio transport
      |
ScorchKitServer ── optional PostgreSQL
      |                 |
ScanJobService     project storage
      |
policy-gated Engine
      |
DAST / SAST / infra / cloud executors
```

The MCP host is not an authorization authority. `ScorchKitServer` holds one immutable `AppConfig`,
and effectful tool handlers construct `Engine::new` from its configured engagement. No engagement,
target mismatch, missing capability, or insufficient effect class returns an error before the scan
resource is created.

Project target registration is inventory only. `project_scan` requires exact canonical membership in
the selected project and an independent engagement decision. `schedule_scan` stores the exact
engagement snapshot; due execution denies missing, legacy, or changed snapshots.

## Server state

```rust
pub struct ScorchKitServer {
    pub(crate) config: Arc<AppConfig>,
    pub(crate) pool: Option<PgPool>,
    pub(crate) jobs: ScanJobService,
}
```

`rmcp` generates tool dispatch and input schemas. `mcp::contract` decorates that generated router
from one exhaustive inventory before it is exposed: every route receives the shared output schema,
complete annotations, a behavior class, and version metadata. Resource and prompt handlers implement
the matching `ServerHandler` methods directly. Business logic remains in `do_*` methods so contract
adaptation cannot change policy, persistence, or scan behavior.

## Tools

The current server exposes 37 tools.

| Group | Tools |
|---|---|
| DAST | `list_modules`, `check_tools`, `scan`, `application_dast`, `plan_application_pentest`, `application_pentest`, `import_application_evidence`, `scan_job_start`, `scan_job_status`, `scan_job_cancel`, `scan_job_resume`, `plan_scan`, `auto_scan`, `target_intelligence`, `scan_progress` |
| SAST and supply chain | `list_code_modules`, `scan_code`, `supply_chain_scan`, `supply_chain_cache_status`, `supply_chain_cache_refresh` |
| Projects | `project_create`, `project_list`, `project_show`, `project_delete`, `project_scan`, `project_status` |
| Targets | `target_add`, `target_list`, `target_remove` |
| Findings | `project_findings`, `finding_show`, `finding_update_status`, `correlate_findings`, `analyze_findings` |
| Schedules | `schedule_scan`, `run_due_scans` |
| Database | `db_migrate` |

`quick`, `standard`, `thorough`, and `pentest` requests use the same profile requirements as the CLI.
Credential and exploit modules are available only through `pentest` with explicit engagement grants.
AI planning or analysis uses the configured provider and never replaces scanner evidence.

`correlate_findings` reconstructs canonical findings plus append-preserved scanner evidence in one
project-scoped read and returns `scorchkit.attack-path-correlation/v1`. Malformed durable records
and resource ceilings are typed incomplete gaps. Historical HTTP proof remains bound to the
revision recorded by that evidence. The response exposes canonical paths separately from
`legacy_unverified_attack_chains`; compatibility title/module matches never promote path state.

`application_dast` accepts the provider-neutral authenticated application-DAST request: target,
phase profile, persona IDs, and digest-pinned local OpenAPI or GraphQL schemas. The handler delegates
to `Engine::application_dast`, so MCP annotations and host intent cannot bypass scope, effects,
credential-use grants, schema authorization, or the owned ZAP execution boundary. See
[Authenticated application DAST](application-dast.md).

`plan_application_pentest` is read-only: it canonicalizes inert proposals and derives the closed
executor and exact grant inventory without target, credential, local-file, or subprocess effects.
`application_pentest` is an external-effect operation that requires the same proposals and exact
reviewed plan identity, recompiles them before any effect, and persists the complete plan plus typed
scenario outcomes. `import_application_evidence` is local-state only; it verifies, scopes, redacts,
and atomically links one digest-pinned local HAR or HTTP exchange. See
[Code-informed application pentest workflow](application-pentest.md).

`scan_code` merges the supply-chain profile selected by the same profile name. The explicit
`supply_chain_scan` route accepts only a caller-declared local target shape. Cache status reports
typed local snapshot health; cache refresh is a separate provider effect and cannot occur during a
scan. See [Application supply-chain evidence](application-supply-chain.md).

`project_scan` accepts optional `modules` and `skip` selectors after the profile is authorized. This
allows a host to persist the reviewed recommendations from `plan_scan` without silently running the
rest of the profile. Project membership and selectors still do not grant scope or effects.

## Result and caller contract

Every successfully routed tool call returns `structuredContent` using
`scorchkit.mcp.tool-result/v1`:

```json
{
  "schemaVersion": "scorchkit.mcp.tool-result/v1",
  "tool": "project_list",
  "toolClass": "read",
  "principal": {
    "kind": "local_process",
    "subject": "local-mcp-process",
    "clientAttribution": {"name": "codex", "version": "...", "trusted": false}
  },
  "outcome": "success",
  "result": []
}
```

The result field carries the tool's existing JSON value, or a string when the legacy result was not
JSON. A routed business failure uses the same envelope with `outcome=error`, a stable error code and
terminal-safe message, and MCP `isError=true`. Parameter decoding can fail before a safe routed
context exists; rmcp retains ownership of that protocol-level error.

The text content remains byte-for-byte compatible for successful calls so pre-SK-032 clients can
continue decoding the original result. New hosts should prefer `structuredContent`, verify the
schema version and tool name, and use the text block only as a compatibility fallback.

The current transport is local stdio, so the principal kind records the local process boundary.
MCP client name and version are self-asserted and explicitly `trusted=false`; they are useful for
trace attribution only. Neither the principal nor client metadata grants an engagement, target,
capability, or effect. Authenticated remote principals and principal-to-engagement binding remain
blocked on SK-044.

## Behavior classes and annotations

Composite tools take the strongest behavior they can accept:

| Class | Tools |
|---|---|
| `read` | `check_tools`, `correlate_findings`, `finding_show`, `list_code_modules`, `list_modules`, `plan_application_pentest`, `project_findings`, `project_list`, `project_show`, `project_status`, `scan_job_status`, `scan_progress`, `supply_chain_cache_status`, `target_list` |
| `local_state` | `db_migrate`, `finding_update_status`, `import_application_evidence`, `project_create`, `project_delete`, `scan_job_cancel`, `schedule_scan`, `target_add`, `target_remove` |
| `external_effect` | `analyze_findings`, `application_dast`, `application_pentest`, `auto_scan`, `plan_scan`, `project_scan`, `run_due_scans`, `scan`, `scan_code`, `scan_job_resume`, `scan_job_start`, `supply_chain_cache_refresh`, `supply_chain_scan`, `target_intelligence` |

All 37 definitions set `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`.
These are conservative client hints, not enforcement. For example, a scan is marked potentially
destructive because its static schema accepts the `pentest` profile even when most calls use a safer
profile. Engine policy still evaluates the concrete request before effects.

`scan_job_start` returns after the authorized request is queued and launches its work in the server
process. Status, cancellation, and resume use the same lifecycle described in
`docs/architecture/jobs.md`. The synchronous `scan` tool remains a compatibility wrapper.

The repository-owned Codex package at `plugins/scorchkit` declares this server and five focused MCP
workflows. It stores no configuration values and adds no authorization path. See
[the Codex plugin guide](../guide/codex-plugin.md).

## Resources

Resources provide read-only project data as `application/json`:

| URI | Value |
|---|---|
| `scorchkit://projects` | all projects |
| `scorchkit://projects/{project_id}` | project detail |
| `scorchkit://projects/{project_id}/scans` | scan history |
| `scorchkit://projects/{project_id}/scans/{scan_id}` | one scan |
| `scorchkit://projects/{project_id}/findings` | tracked findings |
| `scorchkit://projects/{project_id}/findings/{finding_id}` | one finding |

The five parameterized forms are also advertised as resource templates. There is no subscription or
push-notification protocol.

## Prompts

The server advertises five host-neutral workflow prompts:

| Prompt | Required input |
|---|---|
| `full-web-assessment` | `target` |
| `investigate-finding` | `finding_id` |
| `remediation-plan` | `project` |
| `compare-scans` | `project` |
| `executive-summary` | `project` |

Prompts tell the host which tools to call. They do not grant scope or effects.

## Local startup

For stateless local scans, start the stdio server without a database URL:

```bash
scorchkit serve
```

For persistent projects and cross-process jobs, migrate the database and start with its URL:

```bash
cargo build --release --features mcp
DATABASE_URL=postgresql://localhost/scorchkit scorchkit db migrate
DATABASE_URL=postgresql://localhost/scorchkit scorchkit serve
```

The same configuration must contain an engagement for effectful tools. A generic MCP client entry is:

```json
{
  "mcpServers": {
    "scorchkit": {
      "command": "scorchkit",
      "args": ["serve"],
      "env": {
        "DATABASE_URL": "postgresql://localhost/scorchkit"
      }
    }
  }
}
```

Keep database credentials outside committed files. Use the host's protected environment or secret
store.

## Remote transport

ScorchKit does not ship SSE, streamable HTTP, or another remote MCP transport. Do not expose stdio
through an unauthenticated network wrapper. A future remote server must:

1. authenticate the principal;
2. bind that principal to an engagement;
3. validate the listening and requested hosts;
4. define TLS termination and proxy trust;
5. preserve the same deny-before-effects behavior;
6. rate-limit, audit, and test destructive operations.

## Tests and delivery evidence

`tests/mcp_tools.rs` uses a migrated disposable database and loopback servers. It covers authorized
and denied scans, the exact 37-tool inventory and schema snapshot, annotations, structured success
and failure, spoofed client attribution, stateless jobs over duplex MCP transport, project
membership, schedule snapshots, one-slot concurrency, N-caller at-most-once execution, finding
lifecycle, resources, and prompts. Contract unit tests decorate and reject generated routers without
a transport.
Direct test commands may skip database cases
when `DATABASE_URL` is absent. Delivery gate 21 treats a missing database as failure, and gate 22
executes the CLI/MCP contract lane.

## Source layout

```text
crates/scorchkit-mcp/src/
  contract.rs      tool inventory, annotations, result envelope, and caller context types
  types.rs         deserializable, JSON-schema input types
  instructions.rs  host-neutral server instructions
src/mcp/
  contract.rs      rmcp router and structured-result adapter over package contracts
  server.rs        server state, handler implementation, stdio startup
  tools.rs         37 tool wrappers and do_* business methods
  types.rs         compatibility re-exports
  resources.rs     URI parser, listings, templates, and reads
  prompts.rs       five workflow prompts and compatibility-only unverified correlation rules
  instructions.rs  compatibility re-exports
```
