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

`rmcp` generates tool dispatch and input schemas. Resource and prompt handlers implement the matching
`ServerHandler` methods directly. Business logic lives in `do_*` methods so most integration tests
can exercise policy and persistence directly; one duplex-transport contract proves stateless job
operation through MCP framing.

## Tools

The current server exposes 30 tools.

| Group | Tools |
|---|---|
| DAST | `list_modules`, `check_tools`, `scan`, `scan_job_start`, `scan_job_status`, `scan_job_cancel`, `scan_job_resume`, `plan_scan`, `auto_scan`, `target_intelligence`, `scan_progress` |
| SAST | `list_code_modules`, `scan_code` |
| Projects | `project_create`, `project_list`, `project_show`, `project_delete`, `project_scan`, `project_status` |
| Targets | `target_add`, `target_list`, `target_remove` |
| Findings | `project_findings`, `finding_show`, `finding_update_status`, `correlate_findings`, `analyze_findings` |
| Schedules | `schedule_scan`, `run_due_scans` |
| Database | `db_migrate` |

`quick`, `standard`, `thorough`, and `pentest` requests use the same profile requirements as the CLI.
Credential and exploit modules are available only through `pentest` with explicit engagement grants.
AI planning or analysis uses the configured provider and never replaces scanner evidence.

Tool results are currently JSON serialized into text for compatibility. Typed MCP structured content,
read/state/effect grouping, and complete tool annotations are roadmap batch SK-032.

`scan_job_start` returns after the authorized request is queued and launches its work in the server
process. Status, cancellation, and resume use the same lifecycle described in
`docs/architecture/jobs.md`. The synchronous `scan` tool remains a compatibility wrapper.

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
and denied scans, stateless jobs over duplex MCP transport, project membership, schedule snapshots,
one-slot concurrency, N-caller at-most-once execution, finding lifecycle, resources, and prompts.
Direct test commands may skip database cases
when `DATABASE_URL` is absent. Delivery gate 21 treats a missing database as failure, and gate 22
executes the CLI/MCP contract lane.

## Source layout

```text
src/mcp/
  server.rs        server state, handler implementation, stdio startup
  tools.rs         30 tool wrappers and do_* business methods
  types.rs         deserializable, JSON-schema input types
  resources.rs     URI parser, listings, templates, and reads
  prompts.rs       five workflow prompts and correlation rules
  instructions.rs  host-neutral server instructions
```
