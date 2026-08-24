# MCP server

ScorchKit exposes its security engine through local stdio MCP by default and an optional
authenticated Streamable HTTP host. Codex is the preferred client, but both transports use standard
MCP types and have no vendor-specific authorization path.

The current `mcp` Cargo feature implies the storage code is compiled, but local scan operation does
not require a database. With no configured database URL, the server starts with process-local jobs;
project, schedule, finding, resource, and migration operations fail explicitly.

## Process and trust boundary

```text
local MCP host                 remote MCP client
      |                               |
  stdio transport              HTTPS reverse proxy
      |                               |
      |                    loopback authenticated HTTP guard
      |                               |
      +--------- ScorchKitServer -----+
                       |        |
              ControlService   optional PostgreSQL
                    |
              ScanJobService
                       |        |
                 policy-gated Engine
                       |
             DAST / SAST / infra / cloud executors
```

The MCP host is not an authorization authority. `ScorchKitServer` holds one immutable `AppConfig`
and one shared `ControlService`; overlapping job, project, target, finding-read, and module handlers
adapt that service. Other effectful tool handlers construct `Engine::new` from the configured
engagement. No engagement,
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
    pub(crate) transport_principal: McpTransportPrincipal,
}
```

`rmcp` generates tool dispatch and input schemas. `mcp::contract` decorates that generated router
from one exhaustive inventory before it is exposed: every route receives the shared output schema,
complete annotations, a behavior class, and version metadata. Resource and prompt handlers implement
the matching `ServerHandler` methods directly. Business logic remains in `do_*` methods so contract
adaptation cannot change policy, persistence, or scan behavior.

## Tools

The current server exposes 39 tools.

| Group | Tools |
|---|---|
| Application workflows | `application_context`, `plan_appsec_workflow` |
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

## Conversation-native workbench

The server advertises the stable `io.modelcontextprotocol/ui` extension with the single supported
MIME type `text/html;profile=mcp-app`. A client receives nested `ui.resourceUri` metadata only when
its initialization capabilities advertise that exact extension and MIME type. Negotiation never
examines client implementation name or version. The three associated read tools are:

| Tool | View |
|---|---|
| `project_status` | scan coverage, posture metrics, severity/status breakdown, trend, and unresolved findings |
| `finding_show` | canonical scanner evidence, separately labeled model analysis, triage history, and remediation |
| `correlate_findings` | canonical attack paths, evidence gaps, and separately labeled legacy unverified chains |

All three retain their complete text block and `scorchkit.mcp.tool-result/v1` structured envelope.
Headless clients receive no `ui` tool metadata and lose no data or workflow. The component validates
the schema, exact tool, success outcome, and object result before rendering. Untrusted values enter
the document only through text nodes; malformed or unsupported data produces a visible fallback.

`ui://scorchkit/conversation-workbench/v1` is a compile-time HTML/CSS/JavaScript resource. It has
empty connect, resource, frame, and base-URI domain sets; no browser permissions, external assets,
credential access, direct API client, database handle, or persistent browser storage. It branches
only on negotiated capability, host display context, and the exact result tool—not on a vendor or
client name. A finding lifecycle action sends the ordinary `tools/call` request for
`finding_update_status`; the MCP/control path repeats its existing authorization, canonical read,
append-only write, audit, and redaction rules.

Local stdio records `kind=local_process` and subject `local-mcp-process`. Remote HTTP records
`kind=authenticated_bearer` and the subject selected by the matched runtime credential binding.
Remote startup separately proves that binding names the exact configured engagement UUID. MCP
client name and version remain self-asserted and explicitly `trusted=false` on both transports; a
client calling itself an administrator gains nothing. The transport principal selects a remote
session boundary but grants no target, capability, or effect. The immutable engagement and engine
policy still decide every operation.

## Behavior classes and annotations

Composite tools take the strongest behavior they can accept:

| Class | Tools |
|---|---|
| `read` | `application_context`, `check_tools`, `correlate_findings`, `finding_show`, `list_code_modules`, `list_modules`, `plan_application_pentest`, `plan_appsec_workflow`, `project_findings`, `project_list`, `project_show`, `project_status`, `scan_job_status`, `scan_progress`, `supply_chain_cache_status`, `target_list` |
| `local_state` | `db_migrate`, `finding_update_status`, `import_application_evidence`, `project_create`, `project_delete`, `scan_job_cancel`, `schedule_scan`, `target_add`, `target_remove` |
| `external_effect` | `analyze_findings`, `application_dast`, `application_pentest`, `auto_scan`, `plan_scan`, `project_scan`, `run_due_scans`, `scan`, `scan_code`, `scan_job_resume`, `scan_job_start`, `supply_chain_cache_refresh`, `supply_chain_scan`, `target_intelligence` |

All 39 definitions set `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`.
These are conservative client hints, not enforcement. For example, a scan is marked potentially
destructive because its static schema accepts the `pentest` profile even when most calls use a safer
profile. Engine policy still evaluates the concrete request before effects.

`scan_job_start` returns after the authorized request is queued and launches its work in the server
process. Status, cancellation, and resume use the same lifecycle described in
`docs/architecture/jobs.md`. The synchronous `scan` tool remains a compatibility wrapper.

The repository-owned Codex package at `plugins/scorchkit` declares this server and six focused
workflows, including the Codex-first application-security coordinator. It stores no configuration
values and adds no authorization path. See
[the Codex plugin guide](../guide/codex-plugin.md).

## Resources

Resources provide read-only project data as `application/json` plus the optional MCP Apps resource:

| URI | Value |
|---|---|
| `scorchkit://projects` | all projects |
| `scorchkit://projects/{project_id}` | project detail |
| `scorchkit://projects/{project_id}/scans` | scan history |
| `scorchkit://projects/{project_id}/scans/{scan_id}` | one scan |
| `scorchkit://projects/{project_id}/findings` | tracked findings |
| `scorchkit://projects/{project_id}/findings/{finding_id}` | one finding |
| `ui://scorchkit/conversation-workbench/v1` | self-contained optional result workbench |

The UI resource is available without PostgreSQL; project resources retain their database
requirement. The five parameterized project forms are also advertised as resource templates. There
is no subscription or push-notification protocol.

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

`scorchkit serve --remote` starts stateful Streamable HTTP at the fixed `/mcp` path only after the
complete `[mcp.remote]` configuration passes. The supported deployment is deliberately narrow:

```text
client -- TLS --> same-host reverse proxy -- cleartext loopback --> ScorchKit
```

The backend address must be loopback. The proxy must replace `X-Forwarded-Proto` with the single
exact value `https`, preserve an allowed public Host, and forward bearer authorization. ScorchKit
checks the path, HTTPS assertion, exact Host, optional exact HTTPS Origin, body ceiling, and global
in-flight ceiling before rmcp parses the message. Body reads have a 30-second deadline, and the raw
authorization header is removed before routing. Missing Origin is valid for non-browser clients.
The public proxy must independently bound connection counts and connection, header, request, and
idle time because those phases begin before the loopback application handler.

Bindings name a stable subject, the exact configured engagement UUID, and an environment variable.
Token values are validated at startup, hashed with SHA-256, zeroized, and matched across the entire
bounded digest list in constant time. Missing, duplicate, short, malformed, mismatched, disabled, or
expired bindings fail before listening. Credential values are absent from serializable config,
`Debug`, responses, logs, and errors.

Each binding selects its own rmcp service and bounded stateful session manager. A session ID used
with another valid bearer therefore resolves as unknown. Initialization is serialized around the
session ceiling, and rejected initialization is cleaned up so malformed traffic cannot consume a
slot. Negotiated client metadata remains untrusted attribution inside that principal-owned session.

Direct TLS certificate handling, non-loopback backends, a proxy on another host, OAuth/OIDC,
multi-engagement selection, tenant isolation, RBAC, and remote queue administration are not part of
this profile. Do not expose stdio through a wrapper or broaden the cleartext listener.

## Tests and delivery evidence

`tests/mcp_tools.rs` and `mcp::remote` tests use a migrated disposable database, duplex transports,
and real loopback HTTP. They cover authenticated startup denials, TLS/Host/Origin/body/concurrency
guards, credential secrecy, session ceilings and cross-principal isolation, failed-initialization
cleanup, authenticated principal projection, authorized and denied scans, the exact 39-tool
inventory and schema snapshot, annotations, structured success
and failure, spoofed client attribution, stateless jobs over duplex MCP transport, project
membership, schedule snapshots, one-slot concurrency, N-caller at-most-once execution, finding
lifecycle, resources, and prompts. Contract unit tests decorate and reject generated routers without
a transport. Delivery gates 17–19 run a disposable loopback Node/Chrome harness for handshake,
malicious-text containment, exact lifecycle action, all three representative render shapes, narrow
and forced-high-contrast presentation, reviewed CSS digest, and forbidden source/asset patterns.
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
  server.rs        shared server state, recovery lifecycle, stdio and remote startup
  remote.rs        authenticated bounded Streamable HTTP adapter and session isolation
  tools.rs         39 tool wrappers and do_* business methods
  types.rs         compatibility re-exports
  resources.rs     URI parser, listings, templates, and JSON/UI resource reads
  conversation-workbench.html  self-contained MCP Apps component
  prompts.rs       five workflow prompts and compatibility-only unverified correlation rules
  instructions.rs  compatibility re-exports
```
