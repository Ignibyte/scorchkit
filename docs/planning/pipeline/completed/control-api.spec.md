---
title: Add a versioned provider-neutral control API
pipeline_id: 6eb0a4cf-5f53-40e3-b90e-587a2b5450b7
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-027
ticket_doc: docs/planning/tickets/closed/TICKET-027-control-api.md
aar: docs/planning/knowledge/aar/AAR-027-control-api.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-027
created: 2026-08-23
---

# Add a versioned provider-neutral control API — spec

## Intent

Ship the stable local-first application-service contract that every later platform client and
extension can consume without learning CLI output, MCP routing, root Rust internals, or database
tables. The contract describes itself, resolves bounded run configuration monotonically toward the
active engagement, routes effects through existing policy-sealed execution, verifies durable
canonical data on read, and offers bounded ordered job events through in-process and authenticated
loopback adapters.

## Scope

- In: package-owned v1 wire types and JSON schemas; self-description; typed four-layer run
  configuration; principal and engagement projections; project/target, job, finding/evidence,
  module, report, and event commands/queries; one root service; a journaled job-store decorator;
  canonical PostgreSQL reads; in-process adapter; opt-in authenticated loopback HTTP and event
  replay; representative CLI/MCP adaptation; public docs and compatibility fixtures.
- Out: browser or console UI; public listener; multi-user/tenant/RBAC; OAuth/OIDC/direct TLS;
  multiple remotely selectable engagements; client storage handles; model analysis; triage state
  redesign; extension runtime; general network/cloud posture; new scanner effect classes.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a client requests self-description, ScorchKit shall return versioned configuration, command, query, event, module, capability, result, and error schemas without requiring inspection of internal tables or Rust types. | Exact schema snapshots, compatibility fixtures, and an external package consumer test. |
| REQ-002 | When configuration is resolved for a run, ScorchKit shall produce one effective configuration and ordered decision log from safe defaults, organization, project, and run layers, and each later layer shall only retain or narrow targets, capabilities, effects, modules, time, concurrency, and output budgets. | Four-layer precedence, omission, exact-boundary, and widening-denial matrices. |
| REQ-003 | When a command can cause local-state or external effects, ScorchKit shall bind a transport-established principal to the exact enabled, unexpired engagement and complete policy authorization before storage mutation, network-client, filesystem traversal, credential resolution, or process construction. | In-process and HTTP success tests plus missing principal, spoofed metadata, missing/mismatched engagement, target, capability, and effect denial tests at the production service boundary. |
| REQ-004 | When a job is created or changes state or durable progress, ScorchKit shall expose a bounded, monotonically sequenced `scorchkit.control.event/v1` stream with replay, explicit expired-cursor failure, cancellation, recovery, lineage, and terminal-state parity. | Journal/store wrapper contract, event ordering/replay/overflow/reconnect tests, and existing lifecycle regression suite. |
| REQ-005 | When durable findings or evidence cross the API, ScorchKit shall deserialize and normalize the canonical raw record, compare every duplicated identity, schema, provenance, time, parent, and projection field, and fail closed on mismatch. | Fresh-schema PostgreSQL round trips and independently corrupted raw/duplicated projection tests. |
| REQ-006 | When a local HTTP API transport starts, ScorchKit shall require an environment-backed bearer credential, bind only loopback, authenticate before routing, remove credentials before downstream handling, and ignore client-supplied identity metadata for authority. | Startup matrix, constant-time credential match, header scrubbing, spoofing, loopback, and live HTTP contract tests. |
| REQ-007 | When no control transport is explicitly selected, ScorchKit shall open no listener; when any non-loopback or unsupported remote control listener is configured, startup shall fail closed and direct the operator to the existing authenticated MCP profile until team identity and isolation exist. | Default/no-listener and bind-address matrix tests plus configuration documentation. |
| REQ-008 | When CLI, MCP, library, or HTTP clients perform an overlapping control operation, they shall adapt the same application-service command or query and shall never receive a direct canonical storage handle. | Architecture/source contract plus representative CLI/MCP/service parity tests. |
| REQ-009 | When a request, page, result, event, or subscriber reaches a configured bound, ScorchKit shall reject or truncate only at the documented deterministic boundary with a typed versioned error or continuation cursor and shall not allocate an unbounded body, collection, or channel. | Body, page, result, event-journal, subscriber, and serialized-response boundary tests. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Own stable control DTOs and schemas in a new lower package; own composed service and adapters in the root package. | Keeps provider-neutral contracts reusable without reversing workspace dependencies. |
| 2 | Treat the configured engagement as immutable authority and every config layer as a restriction over explicit run inputs. | A generic config merge cannot safely prove arbitrary scope-rule containment. |
| 3 | Authenticate local HTTP with an environment-backed bearer on loopback; reject non-loopback. | Loopback alone is not identity, and SK-056 owns future team isolation. |
| 4 | Decorate `JobStore` for event sequencing and replay. | Durable create/CAS commits are the authoritative job-change seam; best-effort scan broadcast is not replay evidence. |
| 5 | Reconstruct canonical finding/evidence records from raw JSON and compare duplicated columns before returning them. | The API boundary must not bless corrupted projections. |
| 6 | Keep commands and queries bounded, page-oriented, and versioned from v1. | Later frontends must not depend on unbounded collection behavior. |
| 7 | Use fast checks during implementation and the sealed six-survivor FOCUSED-REPAIR gate for validation/delivery. | The operator explicitly stopped repeat mutation testing and approved only the original six-survivor repair before SK-050. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-027-control-api.md`
- AAR: `docs/planning/knowledge/aar/AAR-027-control-api.md`
- Intake: `docs/planning/intake/INTAKE-control-api.md`
- Architecture: `docs/architecture/workspace.md`, `docs/architecture/jobs.md`,
  `docs/architecture/storage.md`, `docs/architecture/mcp.md`, `docs/architecture/config.md`

## Confirmed design

### Dependency and ownership boundary

Add `scorchkit-control` as a leaf package with no dependency on the root composition, CLI, MCP,
storage, executor, config, policy, or agent packages. It owns serializable v1 request, response,
error, resource, configuration, event, cursor, operation-description, and JSON Schema types plus the
pure monotonic configuration resolver. The root package re-exports those identities and owns every
conversion to or from `AppConfig`, `Engagement`, `ScanJob`, registry descriptors, reports, and
PostgreSQL rows.

`ControlService` is the single root application service. A verified principal is an opaque root
type: public in-process calls can obtain only the local-process identity; MCP and HTTP adapters use
crate-private transport constructors after their own authentication. Requests carry an engagement
UUID for confused-deputy protection, but the immutable service configuration selects the actual
engagement. A matching principal and UUID grant nothing by themselves; command-specific policy
checks still run before mutations or execution.

### Request and resource boundary

One tagged `ControlRequestV1` carries a request UUID and exactly one `ControlQueryV1` or
`ControlCommandV1`. Queries cover self-description, run-configuration resolution, current
engagement, projects, targets, jobs, findings, evidence, application module descriptors, project
reports, and event replay. Commands cover project create/delete, target add/remove, DAST job
start/cancel/resume, and interrupted-job recovery. Responses use one tagged, versioned result or one
typed error with a stable code, safe message, optional retryability, and bounded structured details.

All collections use a v1 page request with an opaque stable cursor and a maximum page size of 200.
The package rejects zero/oversized limits, malformed cursors, duplicate or oversized selectors,
unknown schema versions, control characters in identifiers, and serialized response/event values
over their configured ceilings. Cursor sort keys are deterministic and never expose database
connection or credential data.

### Configuration resolution

The service first derives a maximum explicit run ceiling from the active engagement, selected
application module descriptors, and safe application defaults. The pure package resolver then
applies organization, project, and run patches in that exact order. Lists can only retain a subset;
timeouts, concurrency, result bytes, and event bytes can only stay equal or decrease. Adding a
target, capability, effect, or module, raising a budget, duplicating a value, or using an unknown
value produces a typed widening error and an ordered decision record. The service independently
normalizes and authorizes every ceiling target and selected module before invoking the resolver.
No secret-bearing `AppConfig` field enters the wire model.

### Jobs and ordered events

Wrap the configured `JobStore` in `JournaledJobStore`. After and only after a successful `create` or
compare-and-swap, the decorator publishes the committed job revision to a bounded
`ControlEventJournal`. Each event receives a process-monotonic `u64` sequence, versioned kind,
resource identity, revision, timestamp, and bounded redacted payload. The journal keeps the newest
configured window, supports deterministic replay after a cursor, rejects expired/future cursors,
and fans out through a bounded broadcast channel. Lagged HTTP subscribers recover from the journal;
if the missing sequence has expired they receive a terminal typed event and reconnect explicitly.
The underlying job store remains the lifecycle authority, so cancellation, recovery, lineage, and
terminal rules are unchanged.

### Durable canonical reads

Add validating storage read helpers rather than projecting generic `TrackedFinding` and
`FindingEvidence` rows directly. A finding read deserializes `raw_finding`, obtains its normalized
canonical v2 record, reapplies redaction, and compares identity schema/value, correlation keys,
module, severity, title, description, target, evidence, remediation, OWASP, CWE, confidence, and
the scan/project relationship. An evidence read deserializes and normalizes `raw_evidence`, then
compares schema, identity, collection time, parent finding, scan/project relationship, and the
canonical finding's declared evidence when applicable. Any malformed or divergent record fails the
complete query with `canonical_projection_mismatch`; partial corrupt results are never returned.

### Local HTTP adapter

Add `[control_api]` configuration and the opt-in `scorchkit control-api` command behind a new
`control-api` feature. Startup requires an explicit loopback `SocketAddr`, bounded request,
concurrency, response, journal, subscriber and page limits, one stable subject, the exact active
engagement UUID, and an environment-variable name containing a 32–4096 byte printable bearer.
Resolve, validate, hash, and zeroize the credential before binding. Requests authenticate in
constant time before body parsing, remove `Authorization` and any claimed principal headers, recheck
the engagement on each request, bound body read time/bytes and concurrent work, and dispatch only to
`ControlService`.

Expose authenticated `GET /v1/description`, `POST /v1/control`, and `GET /v1/events`. The event
route honors one `Last-Event-ID` or query cursor, reserves a bounded subscriber slot, replays journal
events, then continues as SSE with sequence IDs and keepalives. It rejects duplicate/malformed
credentials or cursors before service routing. No command, config section, or default opens a
listener except the explicit CLI command; every non-loopback bind is invalid. Remote/public control
hosting remains an SK-056 concern and existing authenticated remote MCP remains the supported remote
automation path.

### Existing client adaptation

`ScorchKitServer` and the storage CLI construct one shared `ControlService`. MCP job, project,
target, finding/evidence read, module-list, and report-compatible handlers translate their existing
inputs into control requests and preserve legacy text envelopes. Storage CLI job, project, target,
and finding reads invoke the same typed service and retain terminal escaping only in the CLI
renderer. Existing scan-specific CLI/MCP commands may still compose `Engine`, but no overlapping
control CRUD or lifecycle path writes canonical storage outside the service after this ticket.

### File manifest

- Add `crates/scorchkit-control/Cargo.toml` and
  `crates/scorchkit-control/src/{lib,configuration,contract,error,event,resource,schema}.rs`.
- Modify root `Cargo.toml`, `Cargo.lock`, `tests/workspace_architecture.rs`, and `src/lib.rs` for the
  package, feature, dependency direction, and compatibility re-exports.
- Add `crates/scorchkit-config/src/control_api.rs`; modify its `lib.rs` and `types.rs` for safe
  transport configuration and validation.
- Add `src/control/{mod,journal,service,transport}.rs`; modify `src/storage/findings.rs` for
  validating reads and `src/storage/mod.rs` only for exported adapter access.
- Modify `crates/scorchkit-cli/{Cargo.toml,src/lib.rs}`, `src/cli/{runner,project,finding,job}.rs`, and
  add `src/cli/control_api.rs` for explicit startup and shared-service adaptation.
- Modify `src/mcp/{contract,server,tools,resources}.rs` where required to carry verified principal
  context and delegate overlapping operations to the service without changing the 39-tool census
  or v1 MCP envelope.
- Add `tests/control_contract.rs`, `tests/control_service.rs`, `tests/control_http.rs`,
  `tests/control_storage.rs`, `tests/fixtures/control/v1-description.json`, and narrowly extend CLI,
  MCP, configuration, workspace, and source-boundary contracts.
- Add `docs/architecture/control-api.md`; update `docs/architecture/{workspace,config,mcp,storage}.md`,
  `README.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/planning/ROADMAP.md`, current ticket/spec/notes,
  AAR, and knowledge register.

### Regression plan

1. Package tests pin schema constants, exact operation inventory/order, serde round trips, schema
   snapshots, cursor validation, error projections, all list and numeric boundaries, and every
   monotonic-resolution accept/reject arm.
2. Service tests prove local and authenticated principals, request/engagement mismatch,
   disabled/expired engagement, target/capability/effect denial before a recording store mutation,
   pagination, module/report projection, and typed unavailable storage.
3. Job tests wrap both in-memory and PostgreSQL stores and prove no event on rejected/stale writes,
   exact create/CAS revision order, replay, overflow, expired/future cursors, lag recovery,
   cancellation, recovery, resume lineage, and terminal parity.
4. PostgreSQL tests create canonical rows and independently corrupt every duplicated finding and
   evidence class, asserting complete fail-closed reads and no secret-bearing projection.
5. HTTP tests use real loopback sockets and cover absent/invalid/duplicate bearer, spoofed identity,
   mismatched engagement, non-loopback startup denial, request/body/concurrency/response/subscriber
   limits, credential scrubbing, description/control calls, SSE replay and reconnect, and default
   no-listener behavior.
6. CLI/MCP tests assert representative byte-compatible results come from the service, remote MCP
   preserves its authenticated principal, and source contracts reject direct storage calls in
   adapted control handlers.
7. Run focused package/test commands and `bash bin/gate.sh --fast` during implementation. Run
   `bash bin/gate.sh --diff` in validate and again after archive; never invoke the no-argument or
   full gate.

## Phase plan

| Phase | Deliverable | Exit evidence |
|---|---|---|
| 1 Plan | ticket, AAR, spec, notes, recalled knowledge | operator confirmation |
| 2 Design | architecture, file manifest, regression plan | operator confirmation |
| 3 Implement | code per design | self-review |
| 3.5 Inspect | adversarial ledger with dispositions | lead review |
| 4 Validate | tests run and delivery gate green | matching receipt |
| 5 Complete | docs, submitted AAR, archive, closed ticket | archive complete |
| Delivery | gate rerun after archive, commit/PR | matching receipt |
