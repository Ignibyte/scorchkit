---
title: Add a versioned provider-neutral control API — notes
pipeline_id: 6eb0a4cf-5f53-40e3-b90e-587a2b5450b7
---

# Add a versioned provider-neutral control API — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001`,
  `PR-scorchkit-attribution-not-authorization-001`,
  `PR-scorchkit-store-invariants-falsification-001`,
  `PR-scorchkit-provider-consumption-validation-001`,
  `PR-scorchkit-workspace-gate-scope-001`,
  `PR-scorchkit-public-evidence-revalidation-001`,
  `PR-scorchkit-durable-canonical-parity-001`,
  `PR-scorchkit-projection-validate-canonical-001`,
  `PR-scorchkit-local-api-principal-boundary-001`,
  `PR-scorchkit-local-frontend-bind-boundary-001`,
  `PR-scorchkit-remote-request-lifecycle-001`, and
  `PR-scorchkit-bounded-validator-mutation-table-001`.
- Recon: the root already composes policy-sealed `Engine`, durable `ScanJobService`, in-memory and
  PostgreSQL `JobStore`, bounded best-effort `EventBus`, module registries, report projections, MCP
  principal binding, and storage CRUD. There is no common application service, layered run-config
  resolver, replay journal, or canonical validating read for generic finding/evidence rows.
- Boundary decision: stable wire contracts remain independent of root/CLI/MCP/storage; the root
  service owns all conversions, authorization, stores, execution, and transport composition.
- Transport decision: opt-in bearer-authenticated loopback HTTP only. No default listener and no
  non-loopback control transport before SK-056.
- Mutation decision: no no-argument or `--full` gate. Development uses `--fast`; validation and
  post-archive delivery use `--diff` only.
- Operator confirmation: the user's standing 2026-08-23 direction is to continue the next roughly
  five tickets and use mutation diffs rather than full mutation runs. That confirms this plan and
  its delivery mode without an additional pause.

## Phase 2 — Design

- Architecture: `scorchkit-control` owns provider-neutral v1 wire contracts and a pure monotonic
  resolver. Root `ControlService` owns opaque verified principals, authorization, conversions,
  execution, stores, canonical validation, reports, and a `JobStore`-backed replay journal.
  In-process, CLI, MCP, and opt-in authenticated loopback HTTP are adapters. The control HTTP host
  has no default listener and no non-loopback mode.
- File manifest: exact additions and modifications are recorded under Confirmed design in the
  active spec. The package, root service, config/CLI feature, job journal, validating storage reads,
  client adapters, four integration suites, schema fixture, and architecture/public docs are all in
  scope; UI, team identity, model analysis, triage redesign, and extension execution are not.
- Regression test plan: exact operation/schema snapshots; monotonic four-layer truth tables;
  principal/engagement/policy-before-store tests; in-memory and PostgreSQL job-event ordering;
  corrupted canonical projection matrices; real authenticated loopback HTTP/SSE bounds; CLI/MCP
  parity and no-direct-storage source contracts; fast development gate and DIFF-only validation.
- Operator confirmation: the standing direction to continue SK-049 and later tickets with DIFF-only
  mutation validation confirms this implementation design and does not authorize a broad campaign.

## Phase 3 — Implement

- Files and behavior changed:
  - Added the dependency-light `scorchkit-control` workspace package with the v1 tagged request,
    response, result, error, resource, event, cursor, module, and four-layer configuration types.
    Runtime self-description publishes the exact 22-operation inventory and 12 generated schemas;
    an external consumer fixture pins the schema versions, inventory, names, and exact generated
    schema digest.
  - Added `ControlService` as the one root application boundary over composed policy, job
    execution, project/target CRUD, validating canonical finding/evidence reads, module inventory,
    reports, configuration resolution, and bounded results. Local, MCP, and HTTP principals all
    reach the same dispatcher; identity remains attribution plus exact engagement binding.
  - Added `JournaledJobStore` and a bounded monotonic event journal. Only successful create/CAS
    commits emit, replay is page bounded, future and expired cursors are typed failures, and live
    subscribers recover broadcast lag from retained journal state.
  - Added storage readers that reconstruct normalized canonical raw finding/evidence records and
    compare every duplicated identity, content, provenance, timestamp, lifecycle, parent, scan,
    and project field. The PostgreSQL corruption matrix independently falsifies representative
    duplicated and raw fields and requires complete fail-closed reads.
  - Added inert-by-default `[control_api]` configuration and the explicit `scorchkit control-api`
    command. Its Axum adapter accepts only a loopback bind, resolves and zeroizes an
    environment-backed bearer, compares its digest in constant time, validates loopback Host,
    scrubs credentials and claimed identity, and bounds bodies, responses, concurrency, replay,
    events, and subscribers. Real-socket HTTP and SSE tests exercise the production router.
  - Routed overlapping storage CLI and MCP project, target, finding, module, and job operations
    through `ControlService`. The CLI compatibility adapter owns no PostgreSQL handle or direct
    canonical storage dependency; existing scan-specific and out-of-v1 workflows remain separate.
  - Updated workspace/config/storage/MCP/control architecture, README, security boundary, and
    changelog documentation.
- Design deviations:
  - The planned standalone `tests/control_service.rs`, `tests/control_http.rs`, and
    `tests/control_storage.rs` files were consolidated into their owning module test suites so
    private principal, journal, transport, and row-validation seams could be falsified without
    widening their visibility. `tests/control_contract.rs` remains the external package/source
    boundary suite.
  - Existing MCP legacy result envelopes were retained around service results instead of exposing
    the new control response envelope directly.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | Finding validation compared `found_at` with the latest raw timestamp instead of the durable first-observation timestamp. | High | Fixed the invariant to require `found_at == first_seen`; added corruption coverage. |
| 2 | Security | Declared evidence rows were loaded but not independently canonical-validated before comparison. | High | Routed every declared evidence row through the complete evidence validator. |
| 3 | Compatibility | Initial CLI/MCP reuse changed legacy envelopes and required an engagement for reads that historically worked without one. | High | Restored legacy renderers/envelopes and kept engagement optional for read queries. |
| 4 | Authorization | Cancellation incorrectly required a live DAST grant rather than the local-state administration grant. | High | Authorized the job target with `LocalState` and `ActiveSafe`; added a focused denial/acceptance test. |
| 5 | Bounds | The response ceiling measured only the result payload, allowing the versioned envelope to exceed the configured maximum. | High | Measure the serialized complete response and reject the complete envelope at the boundary. |
| 6 | Correctness | Finding pagination ordered by mutable `last_seen`, so rediscovery between pages could skip an unseen row. | High | Changed stable ordering to immutable `(first_seen, id)` and added a rediscovery regression test. |
| 7 | Authorization | The stable request validator allowed commands without an explicit engagement UUID. | High | Reject every command missing the exact engagement binding before dispatch. |
| 8 | Authorization | Interrupted-job recovery authorized an incomplete abstraction and then swept a newly changing candidate set. | Critical | List the exact candidates, authorize every target before mutation, and recover only those preauthorized IDs. |
| 9 | Authorization | Project deletion enumerated targets outside the delete transaction, allowing an authorization race and an unbounded allocation. | Critical | Lock the project row, stream and authorize every target in the transaction, then delete and commit; added rollback coverage. |
| 10 | Authorization | The HTTP host composition path did not independently recheck enabled and unexpired engagement state. | High | Recheck engagement eligibility while composing the authenticated host and during live event delivery. |
| 11 | Test quality | The compound configuration-limit test used individually invalid values, so it did not prove the cross-field relation. | Medium | Use individually valid limits that violate only the response/event relationship. |
| 12 | Privacy | New and legacy target projections could retain credentials, fragments, or sensitive query values and configuration errors could echo them. | Critical | Canonicalize new targets, reject secret-bearing inputs without echo, redact legacy projections, and add focused tests. |
| 13 | Integrity | Finding and evidence continuation cursors trusted duplicated timestamp fields without validating the cursor row. | High | Canonical-validate the cursor row and its parent/project relationship before deriving the continuation key. |
| 14 | Injection | MCP project deletion manually interpolated project names into JSON. | High | Build the compatibility envelope with `serde_json::json!`; test a quote-bearing name and parse the result. |
| 15 | Injection | The CLI no-findings message printed a stored project name without terminal escaping. | Medium | Apply the existing terminal escaping boundary to that branch. |
| 16 | Contract | `ControlEventKindV1` advertised `stream_reset_required`, but continuity loss is delivered as a typed SSE error and no producer emitted that event. | Medium | Removed the phantom event variant; the schema now describes only emitted event kinds. |
| 17 | Consistency | Project reports assemble bounded read-only counts across statements rather than promising a database snapshot. | Low | Accepted for v1 as an explicitly generated operational projection; every finding is still canonical-validated and all collections remain bounded. Snapshot reports can be added as a distinct later contract. |
| 18 | Reliability | Journal publication reports an error after a durable store commit if the fixed-shape event cannot fit or the sequence exhausts `u64`. | Low | Accepted with proof: configuration enforces a 4096-byte minimum, focused tests serialize every job state under that minimum, and sequence exhaustion is outside any realizable process lifetime. |
| 19 | Bounds | Job pagination operated on `JobStore::list`, which materialized up to 1,000 rows and then silently hid any durable tail. | High | Added bounded stable store-level job paging with explicit cursor failure and continuation coverage. |
| 20 | Privacy | A legacy or externally corrupted stored job target could cross the control boundary without URL redaction. | High | Apply the shared safe web projection to job and registered-target views; added a secret-bearing legacy job regression test. |
| 21 | Bounds | Recovery's inherited 1,000-row store cap could make the command silently recover only a prefix while reporting success. | High | Fetch a 1,001-row sentinel batch and fail with `limit_exceeded` before authorization or mutation when the exact candidate set is too large. |
| 22 | Privacy | `start_job` could persist a credential-shaped query value, and `resume_job` could copy one from a legacy row, even though configuration and target registration rejected the same input. | Critical | Canonicalize and enforce the secretless web-target rule before submission and require a safe canonical stored target before resume; prove denial, no echo, and no successor persistence. |
| 23 | Integrity | Inspection proposed requiring every evidence row's scan to equal the parent finding's current scan. | Info | Rejected after tracing verified manual-evidence imports: later evidence intentionally has its own scan in the same project. Retained exact parent and scan/project validation. |
| 24 | Compatibility | The MCP cancel/resume wrapper fixture still modeled cancellation as a DAST effect and seeded a noncanonical resumable target. | Medium | Grant the fixture both DAST and local-state capabilities and seed its URL in canonical form; the focused wrapper test passes. |

- Inspection closure: strict all-feature Clippy, the 27-test control suite, 9 canonical storage
  tests, PostgreSQL job continuation, 77 MCP compatibility tests, the external control contract,
  and `bash bin/gate.sh --fast` are green. The fast gate reported 14 passed, 0 failed, 8 skipped;
  mutation was explicitly skipped.

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - Strict all-feature Clippy and formatting: PASS.
  - PostgreSQL-backed control service: 27 passed; canonical finding/evidence storage: 9 passed;
    PostgreSQL job-store continuation: PASS; external control contract: 3 passed; MCP compatibility:
    77 passed.
  - `DATABASE_URL=postgresql://postgres@127.0.0.1:32776/scorchkit_test bash bin/gate.sh
    --fast`: GREEN, 14 passed, 0 failed, 8 delivery-only skips; mutation explicitly skipped.
  - `bash bin/mutants.sh --inspect`: PASS; 10,426 configured mutants across 308 workspace source
    files, composition binary excluded, policy kernel included. Inspection compiled no mutant.
- Gate run and receipt: DIFF-only validation is selected and pending below. No no-argument or full
  mutation mode is authorized.
- Documented skips with reasons: the fast gate skipped coverage, mutation, strict Nextest,
  PostgreSQL integration, and CLI/MCP delivery lanes for its documented development-mode contract;
  all focused PostgreSQL and MCP suites above ran separately. Browser/rendering/asset lanes remain
  not applicable because ScorchKit has no web UI.
- The repeat DIFF gate passed gates 1-15, 20, 21, and 22, but the owner stopped its mutation lane
  after 26 outcomes (8 caught, 18 missed). The gate remained RED and the interrupted mutation output
  is retained only as incomplete discovery evidence; it is not a DIFF result, score, or receipt.
- The approved scope is all and only the original six names in `LocalControlClient::project`,
  `LocalControlClient::targets`, `LocalControlClient::findings`, `append_bounded` (two boundary
  substitutions), and `run_control_api`. Focused tests now observe nonempty project/target/finding
  results, the exact 10,000-item compatibility boundary and one-item overflow, and listener
  preflight-error propagation.
- A fresh exact-name pre-repair baseline selected exactly six and reproduced six misses. The sealed
  current-tree exact recheck selected the same six and caught all six: 100% viable MSI, zero misses,
  zero timeouts, and zero unviable outcomes. No other mutation selection ran after the repair.
- `bash bin/focused-mutation-evidence.sh --verify
  .git/scorchkit-mutants-focused-ticket-027`: PASS; 6/6 viable caught, 100% MSI, mutation-input hash
  `3bcba73889c5c5b55a43ffc01b20f2656b5fee6e188bbcd0ac1db75e0d07c9f3`, evidence digest
  `2c4ffaa166c53f72726bd741a77efcee77c0d327057775a1a071fa0e339bb396`.
- The explicit TICKET-027 §19 amendment and ticket/spec metadata bind the owner's direction to stop
  repeat mutation testing, repair only the original six, and move to SK-050. Validation and delivery
  therefore use `bash bin/gate.sh --focused-repair`, whose mutation lane verifies the sealed evidence
  without launching cargo-mutants.
- Gate run and receipt: pre-completion
  `DATABASE_URL=postgresql://postgres@127.0.0.1:32776/scorchkit_test bash bin/gate.sh
  --focused-repair` was GREEN: 19 passed, 0 failed, and 3 named web-only skips. Coverage was 84.40%;
  Nextest passed 2,001 cases with 10 reasoned live-tool/network skips; PostgreSQL and CLI/MCP lanes
  passed. Gate 16 verified the sealed 6/6 outcome at 100% MSI and launched no cargo-mutants. The
  focused-repair delivery receipt matched the exact pre-completion worktree and evidence digest.

## Phase 5 — Complete

- Docs updated: README control API use, SECURITY boundary, control/config/storage/MCP/workspace
  architecture, CHANGELOG SK-049 entry, ROADMAP completion/next-ticket state, external contract
  fixtures, and the explicit TICKET-027 focused-repair amendment.
- AAR submitted: `AAR-027-control-api`, effectiveness 4/5, with four failure patterns and four
  prevention rules registered in the knowledge index.
- Archive: TICKET-027 closes on 2026-08-23 and the spec/notes move to the completed pipeline store.
  Delivery reruns the same FOCUSED-REPAIR gate because archival invalidates the validation receipt;
  its mutation lane only verifies the sealed six-survivor evidence.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first fast gate failed default-feature clippy. | Storage-only imports and helpers in the shared service were compiled without `storage`. | Applied exact `cfg(feature = "storage")` boundaries and reran the default/all-feature focused checks. | Keep every optional-adapter symbol inside the same feature boundary as its call sites. |
| 2 | The first fast gate flagged a test bearer as a hardcoded secret. | The otherwise fake fixture used a credential-shaped literal. | Generate the minimum-length token inside the test helper. | Generate credential fixtures structurally so secret scanners remain useful and noise-free. |
| 3 | The initial CLI source contract rejected the adapter. | The adapter accepted `PgPool` solely to compose its own service, technically giving the client a storage handle. | Moved service composition to the CLI runner and pass an already-built `ControlService` into the adapter. | Compose infrastructure at the host boundary; application clients receive only the service they invoke. |
| 4 | The post-inspection fast gate failed one MCP cancel/resume wrapper test. | Its policy fixture omitted the new local-state cancellation grant and its directly seeded resumable URL was not canonical. | Corrected both fixture invariants and reran the focused test. | Shared wrapper fixtures must declare the union of command capabilities and seed canonical durable inputs. |
| 5 | The release-upgrade test failed under the first disposable database fixture. | Host PostgreSQL 17 dump tools emitted a setting unsupported by the PostgreSQL 16 test server. | Replaced only the disposable container with the already-installed PostgreSQL 17 image and reran the focused rehearsal plus fast gate. | Match disposable database major versions to host dump/restore tools for release rehearsals. |
| 6 | The first focused adapter command reported success but executed zero tests. | `cargo test --exact` received an unqualified test name. | Reran with the fully qualified library path and checked the explicit `running 1 test` count. | Treat a green filtered command as evidence only when its executed count is nonzero and expected. |
| 7 | The first six-name recheck baseline failed the CLI architecture contract before executing mutants. | Database setup code was placed inline in `control_adapter.rs`, whose source contract forbids direct storage dependencies even in tests. | Moved the fixture to the existing CLI parent test module and retained only a test-only forwarding seam in the adapter. | Keep mechanically neutral adapter files free of infrastructure references; place white-box fixture composition outside the protected source file. |
