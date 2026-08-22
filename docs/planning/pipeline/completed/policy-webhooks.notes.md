---
title: Restore policy-owned durable webhook delivery — notes
pipeline_id: ce4989ad-6acd-4c9c-a916-6c6821a2979d
---

# Restore policy-owned durable webhook delivery — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-policy-before-effects-001`: authorize the effect before constructing the client
    and keep enforcement in the engine-owned path.
  - `PR-scorchkit-derived-network-policy-001`: authorize hostnames and every derived address on
    direct and redirected connections.
  - `PR-scorchkit-attribution-not-authorization-001`: destination identity and event provenance do
    not grant network authority.
  - `PR-scorchkit-public-evidence-revalidation-001`: durable/public delivery evidence must be
    revalidated at its serialization and exposure boundary.
  - `PR-scorchkit-untrusted-finding-channel-redaction-001`: redact untrusted scanner-controlled
    fields before they enter another output or persistence channel.
  - `PR-scorchkit-local-api-principal-boundary-001`: do not broaden MCP administration or assume a
    local principal while restoring an application service.
  - `scan-job-lifecycle.notes.md`: use revision CAS, leases, recovery, and immutable history for
    durable work ownership.
  - `mcp-contract-hardening.notes.md`: keep serialized projections deterministic, bounded, and
    secret-safe.
- Operator confirmation: the 2026-08-21 request to take and finish the next three roadmap tickets
  confirms SK-043's plan and bounded design; no scope-expanding remote queue administration is
  inferred.

## Phase 2 — Design

- Architecture:
  - Core event publication gains a provider-neutral awaited durable-sink interface. Sink failures
    return sanitized diagnostics to the host but do not replace the scan's terminal result; the
    existing broadcast bus remains best-effort telemetry.
  - Executor-domain delivery types define immutable redacted payloads, explicit states, revision
    CAS, leases, retry scheduling, and audit events without CLI, MCP, PostgreSQL, or HTTP types.
  - A PostgreSQL adapter persists queue revisions and matching audit events atomically. Claim and
    recovery operations use the same ownership contract as durable scan jobs but remain separate
    domain tables and traits.
  - The root application service maps configured destination IDs to runtime URLs, redacts before
    calling the store, and performs due attempts through the shared policy-owned service client.
    It resolves optional authorization only after claim and policy approval, ignores response
    bodies, sanitizes failures, and computes bounded retry state.
  - Durable CLI and MCP hosts attach the sink. MCP runs periodic recovery/delivery beside job
    recovery; CLI supplies typed list, detail, and one-shot run-due operations. A webhook-enabled
    host without PostgreSQL fails startup while webhook-free scan behavior remains unchanged.
- File manifest:
  - Modify `crates/scorchkit-config/src/webhook.rs` and configuration fixtures for bounded,
    credential-indirect destination settings and validation.
  - Modify `crates/scorchkit-core/src/events.rs` and lifecycle publishers for the awaited durable
    sink outcome.
  - Add `crates/scorchkit-executor/src/webhook.rs` and export it for delivery state, store, audit,
    and in-memory contract behavior.
  - Modify policy capability definitions, documentation, and tests to add explicit
    `WebhookDelivery` classification.
  - Add `migrations/012_webhook_deliveries.sql` and `src/storage/webhooks.rs` for transactional
    PostgreSQL persistence.
  - Add `src/webhooks.rs`; modify `src/runner/job.rs`, MCP server composition, and CLI composition
    for enqueue and worker lifecycle.
  - Update command definitions, operator/architecture/configuration documentation, examples,
    changelog, and focused integration tests.
- Regression test plan:
  - Config: old URL/events fixtures remain readable; invalid IDs, schemes, userinfo, environment
    references, and all zero/out-of-range bounds fail closed; Debug remains secret-safe.
  - Domain/store: all state transitions, stale revisions, lease recovery, deterministic ordering,
    queue capacity, audit parity, and PostgreSQL rollback semantics.
  - Redaction: scanner, metadata, target, header, token, and URL canaries are absent from stored
    JSON, audits, diagnostics, CLI JSON, and MCP-visible scan outputs; oversized redacted payloads
    fail before persistence.
  - Network: allowed endpoint success plus denied loopback/private/metadata/mixed DNS, connection
    rebinding, redirected denial, redirect bound, timeout, status failure, missing auth, and
    credential non-disclosure.
  - Lifecycle: sink receives eligible events; filtering is exact; enqueue/delivery faults do not
    alter scan results; expired claims recover; retries exhaust at configured bounds; worker batch
    and queue bounds hold.
  - Hosts: webhook-free stateless behavior is unchanged; webhook-enabled durable MCP starts a
    worker; webhook-enabled non-durable composition fails; CLI list/detail/run-due output is typed
    and sanitized.

## Phase 3 — Implement

- Files and behavior changed:
  - Added bounded, backward-readable webhook destination configuration with stable non-secret IDs,
    exact event filters, environment-only authorization references, and validation for every queue,
    payload, attempt, timeout, backoff, redirect, and batch bound.
  - Added `Capability::WebhookDelivery`, a typed webhook error, and an awaited
    `DurableEventSink` path that persists job lifecycle events before best-effort broadcast without
    propagating sink failures into scan results.
  - Added provider-neutral queue records, queued/delivering/succeeded/exhausted transitions,
    revisions, recoverable leases, bounded attempts, audit events, store contract, and deterministic
    in-memory conformance store in `scorchkit-executor`.
  - Added migration 012 and `PostgresWebhookStore`; capacity checks serialize with insertion, while
    every create/CAS revision and audit event commits in one transaction.
  - Added the root `WebhookService` for pre-store structured redaction, filtering, bounds, claims,
    recovery, policy-owned delivery, runtime-only authorization, response-body avoidance,
    exponential retry, and sanitized terminal diagnostics.
  - Attached exact job engagement snapshots to webhook sinks; added stateful MCP background passes,
    stateless-host rejection, and explicit `webhook list/status/audit/run-due` CLI operations that
    keep outbound work outside foreground scan latency.
  - Updated security, architecture, workspace, configuration, getting-started, README, and changelog
    contracts; added focused in-memory, loopback, host, scan-independence, secret, and PostgreSQL
    tests.
- Design deviations:
  - Queue records also retain the exact non-secret engagement snapshot, in addition to the redacted
    payload and destination ID. Asynchronous delivery cannot safely depend on a later global
    engagement that may differ from the scan's authority; the ticket/spec were corrected.
  - Authenticated destinations require `max_redirects = 0`. This conservative rule prevents a
    runtime authorization header from crossing an origin boundary; unauthenticated destinations
    retain separately authorized redirect support.
  - The DAST job context now uses the request's stored engagement directly rather than reconstructing
    it from global config, aligning execution and later delivery with the already persisted
    authorization snapshot.
  - Fast gate: `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --fast`
    passed all 14 applicable lanes after source-level lint/test-fixture corrections.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Security | A fixed 30-second ownership lease could expire while an allowed 300-second HTTP attempt was still live, permitting concurrent duplicate delivery. | high | Fixed: every claim now leases for the destination timeout plus a five-second commit margin; focused tests pin the relationship. |
| 2 | Security | A stored payload was trusted as permanently redacted instead of being revalidated at the request-construction boundary. | high | Fixed: attempts serialize, structurally redact, parse, and reapply the current payload ceiling before constructing the request body. |
| 3 | Security | The shared service client inherited ambient proxy settings, creating an additional network effect outside the explicit endpoint policy model. | high | Fixed: policy-owned service clients disable ambient proxies; destination and DNS/redirect enforcement remain explicit. |
| 4 | Security | Runtime authorization could have followed a redirect and crossed an origin boundary. | high | Fixed: authenticated destinations are valid only with `max_redirects = 0`; unauthenticated hops retain per-hop policy checks. |
| 5 | Security | The public durable-sink seam trusted implementer-supplied error text before emitting a warning. | medium | Fixed: core now emits a constant diagnostic and never logs arbitrary sink error text. |
| 6 | Correctness | Synchronous worker passes on foreground CLI completion and before MCP stdio startup could block for `batch_size * timeout_seconds`. | high | Fixed: CLI exposes an explicit one-shot worker only, while MCP starts delivery solely in its background recovery loop after transport startup. |
| 7 | Correctness | Audit events did not retain the sanitized failure reason and response status present in terminal/retry state. | medium | Fixed: immutable audit revisions now include bounded `last_error` and status metadata, with backward-readable defaults. |
| 8 | Correctness | The in-memory conformance store used separate record and audit locks, leaving a cancellation gap that PostgreSQL did not have. | medium | Fixed: one state lock commits the record and audit together; tests retain audit parity. |
| 9 | Correctness | Claim, retry, success, and exhaustion replacement validation admitted inconsistent deadline, result, and early-terminal shapes. | high | Fixed: domain validation now pins revision overflow, lease/due ordering, success status, failure presence, attempt bounds, and immutable fields. |
| 10 | Correctness | A destination with a small `batch_size` could consume the largest batch configured by another destination. | medium | Fixed: a pass considers at most 100 due records and independently enforces every destination's claim ceiling; a two-destination regression test pins 1-versus-2 behavior. |
| 11 | Correctness | A receiver had no stable per-delivery/per-attempt keys for suppressing the unavoidable crash-after-acceptance duplicate case. | medium | Fixed: requests carry `x-scorchkit-delivery-id` and `x-scorchkit-delivery-attempt`; documentation states at-least-once semantics and receiver idempotency. |
| 12 | Test | Missing-secret, request-boundary redaction, lease-deadline, idempotency-header, immutable-failure-audit, and per-destination batch cases were not all directly exercised. | medium | Fixed: focused service and store tests cover each boundary, including absence of the environment-variable name from the sanitized error. |
| 13 | Simplicity | The initial host wiring coupled outbound delivery to foreground scan completion even though queueing already provides the required durability boundary. | medium | Fixed: foreground scans only await enqueue; explicit/background workers own network attempts. |

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 cargo test --all-features
    --test storage_integration postgres_webhook_store_enforces_capacity_cas_and_atomic_audits
    -- --exact`: passed after removing abandoned test-owned webhook fixtures.
  - `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --fast`:
    14 applicable lanes passed; eight intentionally skipped by fast mode.
  - `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --diff`:
    19 applicable lanes passed and three product-inapplicable web lanes skipped. Line coverage was
    84.39%. Mutation testing evaluated 316 mutants in 71 minutes: 276 caught, seven missed, and 33
    unviable, for 97.52% MSI against the 95% delivery floor. All 1,904 strict-nextest tests passed,
    as did PostgreSQL integration and CLI/MCP contract lanes.
- Gate run and receipt:
  - `bash bin/pipeline.sh receipt` accepted
    `.git/scorchkit-gate-receipt` for DIFF worktree digest
    `20a41f295feac9d93d7c1455fd1326f36f55352f1939bcd3ba5880117bba0d6f`.
- Documented skips with reasons:
  - Browser E2E is inapplicable until ScorchKit ships a web UI; website dogfood render and built
    CSS are inapplicable to the terminal security engine.
  - The seven residual survivors are retained in `.git/scorchkit-mutants-last`: four compound
    backoff-bound substitutions, one replacement-time equality, and two adapter ordering/page-size
    substitutions. The canonical 97.52% score is green and above the constitutional 95% floor;
    these are recorded as future mutation-table hardening rather than used to block this ticket.

## Phase 5 — Complete

- Docs updated: README, security policy, architecture, configuration, getting-started guide,
  changelog, roadmap, ticket, validation evidence, and operator contracts describe the same
  durable policy-owned webhook lifecycle and at-least-once receiver contract.
- AAR submitted: `AAR-021-policy-webhooks` on 2026-08-22 with effectiveness 5/5; four reusable
  prevention rules and three failure patterns are registered in the knowledge index.
- Archive: pending the repository-owned completion transition and post-archive exact-tree DIFF
  receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | First fast gate failed strict doc-markdown and a hardcoded-secret Semgrep fixture rule. | New crate docs omitted code formatting and the runtime-only credential test used a secret-shaped constant name/value. | Formatted the term and built a neutral authorization canary at runtime. | Keep security fixture values semantically observable without resembling deployable credentials. |
| 2 | Second and third fast gates exposed missing public `# Errors` docs, default-field reassignment, a non-const mapper, pass-by-value, and an environment mutex held across await. | New public APIs and async test scaffolding had not yet been exercised under every strict feature-state lint. | Documented errors, used direct initialization/const/borrows, and moved the environment test into a current-thread runtime inside a synchronous guarded test. | Run strict default and all-feature Clippy before the full fast-gate loop for new public modules. |
| 3 | The first normal DIFF gate reported 58.3% MSI (118 survivors of 316 testable mutants) and a stale `scorchkit-executor` entry in the exact zero-test-suite inventory. | The implementation tests proved happy paths and selected denials but did not isolate every combined validation predicate, exact boundary, state transition, adapter read, host composition branch, or public CLI projection; adding package-local executor tests also made the old nextest allowlist entry invalid. | Used the canonical survivor artifact to add exact configuration, domain state-machine, queue selection, recovery/retry, credential, payload, PostgreSQL projection, CLI dispatch, and job-host tests; removed only the now-inaccurate executor empty-suite entry. | Treat new bounded state machines and multi-clause validators as mutation tables from the first implementation pass, and update exact suite inventories whenever a formerly type-only crate gains local tests. |
| 4 | The second normal DIFF gate reached 100% MSI but the PostgreSQL webhook integration assertion failed in both strict-nextest and PostgreSQL lanes. | The test requested the first ten globally due rows and assumed an empty shared table; aborted earlier runs had retained more than ten test-owned queued fixtures, so the newly inserted row was correctly outside that batch. | Delete only stale `fixture-%` webhook rows at test setup and exercise the adapter with its documented 1,000-row read ceiling. | Shared-database integration tests must remove their own abandoned fixtures and must not infer membership from an arbitrarily smaller global page. |
| 5 | The exact repaired worktree's canonical DIFF run exposed seven residual mutation survivors while remaining green at 97.52% MSI. | Compound validator clauses, one time-equality edge, and PostgreSQL projection ordering/page-size behavior are not each isolated by a single observable test assertion. | Accepted the canonical result because all 19 applicable lanes passed and MSI exceeded the constitutional 95% floor; retained the exact survivor artifact for subsequent hardening. | Build validators and ordered bounded adapters from explicit mutation tables that independently pin every equality, logical clause, page-size, and ordering observable. |
