---
title: Add authenticated remote MCP — notes
pipeline_id: 73a09db1-abaa-46f3-a430-8c883f9f5f8b
---

# Add authenticated remote MCP — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-policy-before-effects-001`: transport authentication must precede listener-owned
    routing, while every target/subprocess effect remains independently engine-authorized.
  - `PR-scorchkit-attribution-not-authorization-001`: authenticated transport subject and
    self-asserted MCP client metadata need distinct typed fields and spoof tests.
  - `PR-scorchkit-local-api-principal-boundary-001`: loopback and claimed identity are not
    authentication; use an explicit credential and bind it to authority.
  - `PR-scorchkit-local-frontend-bind-boundary-001`: before tenant isolation, optional frontends
    stay loopback or OS-protected. The trusted proxy is same-host and the backend stays loopback.
  - `PR-scorchkit-compound-guard-boundaries-001`: test each configuration and request-guard clause
    independently, including exact size/session/concurrency boundaries.
  - `mcp-contract-hardening.notes.md`: retain one exhaustive tool contract and keep client metadata
    untrusted in the structured result envelope.
- Operator confirmation: the 2026-08-21 request to take and finish the next three roadmap tickets
  confirms SK-044's bounded plan and design; direct TLS, multi-tenant identity, and public backend
  listening would expand scope and remain deferred.

## Phase 2 — Design

- Architecture:
  - Configuration owns a provider-neutral remote MCP shape: loopback socket, fixed proxy TLS mode,
    exact host/origin allowlists, body/session/concurrency bounds, and principal bindings containing
    only a subject, engagement UUID, and environment-variable reference.
  - Startup validates the shape and current engagement, resolves each token into a SHA-256 digest,
    rejects duplicate digests, and builds one remote endpoint per principal. Errors may name a
    binding or environment reference but never a credential value.
  - The HTTP guard accepts only `/mcp`, one exact HTTPS forwarding assertion, an allowed Host,
    optional allowed Origin, bounded content length/body, and a matching bearer digest. A global
    semaphore bounds in-flight requests before rmcp parses the message.
  - Each authenticated binding selects its own rmcp `StreamableHttpService` and
    `LocalSessionManager`. Initialization is serialized around the session-count check; later
    requests under another valid token use a different manager and receive an unknown-session
    response.
  - A cloned `ScorchKitServer` carries the host-owned remote subject. Tool-call context combines it
    with rmcp's negotiated client name/version as untrusted attribution. The server's immutable
    engagement, jobs, webhooks, stores, tools, and engine effects remain unchanged.
  - `serve --remote` composes the same durable/stateless host state and recovery lifecycle as stdio,
    binds only after every guard is ready, and shuts recovery down with the HTTP server.
- File manifest:
  - Add `crates/scorchkit-config/src/mcp.rs`; export it and extend `AppConfig` with bounded remote
    transport and binding types plus compatibility/default tests.
  - Enable rmcp Streamable HTTP server support and add only the HTTP server/middleware dependencies
    needed by the root adapter.
  - Add `src/mcp/remote.rs`; modify `src/mcp/server.rs` for cloneable shared composition and remote
    lifecycle, and `src/mcp/contract.rs` for host-owned principal selection.
  - Modify CLI command/dispatch/serve handling for explicit `serve --remote` selection and tests.
  - Add focused remote transport integration tests and versioned principal-schema fixture updates
    without changing the 39-tool inventory.
  - Update security, MCP/config/workspace architecture, getting-started, README, changelog, roadmap,
    ticket, and AAR artifacts.
- Regression test plan:
  - Config/startup: legacy/default local configs round-trip; every empty/duplicate/oversized binding,
    malformed env name, bad socket, non-loopback address, empty/malformed host/origin, zero/over-max
    limit, absent/mismatched/disabled/expired engagement, missing/short/duplicate token, and absent
    remote block fails at the exact source before bind.
  - Request guard: wrong path; missing/multiple/wrong forwarded protocol; missing/malformed/denied
    Host; malformed/denied Origin; missing/malformed/wrong bearer; exact and over body limit;
    concurrency saturation; and secret-canary absence from response/log/debug projections.
  - Sessions: authorized initialize/tool/delete; exact session ceiling; capacity recovery after
    delete; wrong valid principal with another session ID; invalid/expired session; shutdown; and
    client attribution retention.
  - Policy/contracts: spoofed privileged client remains untrusted; remote principal is exact;
    allowed loopback scan retains normal engagement enforcement; mismatched/denied targets fail;
    cancellation/output/redaction and durable job/webhook behavior remain shared.
  - Local compatibility: stdio CLI parsing and transport tests, local principal fixture, stateless
    fallback, 39-tool inventory, resources/prompts, and durable recovery remain unchanged.

## Phase 3 — Implement

- Files and behavior changed:
  - Added provider-neutral remote MCP configuration with loopback/TLS, authority, principal,
    credential-reference, body, concurrency, and per-principal session validation in
    `scorchkit-config`; default and local-only configuration remain compatible.
  - Added an authenticated Streamable HTTP adapter that resolves environment credentials into
    zeroized startup strings and retained SHA-256 digests, scans every bounded digest during
    constant-time comparison, and rejects duplicate credentials without disclosing values.
  - Added pre-protocol path, forwarded-TLS, Host, optional Origin, bearer, current-engagement,
    concurrency, content-length, streamed-body, and 30-second body-read guards. The raw
    authorization header is removed before rmcp routing. Disabled or expired engagement state is
    rechecked at composition and for every authenticated request.
  - Added one stateful rmcp service/session manager per authenticated subject, serialized bounded
    initialization, rejected-initialization cleanup, cross-principal session isolation, and shared
    cancellation for graceful shutdown.
  - Refactored MCP server composition so stdio and remote modes share the same engine, jobs,
    webhook delivery, persistence, recovery, tool inventory, and policy boundaries. Remote
    subjects project as `authenticated_bearer`; client name/version remain untrusted attribution.
  - Added explicit `serve --remote` CLI selection while leaving bare `serve` on stdio, plus config,
    CLI, schema, request-guard, session-isolation, denied-policy, and actual loopback TCP tests.
  - Updated root dependencies, lockfile, README, SECURITY, configuration/MCP/workspace architecture,
    getting-started guide, schema fixture, and changelog.
- Design deviations:
  - None. Implementation added fail-closed cleanup for rmcp sessions allocated by rejected first
    messages, a composition-time engagement consistency check, and per-request expiry enforcement;
    these strengthen the locked lifecycle and binding decisions without expanding scope.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | correctness | rmcp could allocate a session for an invalid first message and omit the session header, allowing malformed messages to consume the principal's bounded capacity. | medium | Fixed: snapshot session IDs around serialized initialization and close every newly allocated session when the response does not establish one; regression test proves capacity remains available. |
| 2 | security | Returning after the first matching bearer digest made authentication time depend on binding order. | medium | Fixed: hash the bounded candidate once, perform `ConstantTimeEq` against every configured digest, and select only after the full scan. |
| 3 | security | Environment-resolved bearer strings lived as ordinary `String` values until allocator reuse after startup preparation. | medium | Fixed: wrap each resolved value in `Zeroizing` and retain only its SHA-256 digest; Debug/error tests prove values and digests are not projected. |
| 4 | correctness | Graceful listener shutdown did not explicitly cancel active rmcp stateful session streams. | medium | Fixed: give every endpoint a child of one host cancellation token and cancel it on both signal and server exit; actual loopback initialize/tool/delete/shutdown coverage passes. |
| 5 | data integrity | Prepared bindings could theoretically be paired with a separately composed server carrying another engagement. | high | Fixed: host composition requires every prepared UUID to equal the server's immutable engagement UUID before bind; mismatch regression test passes. |
| 6 | security | Engagement eligibility was checked only during credential preparation, leaving expiry between preparation and bind and after startup as time-of-check gaps. | high | Fixed: recheck enabled/expiry at host composition before bind and on every authenticated request; independent startup and request tests pass. |
| 7 | security | Authority validation relied on URL parse success alone and did not pin malformed ports, escaped delimiters, or backslash normalization. | medium | Fixed: reject empty ports and escaped/backslash forms, require a host-only parsed shape, and add boundary cases for invalid ports and normalized paths. |
| 8 | security | The authenticated request still carried its raw `Authorization` header into rmcp after identity selection. | medium | Fixed: remove the header immediately after successful comparison and before any await or protocol routing; remote protocol tests remain green. |
| 9 | security | A slow authenticated chunked body could retain one global request permit indefinitely. | medium | Fixed: impose a 30-second body-read deadline and test exact, over-limit, and non-terminating bodies. Public pre-header connection and idle controls are explicitly assigned to the trusted proxy in security/architecture docs. |
| 10 | simplification | The combined principal, policy, session, cleanup, and capacity test obscured individual invariants and exceeded the repository lint complexity threshold. | low | Fixed: extracted session/RPC helpers and split cleanup, policy projection, and cross-principal capacity into focused tests without suppressions. |

- Correctness critic result: no open findings after session cleanup, lifecycle, CLI, local-stdio,
  request-boundary, and actual loopback review.
- Security critic result: no open code findings; proxy-owned pre-handler connection limits are a
  documented constraint of the locked same-host trusted-proxy deployment.
- Data-integrity critic result: the authenticated subject, session manager, composed engagement,
  engine configuration, job/webhook services, and policy path remain one consistent binding.
- Simplification critic result: shared server/recovery helpers avoid duplicate transport business
  logic, validator/adapter ownership remains separated, and no suppressions or speculative layers
  were added.

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - `cargo test -p scorchkit-config`: green, 50 unit tests and doc tests.
  - `cargo test --all-features --lib mcp::remote::tests`: green, 11 focused remote transport
    tests including actual loopback HTTP.
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`: green.
  - `DATABASE_URL='postgresql:///scorchkit_codex_validation_001' bash bin/gate.sh --fast`:
    initially red on a default-feature CLI test import and root dependency ordering; both fixed at
    source, then green with 14 passed and 8 mode-defined skips.
  - First `DATABASE_URL='postgresql:///scorchkit_codex_validation_001' bash bin/gate.sh --diff`:
    17 applicable lanes passed, including 84.55% line coverage, PostgreSQL, and CLI/MCP contracts;
    mutation was red at 79.05% (117 caught, 31 missed, 13 unviable) and nextest reported the now
    stale `scorchkit-cli` zero-test entry. Survivor-guided tests and validator simplification were
    applied, then `bash bin/mutants.sh --inspect` and strict all-target Clippy passed.
- Gate run and receipt:
  - The repaired `DATABASE_URL='postgresql:///scorchkit_codex_validation_001' bash bin/gate.sh
    --diff` rerun was green: 19 passed, 0 failed, and 3 documented UI-only skips. Mutation tested
    147 variants at 100% MSI (134 caught, 0 missed, 13 unviable); strict nextest passed all 1,928
    executed tests with 10 suite-declared skips; PostgreSQL passed 100 integration tests across the
    three database suites; and CLI/MCP contracts passed. The gate wrote
    `.git/scorchkit-gate-receipt` for the exact validated worktree.
- Documented skips with reasons:
  - Browser E2E is not applicable until ScorchKit ships a web UI.
  - Website dogfood rendering is not applicable to the terminal security engine.
  - Built CSS sheets are not applicable because the repository has no web asset pipeline.

## Phase 5 — Complete

- Docs updated: README, security policy, MCP/config/workspace architecture, getting-started guide,
  changelog, roadmap, ticket, schema fixture, validation evidence, and operator contracts describe
  the same trusted-proxy, authenticated-principal, isolated-session lifecycle.
- AAR submitted: `AAR-022-authenticated-remote-mcp` on 2026-08-22 with effectiveness 5/5; four
  reusable prevention rules and five failure patterns are registered in the knowledge index.
- Archive: pending the repository-owned completion transition and post-archive exact-tree DIFF
  receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first fast gate failed default-feature Clippy and Cargo dependency ordering. | The new CLI test module imported feature-gated symbols when `mcp` was absent, and optional dependency tables were inserted out of the repository's sort order. | Gate the entire test module with `all(test, feature = "mcp")`; sort the root dependency tables while retaining existing formatting. | Run the repository feature matrix and Cargo sort check, not only all-feature Clippy, before validation. |
| 2 | The first DIFF gate reported 79.05% MSI and a stale `scorchkit-cli` zero-test allowlist entry. | Tests proved compound denials but did not independently observe serde-only defaults, unique collection ceilings, safe Debug metadata, cancellation helpers, selector/listener failure propagation, or every post-startup engagement dimension; redundant URL predicates also overlapped canonical checks. The CLI package gained its first package-local test. | Added exact omitted-default, 32/33 collection, 255/256 authority, Debug, cancellation, engagement, listener, and selector tests; simplified redundant parsed URL conditions; removed only the obsolete CLI zero-test entry. | Design bounded validators as independent mutation tables, test helper/wrapper return behavior directly, and update exact suite inventories whenever a package gains its first test. |
