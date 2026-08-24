---
title: Conversation-native application-security workbench — notes
pipeline_id: 4f250516-2ed5-45b7-885d-e45adfd2ce20
---

# Conversation-native application-security workbench — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-host-workflow-tool-contract-001`: keep every host-facing claim bound to an
    advertised MCP schema, immediate result, and executing transport test.
  - `PR-scorchkit-attribution-not-authorization-001`: UI and client metadata remain untrusted
    attribution; the component cannot create or select an engagement grant.
  - `PR-scorchkit-durable-canonical-parity-001` and
    `PR-scorchkit-projection-validate-canonical-001`: public views consume the existing validated
    control/MCP projections and do not read duplicated storage columns or raw children directly.
  - `PR-scorchkit-local-frontend-bind-boundary-001`: a local frontend cannot broaden the current
    transport boundary; this ticket adds an MCP resource, not a listener.
  - `AAR-020-post-release-platform-roadmap`: the component must be optional, capability-driven,
    provider neutral, and must replace gates 17–19 with executable evidence when it ships.
  - `AAR-006-mcp-contract-hardening`: preserve exact legacy text while extending standard metadata
    and keep one exhaustive tool contract inventory.
  - `AAR-027-control-api` and `AAR-031-finding-triage`: canonical reads fail closed and mutations
    return through `ControlService`; frontend code receives no database handle.
  - Official MCP Apps 2026-01-26 standard plus locked `rmcp` 1.8: nested `ui.resourceUri`,
    `ui://`, `text/html;profile=mcp-app`, extension capability negotiation, restrictive CSP, and
    ordinary proxied `tools/call` are available without a new Rust dependency.
  - Active bulletins: none.
- Recon:
  - `project_status`, `finding_show`, and `correlate_findings` already return the canonical data
    needed for the requested views through `scorchkit.mcp.tool-result/v1`.
  - `RawResource`, `ResourceContents`, tool metadata, and server extension capabilities in the
    locked SDK all carry the standard fields directly.
  - `/usr/bin/google-chrome` and Node 22 are available for a local loopback browser harness; no
    external target, package download, or remote resource is needed.
- Operator confirmation: the owner's standing overnight direction to complete the next roughly
  five roadmap tickets confirms plan/design transitions and local commits. It does not authorize a
  push, public target, live provider/model, FULL mutation gate, external UI origin, or new remote
  listener.

## Phase 2 — Design

- Architecture:
  - `scorchkit-mcp::contract` owns the provider-neutral UI constants and the exact three-tool view
    mapping. The existing metadata builder adds nested `ui.resourceUri` and `visibility` only for
    mapped tools; the `scorchkit` behavior metadata remains unchanged.
  - The MCP server advertises `io.modelcontextprotocol/ui` with the one supported MIME type.
    `tools/list` inspects the peer's negotiated extension capabilities and removes UI metadata when
    the MIME was not offered. It never examines client name/version. Tool execution and result
    adaptation remain identical in both branches.
  - `resources.rs` exposes one fixed `ui://scorchkit/conversation-workbench/v1` resource even when
    PostgreSQL is absent. The content is a compile-time self-contained HTML5 document with nested
    UI metadata, empty CSP domain sets, no permissions, and a visible-border preference. Existing
    `scorchkit://` resources retain their current database requirements.
  - The vanilla component performs the standard `ui/initialize` handshake, accepts only messages
    from its parent, validates the existing tool-result envelope/schema/tool/outcome, and renders
    data exclusively with `textContent` and DOM constructors. It renders posture/scan summary,
    finding/scanner-evidence/model-analysis/triage, or canonical attack paths/gaps according to the
    routed tool name. Unsupported or malformed data produces an explicit safe fallback.
  - A finding action issues `tools/call` for the existing `finding_update_status` tool. The view
    owns no bearer, engagement, grant, URL, database handle, storage state, or audit shortcut; the
    host may require consent and the server repeats its normal control authorization.
  - Delivery gates 17–19 invoke a local Node/Chrome harness. Gate 17 proves handshake, result,
    keyboard/action request, and malicious-text containment; gate 18 renders all three canonical
    fixtures and accessibility/responsive states; gate 19 verifies the reviewed inline CSS digest
    and forbidden external-asset/source patterns. No network outside an ephemeral loopback server
    is used.
- File manifest:
  - `crates/scorchkit-mcp/src/contract.rs`, `crates/scorchkit-mcp/src/lib.rs`: UI constants, view
    mapping, and standard metadata.
  - `src/mcp/contract.rs`, `src/mcp/server.rs`, `src/mcp/resources.rs`: negotiated tool listing,
    extension capability, resource registration/read, and contract tests.
  - `src/mcp/conversation-workbench.html`: self-contained accessible component.
  - `tests/conversation_workbench_ui.mjs` and
    `tests/fixtures/mcp/conversation-workbench.css.sha256`: local browser/render/security and asset
    drift proof.
  - `tests/mcp_tools.rs`, `tests/quality_gate_contract.rs`, `bin/gate.sh`: transport, headless/UI
    capability, executable gates 17–19, and stable gate-contract coverage.
  - `README.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/architecture/mcp.md`,
    `docs/architecture/control-api.md`, `docs/planning/ROADMAP.md`, knowledge/AAR/ticket/pipeline
    artifacts: shipped boundary and evidence.
  - No dependency, migration, storage schema, scanner, model adapter, control command, listener, or
    release workflow change is planned.
- Regression test plan:
  - Pure contract tests pin the exact three-tool mapping, nested metadata, unchanged behavior
    metadata, and no UI metadata on all other tools.
  - Server tests pin extension settings and negotiated/non-negotiated `tools/list` output by
    capability rather than client identity.
  - Resource tests prove database-free list/read, exact URI/MIME/content/meta/size bounds, empty
    external CSP sets, no permissions/domain, valid document shell, and unchanged JSON resources.
  - Duplex tests prove the same selected tool compatibility text and
    `scorchkit.mcp.tool-result/v1` structured value for headless and UI-capable clients.
  - Browser tests cover the three representative result shapes, malicious text, semantic labels,
    status announcements, narrow/high-contrast/reduced-motion context, and the exact ordinary
    `finding_update_status` call request.
  - Existing spoofed-client/unauthorized no-write control tests remain required; source contracts
    forbid direct fetch/XHR/WebSocket/storage/cookie/HTML injection and vendor-name branches.
  - Development uses focused tests and `bash bin/gate.sh --fast`; validation and post-archive
    delivery use the ordinary authenticated `bash bin/gate.sh --diff`. The no-argument FULL gate is
    out of scope; if DIFF exposes survivors, only their exact names are repaired and rechecked.
- Operator confirmation: the owner's overnight multi-ticket direction confirms this design and
  local delivery. It does not authorize push/PR, public targets, live provider calls, remote UI
  origins, a new listener, or a FULL mutation campaign.

## Phase 3 — Implement

- Files and behavior changed:
  - `scorchkit-mcp::contract` now owns the standard extension/MIME/resource constants, exact
    three-tool view mapping, and nested UI tool metadata without changing the serialized 39-tool
    contract fixture.
  - The composed MCP server advertises the extension and makes `tools/list` capability-aware. Only
    clients that advertise the exact supported MIME receive UI metadata; the headless branch keeps
    all ScorchKit metadata, annotations, schemas, tool execution, text, and structured results.
  - `resources.rs` lists and reads one bounded, database-free UI resource with empty external CSP
    domain sets, no permissions, and checked size metadata. Existing project resources and their
    database requirement remain unchanged.
  - `conversation-workbench.html` performs the standard initialize/initialized handshake, accepts
    only parent messages, validates the v1 tool envelope, renders three semantically distinct views
    with DOM text construction, and routes finding lifecycle changes through `tools/call` for the
    existing `finding_update_status` tool.
  - The dependency-free Node/Chrome harness proves the handshake, inert hostile text, exact action,
    narrow/high-contrast representative renders, reviewed CSS digest, responsive/reduced-motion/
    forced-color rules, CSP, and forbidden asset/network/storage/markup sinks. Gates 17–19 execute
    those checks in delivery modes and retain named fast/static-prerequisite skips.
  - README, security, changelog, MCP/control architecture, roadmap, Constitution, and gate-contract
    documentation now describe the shipped optional surface and its unchanged authority boundary.
- Design deviations:
  - None in product scope or architecture. The browser harness uses asynchronous process spawning
    rather than the initially sketched synchronous spawn because its loopback server must keep the
    Node event loop available while Chrome loads fixtures.
- Development evidence:
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS.
  - Focused MCP package, resource, capability, duplex transport, quality-gate, browser interaction,
    representative render, and CSS/source policy tests: PASS.
  - `bash bin/gate.sh --fast`: 14 pass, 0 fail, 8 named fast-mode skips.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness and data contract | The first posture fixture used plausible but noncanonical summary fields, and model analysis was read beside rather than inside `raw_finding.appsec`; real values could render blank while the fixture passed. | Medium | Fixed the renderer and all fixtures to the exact public DTO paths, expanded the posture assertions, and added a Rust source-contract regression test. |
| 2 | Robustness and bounds | UI resource size metadata initially converted the embedded byte length through a panic/sentinel-shaped path. | Low | Replaced it with a checked `Option<u32>` conversion and pinned the bounded metadata in resource tests. |
| 3 | Security and authority | No reportable issue: messages are accepted only from the parent, dynamic values use DOM text construction, CSP/domain/permission sets are restrictive, and the component owns no grant, credential, listener, persistence, or direct network client. | Informational | Retained the design; browser and source-policy tests cover hostile text, external effects, storage, and injection sinks. |
| 4 | Simplification and compatibility | No reportable issue: one embedded resource, one exact mapping, and one capability helper are sufficient; no dependency, migration, new result schema, vendor branch, or duplicate control path was introduced. | Informational | Retained the design and unchanged 39-tool/text/structured-result fixtures. |
| 5 | Verification harness | A synchronous Chrome child blocked the Node event loop that also served its loopback fixtures, so the first browser run timed out. | Low | Switched the harness to asynchronous child spawning; repeated browser and render runs complete deterministically. |

## Phase 4 — Validate

- Tests run (commands and outcomes): focused MCP package/resource/capability/duplex tests, strict
  all-target/all-feature Clippy, exact canonical-projection source tests, browser interaction,
  representative render, CSS/source policy, gate-contract, and fast-gate development checks all
  passed before delivery validation. The first authenticated DIFF attempt exposed that the local
  `cpeppers` PostgreSQL test role lacked `CREATEDB`; mutation and every later delivery lane were
  correctly skipped after the static prerequisite failed. After restoring that test-role
  permission, the exact release upgrade/failure/restore test passed in isolation.
- Gate run and receipt: the one completed
  `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --diff` passed all 22
  lanes with zero failures or skips and wrote `.git/scorchkit-gate-receipt` for worktree hash
  `1c5394e205693f02553483966352dc7388b7997b49fc9d8b8816cba9540fb1e5`. It recorded 85.62% line
  coverage, passed 2,196 strict Nextest cases with 10 reasoned skips, and passed authenticated
  PostgreSQL plus CLI/MCP contracts. Gates 17–19 executed and passed browser interaction,
  representative rendering, and CSS/source asset policy.
- Mutation evidence: DIFF selected 25 mutants and completed in one inventory with 20 caught, zero
  missed, five unviable, and 100% viable MSI at the unchanged 95% floor. There were no survivors
  and no focused or broad follow-up run. The only mutation-blind changed Rust files are the two
  integration/static-contract test files, `tests/mcp_tools.rs` and
  `tests/quality_gate_contract.rs`; production paths have direct mutation evidence. Per the
  owner's direction to stop repeat broad scans, the raw zero-survivor inventory is sealed at
  `.git/scorchkit-mutants-focused-ticket-032`. The verifier reconstructs 20/20 viable caught,
  zero misses, 100% MSI, mutation-input hash
  `e115b5cc5e64ceb9c1ec8f8c4c0c40608deb973815cde090b71310bb7c2d8727`, and evidence digest
  `f31db49ed364b2e8875997dbc180459fb0f029175eca09f7000670e97aad37d1`. Pre-completion and
  post-archive delivery use `--focused-repair` only while that input hash remains unchanged, and
  gate 16 verifies the evidence without launching cargo-mutants.
- Documented skips with reasons: the completed delivery gate skipped no lane. Ten existing
  live-tool/network cases remain reasoned Nextest skips; no remote/public target, live model or
  service, external UI origin, FULL gate, or second broad mutation run was authorized or used.
- Pre-completion receipt: authenticated `bash bin/gate.sh --focused-repair` passed all 22 lanes with
  zero failures or skips, repeated 85.62% coverage and 2,196 strict cases, and passed browser,
  render, CSS, PostgreSQL, and CLI/MCP contracts. Gate 16 verified the sealed input hash and
  evidence digest without launching cargo-mutants; the receipt is bound to that evidence and the
  exact pre-completion worktree.

## Phase 5 — Complete

- Docs updated: README, SECURITY, changelog, MCP/control architecture, Constitution delivery-gate
  contract, roadmap status/evidence/backlog, intake/ticket/index, knowledge register/AAR, and the
  pipeline spec/notes describe the standard optional workbench, unchanged authority boundary,
  exact UI evidence, and zero-survivor delivery scope.
- AAR submitted: `docs/planning/knowledge/aar/AAR-032-conversation-workbench.md` on 2026-08-24 with
  effectiveness 4/5 and two new reusable failure/prevention pairs.
- Archive: `bash bin/pipeline.sh pass complete` will close TICKET-032, remove it from the open
  queue, archive this spec/notes pair, and rewrite active/open cross-links. Authenticated
  post-archive delivery will rerun `bash bin/gate.sh --focused-repair`; gate 16 will verify the same
  sealed zero-survivor evidence without launching cargo-mutants before the local commit.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Canonical posture and nested model-analysis values could render blank. | The browser fixture was hand-shaped from field concepts instead of the exact serialized producer DTO. | Corrected every consumed path and added source-contract plus browser assertions. | `PR-scorchkit-ui-fixture-canonical-shape-001` |
| 2 | The initial local browser check timed out. | Synchronous child execution starved the in-process loopback server. | Use asynchronous spawn and await exit while Node services requests. | `PR-scorchkit-loopback-harness-nonblocking-driver-001` |
| 3 | The first DIFF attempt stopped in the all-feature lane. | The local validation role could connect and migrate but lacked the `CREATEDB` privilege required by the release-recovery fixture. | Restored `CREATEDB`, proved the exact failed test in isolation, then ran one completed DIFF inventory; the failed attempt never reached mutation. | Reuse `BF-scorchkit-postgres-init-env-auth-drift-001`: validate all fixture privileges, not only connectivity, before delivery. |
