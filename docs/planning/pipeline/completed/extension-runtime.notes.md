---
title: Capability-declared extension runtime and SDK — notes
pipeline_id: db68b03e-a4b5-4cfa-996a-caae014e5473
---

# Capability-declared extension runtime and SDK — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001` and
  `PR-scorchkit-attribution-not-authorization-001` keep declarations and identities from becoming
  grants; `PR-scorchkit-extension-persistence-boundary-001` forbids extension storage handles;
  `PR-scorchkit-executor-contract-001`, `PR-scorchkit-scoped-tool-artifacts-001`, and
  `PR-scorchkit-cancellation-whole-lifecycle-001` require one bounded owned process seam with
  cleanup; `PR-scorchkit-adapter-execution-descriptor-parity-001` requires metadata to match
  execution; `PR-scorchkit-public-evidence-revalidation-001` requires normalization/redaction at
  every public and durable boundary; `PR-scorchkit-doc-examples-contract-001` requires compiling
  the public SDK example; `PR-scorchkit-bounded-validator-mutation-table-001` requires exact
  boundary truth tables.
- Comparable work: TICKET-008 established the provider-neutral adapter descriptor and explicit
  compatibility catalog; TICKET-002 established whole-lifecycle process ownership and
  cancellation; TICKET-027 established the application-service/catalog boundary and canonical
  durable read checks; AAR-020 established that extensions return typed proposals and never own
  persistence.
- Recon: existing Rust module traits are trusted in-process APIs, and `runner::plugin` TOML wrappers
  execute arbitrary native tools as trusted configuration. Neither is a sandbox. `scorchkit-tools`
  already supplies bounded stdio, wall time, artifact monitoring, Unix process groups, and Windows
  Job Objects. A WebAssembly worker can add no-ambient imports plus guest memory/instruction limits
  without exposing engine memory.
- Plan impact: use a lower contract/SDK package and a separate digest-bound WebAssembly worker;
  keep effect brokerage and storage in root composition; extend the shared descriptor rather than
  add a parallel catalog; preserve the old trusted APIs with explicit documentation.
- Operator confirmation: on 2026-08-23 the owner directed Codex to continue roughly five tickets
  and use DIFF mutation validation rather than full mutation runs. That confirms this plan and the
  locked `--diff` delivery mode.

## Phase 2 — Design

- Architecture: add a lower `scorchkit-extension` contract/SDK package and a root-owned explicit
  registry, policy/audit effect broker, descriptor adapter, and separate owned Wasmi worker. The
  guest imports nothing and advances a turn-based ABI by returning effect requests to the parent;
  therefore it receives no ambient filesystem, socket, process, environment, credential, engine,
  or storage access. Existing process ownership covers the worker tree while Wasmi fuel, structural
  limits, and linear-memory limits bound guest computation.
- Registration/security: explicit manifest paths only; canonical no-follow authorization and one
  read of manifest/module bytes; exact SHA-256; separate `ExtensionExecute` grant; declarations are
  maxima, not grants. V1 brokers credential-free bounded target HTTP and opaque pre-opened inputs;
  path, credential-value, and arbitrary subprocess requests are typed unsupported denials. Every
  request is audited before a permitted effect begins.
- Data/catalog: add trust/runtime labels to the common adapter contract, map extension output into
  normal normalized/redacted `Finding` records with engine-built manifest/digest/invocation
  provenance, and use existing reports/control/MCP/storage. Protocol types expose no direct host
  handles. First-party modules remain compiled and trusted; legacy TOML command wrappers remain
  trusted configuration.
- File manifest: new extension package, root extension runtime modules, config registration,
  descriptor/policy/workspace updates, hidden worker entry, narrowly affected catalog/client and
  storage projections, extension fixtures/example/tests, architecture/security/public docs, and
  pipeline knowledge artifacts as enumerated in the confirmed spec.
- Regression test plan: manifest/protocol/schema truth tables; dependency and descriptor parity;
  exact-byte/digest and no-follow registration; distinct worker PID/no imports/ABI/fuel/memory/
  frame/time/cancellation/crash/cleanup limits; complete effect-denial/allow matrix with no-side-
  effect recording and audit; hostile output/provenance/redaction; orchestrator/report/control/MCP/
  PostgreSQL parity; standalone Wasm SDK compile; fast development gate and DIFF-only delivery.
- Operator confirmation: the owner's 2026-08-23 standing direction to continue roughly five
  tickets with DIFF rather than full mutations confirms this design and implementation scope.

## Phase 3 — Implement

- Files and behavior changed: added the lower `scorchkit-extension` manifest/protocol/SDK package,
  a standalone Wasm example, explicit extension configuration, descriptor trust/runtime labels,
  `ExtensionExecute` policy/control capability, and the root loader, worker, runtime, broker, and
  module adapter. The loader authorizes canonical no-follow files and retains digest-checked bytes;
  the owned Wasmi worker rejects imports and enforces ABI, fuel, memory, stack, frame, output, and
  time limits; the parent broker audits before effects and normalizes untrusted output into normal
  engine findings. CLI and the shared control/MCP catalog expose configured extensions only after
  reauthorization and digest validation. Added schema, manifest, protocol-boundary, runtime,
  effect-denial, provenance, scope, catalog, dependency, and descriptor regressions plus public,
  architecture, and security documentation.
- Design deviations: kept host-side manifest validation in an optional `host-contract` feature and
  the portable ABI/SDK in `guest-sdk`, because the initial single feature graph pulled host policy
  dependencies into the Wasm guest. The spec's proposed `validation.rs` was folded into
  `manifest.rs` because validation is part of the manifest contract. Runtime fixtures use inline
  deterministic WAT compiled during tests rather than checked-in binary Wasm files, avoiding opaque
  generated fixtures while exercising the official worker.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Catalog consistency | CLI catalog reads detected built-in collisions but not the same ID from two distinct extension manifests. | Medium | Fixed with one claimed-identity set spanning built-ins and every loaded extension; direct duplicate regression added. |
| 2 | Resource exhaustion | The Wasmi store bounded table count but not elements in its one allowed table, permitting a compact oversized allocation request. | High | Fixed with a 10,000-element ceiling and hostile instantiation regression. |
| 3 | Wire compatibility | Effect and turn enums accepted unknown JSON members while their nested records rejected them. | Low | Fixed with enum-boundary `deny_unknown_fields` and malformed-wire regressions. |
| 4 | Effect reachability | `input_read` existed in the protocol and broker but no host API could attach an opaque pre-opened input. | Medium | Added a digest-bound byte attachment API with identity, media, duplicate, capability, and aggregate-budget validation plus an allowed/audited worker test. |
| 5 | Descriptor parity | The v1 web host accepted a mixed source/web target claim and non-JSON output even though execution always used the web JSON adapter. | Medium | V1 execution and every catalog read now require only web/API targets and JSON output; mixed-target and SARIF regressions added. |
| 6 | Secret handling | Embedded `authorization=Bearer token` text redacted only the scheme and left the following token. | High | Fixed the shared source-assignment redactor to consume the complete bearer credential and added core plus hostile-extension regressions. |

- Inspection result: all six findings fixed at source. No open critical, high, medium, or low
  finding remains in the inspected extension change.

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - `cargo test --all-features --test extension_contract --test extension_runtime`: PASS; 2 public
    contract tests and 17 isolated-runtime, effect, resource, cancellation, provenance, catalog,
    and hostile-output tests executed.
  - `DATABASE_URL=postgresql://postgres:***@127.0.0.1:32777/scorchkit_test cargo test
    --all-features --test storage_integration
    isolated_extension_provenance_round_trips_through_postgres -- --exact`: PASS; exactly one
    PostgreSQL integration test executed against the disposable loopback database.
  - `cargo check -p scorchkit-extension --no-default-features --features guest-sdk --target
    wasm32-unknown-unknown`: PASS.
  - `cargo build --manifest-path examples/custom_wasm_extension/Cargo.toml --target
    wasm32-unknown-unknown`: PASS.
  - `bash bin/gate.sh --fast`: GREEN before validation; 14 passed, 0 failed, and 8 documented
    delivery-only skips. Mutation was explicitly skipped by fast mode.
- Gate run and receipt:
  - The first `bash bin/gate.sh --diff` validation attempt passed gates 1–15, including 84.04% line
    coverage, then reported 1,117 selected mutants because Git DIFF spans the still-uncommitted
    TICKET-025 through TICKET-028 worktree. The owner stopped that accumulated repeat. Its
    cargo-mutants invocation and the continuing gate process were terminated; the incomplete
    output is not a mutation result, score, green gate, or delivery receipt.
  - The completed six-name exact repair evidence under
    `.git/scorchkit-mutants-focused-ticket-027` belongs to closed TICKET-027 / SK-049. It caught all
    six original survivors, but its mutation-input hash correctly rejects the current SK-050 tree
    and is not claimed as TICKET-028 evidence.
  - Local checkpoint commit `078cbf9338cfdcfccc09e0cfea9f9dffecad5267` establishes the exact
    delivered TICKET-025 through TICKET-027 tree as the Git baseline. The shared SK-050 worktree
    content hash remained `d21ee6e548c5ea91febeb5f7f30494f03c24dea45ef140858588c3a88ea4e5f3`
    before and after moving the branch and index to that checkpoint, and the index is clean.
  - An inspection-only `cargo mutants --list --in-diff` against that baseline selects 418 mutants
    in 79 functions across 15 production files. It did not compile or execute a mutant. A matching
    TICKET-028 DIFF delivery receipt remains pending; no empty, synthetic, FULL, or repository-wide
    substitute is accepted.
  - The one canonical TICKET-028 DIFF completed its mutation lane against a fresh PostgreSQL 17
    database: 418 selected, 239 ordinary catches, 6 timeouts, 140 misses, and 33 unviable outcomes,
    for 245/385 viable caught (63.63% MSI). Its complete raw evidence is preserved unchanged under
    `.git/scorchkit-mutants-baseline-ticket-028`.
  - That DIFF passed static gates 1-15 and the PostgreSQL and contract lanes. Its Nextest lane later
    failed one CLI list contract because mutation workers had left invalid durable rows in the
    shared gate database; the isolated test and the preceding full all-feature test both pass on a
    fresh database. This is retained as a test-isolation defect to repair, not treated as a product
    validation bypass.
  - The owner approved focused repair of all and only the baseline's 140 exact survivor names and
    prohibited another broad mutation run. The scope spans 10 production files: 55 in
    `extension/broker.rs`, 32 in `extension/worker.rs`, 18 in `extension/module.rs`, 17 in
    `extension/runtime.rs`, 6 in `extension/loader.rs`, 3 in `engine/scan_context.rs`, 2 in
    `runner/orchestrator.rs`, and one each in extension config, core observation, and extension
    constants.
  - Direct exact-boundary tables now observe manifest counts, redaction ranges, binary budgets,
    authorization grants, URL and output validation, bounded reads, invocation inputs, framed
    protocol I/O, exports, worker invocation identity, module metadata, and duplicate registration.
    Narrow source-invariant assertions cover only redundant defense-in-depth guards and the worker
    state-machine conditions that cannot be observed separately after an earlier fail-closed guard.
    No exclusion, skip, retry, suppression, source weakening, or production-behavior relaxation was
    added.
  - The first exact 140-name run caught 139 and reproduced one behaviorally redundant Bearer-token
    range guard. After adding its narrow source-invariant assertion, a one-name exact recheck caught
    that final mutation. No 140-name repeat and no broader mutation selection ran.
  - `bash bin/focused-mutation-evidence.sh --verify
    .git/scorchkit-mutants-focused-ticket-028`: PASS; 140/140 viable caught, 100% MSI,
    mutation-input hash `c4131ecfc6d8ce8f4524446eacdd05d159de7f8f302d8d6dbc8937dff723320f`,
    evidence digest `c617aa629bb2804ec45a6a56c55da3b2088502a3988cdbb7773797b260ae30f7`.
  - The DIFF mutation-blind list was reviewed: its production entries are reexports, serde-only
    protocol/configuration records, adapter catalog wiring, composition entry points, or unchanged
    policy/resource declarations; its remaining entries are tests. Their behavior is covered by
    the green all-feature, architecture, extension contract/runtime, storage, CLI, MCP, and focused
    mutation suites, and no mutation exclusion was introduced.
  - The CLI database-state contract now queries its unique project by name instead of enumerating
    every row left by earlier mutation workers. It passes both on a fresh database and on the
    intentionally contaminated original gate database while retaining fail-closed canonical
    validation for the selected project.
  - Post-repair `bash bin/gate.sh --fast`: GREEN, 14 passed, 0 failed, and 8 documented
    delivery-only skips; mutation was explicitly skipped.
  - Pre-completion `bash bin/gate.sh --focused-repair`: GREEN and issued the exact-tree delivery
    receipt at 84.40% line coverage. The mutation lane verified the sealed 140/140 focused outcomes
    at 100% viable MSI and did not invoke cargo-mutants. PostgreSQL, strict Nextest, and CLI/MCP
    contract lanes passed against a fresh disposable database.
- Documented skips with reasons: browser, website-rendering, and built-CSS lanes remain not
applicable because ScorchKit ships no web UI. The interrupted DIFF's later lanes are not counted as
validation evidence; the green focused-repair gate is the canonical pre-completion receipt.

## Phase 5 — Complete

- Docs updated: README extension registration, SECURITY isolation/effect boundary, plugin SDK,
  extension/control/executor/module/workspace architecture, CHANGELOG SK-050 entry, ROADMAP
  completion/next-ticket state, shared descriptor fixtures, and the focused-repair amendment.
- AAR submitted: `AAR-028-extension-runtime`, effectiveness 4/5, with five failure patterns and five
  prevention rules registered in the knowledge index.
- Archive: TICKET-028 closes on 2026-08-23 and the spec/notes move to the completed pipeline store.
  Delivery reruns the same FOCUSED-REPAIR gate because archival invalidates the validation receipt;
  its mutation lane only verifies the sealed 140-survivor evidence.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The guest example initially inherited host-only dependencies. | Manifest and SDK features were not separated. | Gated manifest validation behind `host-contract` and compiled the SDK with `--no-default-features --features guest-sdk` for the real Wasm target. | Keep a standalone `wasm32-unknown-unknown` compile in the delivery contract. |
| 2 | An allowed effect could have begun before its audit record was durable. | Authorization and publication were initially adjacent but ordered incorrectly. | Prepare and authorize, publish the redacted decision, then construct the effect. | Assert denied effects have no side effect and review policy-before-effect ordering as a security invariant. |
| 3 | CLI catalog output admitted duplicate extension identities. | Its duplicate check compared every extension only with the immutable built-in vector. | Maintain one identity set across the complete catalog. | Use whole-registry identity claims for every dynamic catalog adapter. |
| 4 | Wasmi table elements were unbounded. | Table count and element capacity are separate resource-limiter controls. | Set both limits and trap on failed growth. | Audit every dimension exposed by third-party runtime limit builders. |
| 5 | A bearer token survived redaction after an assignment-shaped scheme. | The unquoted assignment parser stopped at the whitespace after `Bearer`. | Treat scheme plus credential as one sensitive value range. | Include multi-token credential syntax in public-boundary redaction fixtures. |
| 6 | SK-050's nominal DIFF selected 1,117 mutants from several completed tickets. | The prior delivered tickets were never checkpointed in Git, so `git diff HEAD` cannot express the active ticket boundary. | Stopped the repeated inventory and preserved it only as incomplete output. | Apply `PR-scorchkit-ticket-diff-baseline-001` before promoting the next ticket that depends on DIFF mutation scope. |
