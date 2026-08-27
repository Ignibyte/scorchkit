---
title: Add a signed extension catalog and lifecycle — notes
pipeline_id: b04dd984-1a3f-4ee7-b4be-529055060e37
---

# Add a signed extension catalog and lifecycle — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001`,
  `PR-scorchkit-verified-artifact-single-read-001`,
  `PR-scorchkit-offline-scan-refresh-separation-001`,
  `PR-scorchkit-extension-persistence-boundary-001`,
  `PR-scorchkit-release-target-header-binding-001`,
  `PR-scorchkit-restore-integrity-before-effect-001`,
  `PR-scorchkit-dynamic-catalog-global-identity-001`,
  `PR-scorchkit-history-not-latest-reconstruction-001`, and
  `PR-scorchkit-adapter-error-provenance-001`.
- Recon: SK-050 already owns a provider-neutral manifest, strict JSON schema, engine compatibility
  interval, module digest, no-follow bounded loader, retained module bytes, isolated worker, policy
  broker, untrusted-output normalization, and global built-in/dynamic ID claim. SK-057 should add
  signed discovery and lifecycle around that route, not duplicate it.
- Trust decision: only locally configured Ed25519 publisher keys are trusted. A signed bounded raw
  payload binds catalog/publisher sequence and validity plus exact manifest, module, permission,
  provenance, and conformance identities. Catalogs cannot add keys or name remote sources.
- Lifecycle decision: a private exact local root stores immutable approval records and
  append-preserved transitions. Install/upgrade preview computes one normalized permission diff;
  approval binds candidate and diff digests; activation/rollback atomically change only an exact
  active pointer after the candidate passes the existing loader and worker health check.
- Revocation/offline decision: trusted signed revocations block registration and invocation before
  worker selection while history remains readable. Missing catalogs do not revoke or update state;
  exact still-matching locally approved releases and built-ins continue without any fetch.
- Operator confirmation: the owner's standing `proceed` direction, explicit instruction to finish
  remaining roadmap work, and authorization to push the new ScorchKit `main` confirm SK-057 from
  the ordered backlog and this bounded local-only plan.

## Phase 2 — Design

- Architecture: add provider-neutral signed-catalog, permission, provenance, conformance, and
  lifecycle-record contracts to `scorchkit-extension`; add only local path/key/root configuration
  to `scorchkit-config`; and keep signature verification, authorized no-follow reads, private
  atomic lifecycle storage, current-catalog revocation evaluation, and activation composition in
  the root extension adapter. The signed envelope carries base64 raw payload bytes and Ed25519
  signature; verification uses a domain-separated message and a locally configured exact
  key-ID/publisher binding. Release entries name only adjacent regular manifest files and bind the
  exact manifest/module digests, normalized permissions, provenance, conformance evidence,
  catalog sequence, and validity interval. Approvals are immutable content-addressed files;
  activation changes a separate state document through private create-write-sync-rename and
  appends bounded transitions. Active releases reopen and compare their pinned local artifacts but
  do not require the catalog file to remain available. If a configured catalog is available, a
  valid newer/equal signed payload is checked for release or key revocation both during
  registration and immediately before worker spawn. Invalid present catalogs fail closed; absent
  catalogs are treated as offline, never as revocation or update. Catalog-managed modules reuse
  `LoadedExtension`, `WasmExtensionModule`, the isolated no-WASI worker, policy broker, validated
  output, and the existing global module-ID collision check. Catalog identity is added to finding
  provenance without rewriting historical records.
- File manifest: add `crates/scorchkit-extension/src/catalog.rs` and export its pure contracts;
  extend `crates/scorchkit-config/src/extension.rs` with bounded catalogs, trust bindings, and one
  lifecycle root; add `src/extension/catalog.rs` for verification/permission normalization and
  `src/extension/lifecycle.rs` for approval/state operations; extend `loader.rs`, `module.rs`,
  `runtime.rs`, `broker.rs`, and `mod.rs` for exact catalog execution identity and denial order;
  extend `crates/scorchkit-cli/src/lib.rs` plus `src/cli/runner.rs` with inspect, approve, activate,
  rollback, and status commands; integrate active releases in `src/runner/orchestrator.rs` and the
  module catalog; add `tests/extension_catalog.rs`; update extension architecture, configuration,
  CLI, security, and roadmap documentation plus schemas/examples where contract tests require it;
  make the existing root Ed25519 dependency unconditional.
- Regression test plan: contract tests cover bounded/closed schemas, canonical permission
  normalization, every widening axis, stable diff/approval digests, and malformed identities.
  Integration tests use temporary local files and deterministic Ed25519 fixtures to cover valid
  verification; payload/signature/key/publisher/manifest/module/provenance/conformance tampering;
  replay/expiry; approval mismatch; atomic activation failure preserving the prior pointer;
  explicit rollback; duplicate global identity; current release/key revocation before registration
  and before worker spawn; offline exact-release restart; changed artifact denial; and catalog
  paths that cannot cause network or arbitrary subprocess effects. Existing extension runtime and
  built-in module tests remain green. Run focused package/integration tests, `bash bin/gate.sh
  --fast`, pipeline inspection, then the required DIFF delivery gate.

## Phase 3 — Implement

- Files and behavior changed: added closed provider-neutral catalog, release, permission,
  provenance, conformance, revocation, approval, and lifecycle-state contracts to
  `scorchkit-extension`; bounded local catalog/key/lifecycle configuration to `scorchkit-config`;
  and host-side domain-separated Ed25519 verification, exact artifact and permission matching,
  private immutable approvals, atomic active pointers, rollback, replay defense, revocation, Wasm
  health checks, and offline approved loading. Catalog releases now compose through the existing
  retained-byte loader, isolated worker, broker, output validator, global module identity check,
  CLI module listing, control/MCP module projection, and normal orchestrator. Catalog HTTP origins
  are an additional exact signed ceiling, revocation is rechecked before worker selection, and
  finding provenance retains approval/catalog/publisher/key/payload/release/permission/build/
  conformance identities. Added explicit `catalog inspect|approve|activate|rollback|status` CLI
  commands, architecture/security configuration guidance, and deterministic signed integration
  fixtures covering approval, activation, offline restart, replay, key/release revocation,
  post-registration denial, failed upgrade, rollback, artifact drift, and signature/publisher
  tampering.
- Development evidence: `cargo test -p scorchkit-extension --all-features` passed 10/10;
  `cargo test --test extension_catalog --test extension_runtime` passed 9/9 and 17/17;
  `cargo test -p scorchkit --lib --all-features` passed 1,491 tests with four reasoned ignores;
  strict all-target/all-feature Clippy passed. The fast gate passed all 13 source, test,
  dependency, secret, shell, documentation, formatting, and static-analysis lanes it could run.
  Its all-feature aggregate was red only because the optional console preflight correctly rejected
  the unrelated dirty sibling Rustal checkout at a revision other than ScorchKit's approved pin;
  the sibling remains untouched and validation will use the previously approved exact-mirror
  procedure.
- Design deviations: none. The root `ring` dependency became unconditional because catalog
  verification is a core local extension boundary rather than a team-only feature; no new network,
  subprocess, filesystem effect class, remote target, or catalog-controlled trust source was added.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Approval-boundary critic | `approve` recomputed the release and diff but did not require the payload and diff hashes returned by the preceding `inspect`; a changed signed candidate with the same release ID could therefore be approved without matching the operator's reviewed subject. | high | Fixed: approval now requires both exact inspect hashes in the API and CLI, rejects either mismatch before writing, and has a regression that changes the candidate payload. |
| 2 | Concurrency/crash critic | Approval, activation, and rollback performed read-modify-write state transitions without a cross-process writer lock; a crash after publishing an approval file but before state publication also left an otherwise valid orphan that could be activated by digest. | high | Fixed: a private no-follow cross-platform file lock serializes all mutations; activation/rollback accept only approvals already committed by an append-preserved approval transition; the orphan denial has an exact regression. |
| 3 | Replay/equivocation critic | The replay checkpoint stored only the highest sequence, so a second differently signed payload could reuse that accepted sequence without being classified as equivocation. | high | Fixed: state checkpoints bind each highest sequence to one exact payload digest; approval, registration, and pre-worker revocation checks reject lower sequences and same-sequence payload changes. |
| 4 | Offline-boundary critic | `Path::exists` followed links, so replacing a missing catalog with a dangling symlink could make invalid present state appear offline and bypass fail-closed catalog verification. | high | Fixed: `symlink_metadata` distinguishes true absence from every present file type and indeterminate availability; a dangling configured catalog now reaches the no-follow verifier and is denied. |
| 5 | Durable-integrity critic | Lifecycle validation checked field shapes but did not reconstruct active pointers from transition links, and could accept duplicated approval identities or a pointer that was never approved. | high | Fixed: validation now reconstructs per-extension active state, requires exact from/to continuity and prior approval ownership, rejects duplicate approval identities, and compares the reconstruction to every published pointer. |
| 6 | Wasm-health critic | Activation checked export names but not the exact reserve/run function signatures; the initial failed-upgrade test altered bytes after approval and therefore exercised artifact drift rather than signed structural health. | medium | Fixed: health validation resolves the exact typed ABI functions before publication, and the upgrade fixture now signs and approves a structurally loadable module with an unsupported ABI so failure occurs at health validation while the prior pointer remains active. |
| 7 | Filesystem critic | New directories were chmodded only after creation, existing lifecycle paths were not required to belong to the current Unix owner, and concurrent layout creation could report a false failure. | medium | Fixed: Unix directories are created with owner-only mode atomically, regular lifecycle objects require owner-private metadata, create races revalidate the winner, and tests assert private root/approval/lock/state modes plus fail-closed public state. |
| 8 | Provenance/catalog critic | Catalog finding provenance relied on the approval digest to imply the manifest and omitted the accepted sequence, making two important execution identities indirect in the public record. | low | Fixed: exact catalog sequence and manifest digest are now included beside approval, payload, module, permissions, build, revision, and conformance identities; catalog and explicit registrations also have a direct global duplicate-ID integration test. |

## Phase 4 — Validate

- Initial delivery gate: a fingerprint-identical disposable ScorchKit mirror beside clean Rustal
  `8b741c4c0e4c87542dea575aea9be9acfa3bf728` passed 21/22 DIFF lanes. Rustfmt, all 11 Clippy feature
  states, all-feature tests, Rustdoc, audit/deny/machete, gitleaks, shellcheck, source/documentation/
  configuration checks, Semgrep, coverage, browser E2E, website/CSS rendering, strict nextest,
  PostgreSQL integration, and CLI/MCP contracts were green.
- Mutation baseline: the completed DIFF selected 399 mutations in 82 functions across 12 files;
  cargo-mutants recorded 233 ordinary catches, 32 timeout catches, 101 exact survivors, and 33
  unviable outcomes, for 265/366 viable caught and 72.4% MSI. The raw inventory/outcomes are sealed
  under `.git/scorchkit-mutants-focused-ticket-035/initial`; the original and mirror mutation-input
  hashes both equal `3e7a78d499e6010996f5e502fd3ce8ee6d8568be7b34f7f690e9e015a3fbf2c3`.
- Owner-approved repair scope: all and only the 101 survivors in 33 functions across
  `crates/scorchkit-config/src/extension.rs`, `crates/scorchkit-extension/src/catalog.rs`,
  `src/cli/runner.rs`, `src/extension/catalog.rs`, and `src/extension/lifecycle.rs`. Preserve the
  completed broad baseline, add exact boundary/denial assertions, recheck its exact names, and do
  not repeat the four-hour broad campaign. Pre-repair snapshots bind every mutation input planned
  for the repair.
- Focused repair: direct boundary, predicate-truth-table, persistence-denial, and CLI propagation
  tests caught 98/101 names on the first exact diagnostic pass. Its three residuals exposed the
  exact-valid-from boundary, a test-inactive non-Unix create branch, and a private-mode check that
  masked the regular-file directory predicate. The repaired test seam and exact assertions passed
  the root extension suite, a three-name probe caught 3/3, and the canonical all-101 rerun caught
  94 ordinarily plus seven by timeout with zero missed or unviable.
- Sealed evidence: `.git/scorchkit-mutants-focused-ticket-035` reconstructs 366/366 viable outcomes
  caught at 100% MSI, verifies mutation input
  `6128ef4e72e34aae17baccf4781675a7ee4dc00eee494fb3effa804376eb4715`, and has evidence digest
  `059bc02f51e0837c20f8374a3825888b8e9f8ba73c7008d44b476f581c13ea5f`.
- Gate run and receipt: the fingerprint-identical disposable ScorchKit mirror beside clean Rustal
  `8b741c4c0e4c87542dea575aea9be9acfa3bf728` passed all 22 focused-repair lanes with zero failures
  or skips and wrote receipt fingerprint
  `347230ebb23d6725a631559d2df14c04546aa9a7d9cd7659f09f50151a539c44`. Coverage reported 85.92%
  regions, 83.03% functions, and 86.00% lines; strict nextest passed 2,290 executed cases with ten
  configured skips; browser, website/CSS, authenticated PostgreSQL, and CLI/MCP contracts passed.
- Documented skips with reasons: none in the 22 delivery lanes. The ten nextest skips are the
  repository's reasoned live-tool/network cases and are validated by the strictness lane.

## Phase 5 — Complete

- Docs updated: SECURITY, extension/application-security architecture, CLI/configuration surfaces,
  roadmap status/evidence/backlog, intake/ticket indexes, knowledge register/AAR, and this pipeline
  pair describe the signed local catalog, exact lifecycle authority, offline/revocation behavior,
  and sealed focused mutation evidence. Root LLVM profiler artifacts were removed and a narrow
  `*.profraw` ignore prevents recurrence without hiding other generated files.
- AAR submitted: `docs/planning/knowledge/aar/AAR-035-extension-catalog.md` on 2026-08-26 with
  effectiveness 4/5 and six new reusable failure/prevention pairs.
- Archive: `bash bin/pipeline.sh pass complete` will close TICKET-035, remove it from the open queue,
  archive this spec/notes pair, and rewrite active/open cross-links. Post-archive delivery will
  rerun the same 22-lane focused-repair gate from the exact validation mirror; gate 16 will verify
  sealed 366/366 viable evidence without launching cargo-mutants before commit and push.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first fast gate rejected one CLI comparison, two production-source assertions, and one endpoint test expectation. | The new CLI path compared an owned path to an ambiguous reference, static assertions still encoded the previous orchestration/output shapes, and the endpoint test assumed the ordinary engagement policy would allow a request after the catalog ceiling did. | Used an explicit `Path`, updated exact production-source contracts, and asserted only that catalog-origin denial no longer supplied the failure; all-feature tests passed. | Update structural contract tests with their production edit and keep layered-policy tests specific to the layer under test. |
| 2 | Gitleaks classified a deterministic rotated-key fixture identifier as a credential and Taplo rejected the changed root feature layout. | A fixture label resembled a secret name and the dependency/feature edit had not been run through the repository formatter. | Renamed the non-secret fixture key ID and formatted the manifest; both lanes passed. | Use neutral identifiers for deterministic cryptographic fixtures and run Taplo immediately after manifest edits. |
| 3 | The fast gate aggregate remained red despite every ScorchKit test passing. | The shared sibling Rustal checkout contains unrelated dirty work at a revision other than the approved console pin. | Left the sibling untouched; validation uses a fingerprint-identical disposable ScorchKit mirror beside a clean local clone at the exact pin. | Reuse `PR-scorchkit-pinned-sibling-validation-mirror-001` whenever the shared pinned dependency is active. |
| 4 | Strict Clippy rejected the first equal-sequence equivocation predicate as a suspicious operator grouping. | Adjacent `<` and `== && !=` guards obscured the intended three-way sequence state machine. | Rewrote approval, registration, and invocation checks as explicit `Ordering` matches. | Express security monotonicity as a closed ordering table rather than neighboring compound predicates. |
| 5 | The initial failed-upgrade regression was named as a health test but changed the module only after approval. | Artifact-drift setup intercepted the candidate before structural startup validation. | Signed the incompatible ABI bytes and matching manifest/catalog identities before approval, then asserted the exact unsupported-ABI failure and unchanged prior pointer. | Verify that every negative fixture reaches its named enforcement layer by asserting the exact bounded failure source. |
| 6 | The first DIFF mutation lane completed at 72.4% MSI with 101 survivors after all other 21 delivery lanes passed. | Representative catalog/lifecycle tests did not independently pin every exact ceiling, helper return, compound guard operand, persistence denial, and CLI dispatch result. | Preserve the sole broad inventory, add direct boundary/truth-table and failure-injection assertions, and recheck all and only its 101 exact names under the approved focused-repair workflow. | Treat closed contract predicates, exact maxima, durable-write steps, and thin CLI dispatch as explicit mutation tables before the first delivery inventory. |
