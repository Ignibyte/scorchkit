---
title: Application supply-chain SBOM and vulnerability evidence — notes
pipeline_id: 9320d21f-3214-43f2-a5e1-89058c58a2a2
---

# Application supply-chain SBOM and vulnerability evidence — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `CONSTITUTION.md` §§0, 3, 7, 14, 15, 18, and 19; `SECURITY.md` effect,
  process, provider, cache, redaction, and MCP invariants; roadmap SK-037 ordering and product
  boundary; `PR-scorchkit-public-mode-dependency-contract-001` for producer/consumer ordering;
  `PR-scorchkit-provider-transport-quarantine-001` for policy-owned provider traffic;
  `PR-scorchkit-executor-contract-001`, `PR-scorchkit-adapter-execution-descriptor-parity-001`,
  `PR-scorchkit-parser-outcome-integrity-001`, and `PR-scorchkit-scoped-tool-artifacts-001` for strict
  adapters; `PR-scorchkit-provider-consumption-validation-001` and
  `PR-scorchkit-public-evidence-revalidation-001` for consumption boundaries; and
  `PR-scorchkit-verified-artifact-single-read-001` for handing consumers the verified bytes.
- Recon changed the plan: do not extend the unordered code-module batch; add a supply-chain service
  with an explicit SBOM barrier. Do not reuse the best-effort CVE cache; preserve typed snapshot
  health. Do not let any scanner refresh itself; use policy-owned bounded streaming and atomic
  promotion. Do not treat a schema validator's default retriever as safe; embed and resolve only the
  versioned CycloneDX/SPDX/JSF schemas.
- Operator confirmation: the owner directed continuous execution, committed the SK-036 boundary,
  and granted standing authorization for local per-ticket commits after green delivery evidence.
  Prior direction prohibits repository-wide mutation reruns. This confirms the plan transition and
  later local commit, not a push, PR, remote target scan, or registry effect.

## Phase 2 — Design

- Architecture: add an agent-neutral supply-chain evidence vocabulary in `scorchkit-core`, stable
  target/profile/provider descriptors in `scorchkit-code`, and a root composition service with
  explicit `authorize target -> OSV source scan -> Syft producer -> validate/hash -> Grype/Trivy
  consumers -> correlate -> project` phases. The service owns the verified SBOM bytes and passes
  consumers an owned artifact handle; it does not publish security-critical state through
  `SharedData` or the unordered `CodeOrchestrator`. Source lockfile coverage and built-artifact
  coverage remain distinct within one `SupplyChainAssessment`. `ScanExecutionStatus::Incomplete`
  represents an applicable prerequisite that never ran; `Degraded` represents execution or
  validation failure after an attempted phase. Existing `ScanResult` fields remain readable and
  receive deterministic compatibility projections.
- Security boundaries: only explicit canonical local target kinds are representable. The policy
  authorizes the target before discovery or process creation. Every tool receives a clean
  environment, owned configuration/home/cache/temp/output paths, exact accepted exit codes, and a
  non-target working directory. Scanners cannot refresh, contact registries/daemons, load target
  config, inherit credentials, or reinterpret local paths. Provider refresh is a separate
  capability through `PolicyHttp`; a bounded stream is hashed into same-filesystem staging and is
  promoted only after digest/schema validation. Missing, stale, invalid, oversized, malformed, or
  failed prerequisites are typed gaps. The prior valid cache survives every refresh failure.
- Evidence and correlation: retain the exact bounded CycloneDX 1.6 document, its SHA-256, producer
  version, target revision/digest, provider snapshot identities, raw bounded tool reports, and
  normalized observations. A supplied valid PURL is canonicalized; an absent/invalid one stays
  explicit. Correlate only on target revision plus PURL plus an intersecting normalized advisory
  alias set. Never discard per-tool observations when clusters are formed.
- Public contract: `scan_code` selects supply-chain phases by profile; `scan_artifact` accepts only
  local directories/files/archives/OCI layouts/SBOMs; `supply_chain_cache_status` is read/local
  state; `supply_chain_cache_refresh` is external/local state. CLI, MCP, JSON, SARIF, terminal,
  storage, doctor, and Codex-host guidance expose the same target, effect, coverage, and provenance
  fields. Codex remains a preferred host with no vendor types in engine crates.
- File manifest — core/workspace: `Cargo.toml`, `Cargo.lock` (bounded streaming and reviewed schema
  dependencies if needed); `crates/scorchkit-tools/src/lib.rs` (exact accepted exit codes);
  `crates/scorchkit-core/src/{lib.rs,supply_chain.rs,scan_result.rs}` (typed identities, coverage,
  correlation, incomplete status); `crates/scorchkit-code/src/lib.rs` (stable descriptors);
  `crates/scorchkit-config/src/{lib.rs,types.rs}` (tool paths, cache roots, ages, size limits).
- File manifest — composition/adapters: `src/supply_chain/{mod.rs,target.rs,schema.rs,cache.rs,
  adapters.rs,orchestrator.rs}`; `src/engine/{mod.rs,policy_http.rs}`;
  `src/sast_tools/{mod.rs,syft.rs,osv_scanner.rs,grype.rs}`; `src/tools/{mod.rs,trivy.rs}`;
  `src/{lib.rs,adapter_catalog.rs,facade.rs}`; and `src/runner/code_orchestrator.rs` only for the
  profile handoff, never for producer/consumer execution.
- File manifest — projections and operations: `src/cli/{args.rs,doctor.rs,runner.rs}`;
  `crates/scorchkit-mcp/src/{contract.rs,types.rs}` and `src/mcp/{contract.rs,types.rs,tools.rs}`;
  `src/report/{json.rs,sarif.rs,terminal.rs,mod.rs}`; `src/storage/{findings.rs,scans.rs,models.rs}`;
  migrations only if current JSON evidence cannot preserve the new fields; tool and architecture
  docs; README/changelog/roadmap; the Codex ScorchKit skill; and ticket pipeline artifacts.
- File manifest — tests/fixtures: `tests/supply_chain.rs`, `tests/external_tool_contract.rs`,
  `tests/{cli.rs,mcp_tools.rs,storage.rs,workspace_architecture.rs}` and
  `tests/fixtures/supply_chain/{cyclonedx,osv,grype,trivy}`. Fixtures are synthetic and local; no
  registry, daemon, provider, package-manager, build, or public-target effect is permitted.
- Regression test plan: first prove exact exit-code semantics and legacy executor behavior; target
  authorization and symlink/no-registry denial before process creation; deterministic lockfile
  discovery; exact command/env/workdir/output contracts for all four tools; valid-empty versus
  empty/malformed/partial parser behavior; embedded local-only CycloneDX validation and exact-byte
  hashing/handoff; PURL/alias correlation and non-collision; cache Ready/Missing/Stale/Invalid plus
  oversize/digest/schema/interrupted refresh retaining the old snapshot; Complete/Incomplete/
  Degraded compatibility projections; and exact CLI/MCP/effect/doctor/storage/report contracts.
  Development uses focused unit/integration checks and `gate.sh --fast`; delivery uses the
  repository-approved exact-tree gate path without a repository-wide mutation campaign.
- Compatibility and rollback: serde defaults keep legacy results readable. New public fields are
  additive and new commands do not reinterpret existing web/code targets. Tool replacement on the
  build host is atomic and the prior Trivy wrapper is retained as a non-executable backup until the
  native binary is verified. A failed implementation can remove the new service without changing
  DAST, infra, cloud, or existing SAST module contracts.
- Operator confirmation: the owner's continuous-execution direction and standing green-ticket
  commit authorization confirm this locked design. The design does not broaden authorization to
  remote images, provider refresh during scans, pushes, or a full mutation run.

## Phase 3 — Implement

- Files and behavior changed:
  - Added agent-neutral supply-chain target, provider, SBOM, package, advisory, observation,
    correlation, coverage-gap, and complete/incomplete/degraded contracts in `scorchkit-core`, plus
    exact accepted exit codes in `scorchkit-tools` and stable profile/operation descriptors in
    `scorchkit-code`.
  - Added an ordered root composition service: authorize one explicit local shape; discover bounded
    source lockfiles; run pinned offline OSV Scanner; produce or import one bounded CycloneDX 1.6
    document; validate it with embedded local-only CycloneDX/SPDX/JSF schemas; hash and retain the
    exact bytes; pass one owned document to pinned Grype and Trivy; then correlate only matching
    revision, supplied normalized PURL, and advisory aliases.
  - Added strict clean-environment adapters with owned config/home/cache/temp/output state, exact
    source schemes and SBOM paths, exact exit codes, pinned version probes, output/artifact limits,
    native Trivy offline flags, and strict valid-empty versus malformed parsers. Independent legacy
    OSV/Grype and web-target Trivy registrations were removed from production catalogs while their
    source types remain readable for compatibility.
  - Added an existing owner-only snapshot store with immutable versioned directories, digest and
    exact-inventory revalidation, typed missing/stale/invalid/ready state, same-filesystem staging,
    atomic current-pointer replacement, and automatic cleanup of failed in-process staging. OSV
    refresh validates every bounded advisory in exact per-ecosystem `all.zip` paths. Grype refresh
    verifies the pinned binary, imports one digest-pinned Zstandard archive, validates status, and
    inventories only the resulting cache. Trivy refresh fails closed pending a reviewed import
    contract.
  - Added facade, CLI, and MCP scan/status/refresh operations. Ordinary code scans merge the selected
    ordered supply-chain profile. JSON, SARIF, terminal, HTML, PDF, and PostgreSQL
    `scorchkit.scan-execution-evidence.v1` preserve exact status, module outcomes, assessment,
    provider, SBOM, and gap evidence. MCP inventory increased from 30 to 33 tools.
  - Added migration `010_scan_execution_evidence.sql`; integration evidence proves the new JSONB
    field round-trips through the validation database. Doctor now requires exact Syft 1.50.0, OSV
    Scanner 2.3.8, Grype 0.116.1, and native Trivy 0.74.0 rather than treating later unreviewed
    versions as compatible.
  - Installed and checksum-verified the four pinned native Linux amd64 releases on the build host.
    Replaced the Docker/socket Trivy wrapper while retaining a non-executable backup. All Cargo
    output uses `/mnt/fast/scorchkit/cargo-target/ticket-012`; the runtime cache is the owner-only
    `/mnt/fast/scorchkit/supply-chain-cache`.
  - Updated durable architecture, configuration, tool inventory, report, storage, MCP, README,
    changelog, and Codex execution-skill guidance. Corrected the production catalogs to 90 web/DAST,
    22 code, and 122 maximum modules after quarantine.
- Design deviations:
  - Reused the existing root CLI argument package rather than adding `src/cli/args.rs`; the public
    surface remains the locked `supply-chain scan/cache-status/cache-refresh` contract.
  - Added one migration rather than relying only on finding evidence JSON. The existing
    `scan_records.summary` shape cannot preserve typed module failures or supply-chain coverage
    without conflating posture counts and execution integrity.
  - Trivy 0.74.0 has no `--skip-check-update` flag. The adapter uses the release's supported
    database, Java database, version, and telemetry update-disable flags and still supplies only an
    owned SBOM.
  - The requested validation URL authenticates on the Codex host but not as that user over TCP on
    the build host. Focused migration validation used the same named database through the build
    host's peer-authenticated local `cpeppers` role; the initial TCP attempt failed before migration
    or fixture creation.
  - The receipt-producing DIFF gate ran its one changed-code inventory: 570 selected, 291 caught,
    3 timed out and therefore caught by policy, 211 missed, and 65 unviable. It was stopped at the
    normal two-hour budget with a 58.21% viable score. Per the owner's direction, that inventory
    will not be repeated; focused repair rechecks only its exact missed outcomes. Scheduled
    repository-wide mutation remains exclusively SK-047.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Data integrity | A failed refresh left its staging directory in place and blocked reuse of the snapshot ID. | High | Fixed with an armed cleanup guard that transfers ownership only after promotion. Focused cleanup and preservation tests pass. |
| 2 | Correctness | Doctor accepted newer supply-chain binaries although the adapters require exact reviewed versions. | Medium | Fixed by exact version checks for Syft 1.50.0, OSV Scanner 2.3.8, Grype 0.116.1, and Trivy 0.74.0. Other tools keep their existing minimum-version rules. |
| 3 | Data integrity | Merging assessments with different target revisions could attach evidence to the first target. | High | Fixed by refusing the merge, retaining the first assessment unchanged, and recording an `unsupported_target` correlation gap. |
| 4 | Simplification | Low-level cache, adapter, and orchestrator internals were public even though they can bypass the intended facade composition. | Medium | Fixed by keeping only provider request DTOs public. Execution and snapshot internals are crate-private. |
| 5 | Security | A symlink at the provider, staging, snapshot, or run-workspace ancestor could redirect local-state reads or writes. | High | Fixed by rejecting redirected ancestors, binding every canonical directory to the private cache root, and adding provider and run-root symlink regressions. |
| 6 | Correctness | Snapshot freshness used only `checked_at`, and a refresh request could choose an age larger than the configured provider maximum. | High | Fixed by using the supplied upstream build time when present and applying the smaller of request and configured ages at refresh and scan time. |
| 7 | Correctness | The `quick` profile on an artifact selected no phase and returned a complete empty assessment. | High | Fixed by recording an `unsupported_target` gap. The focused artifact fixture now returns incomplete with no tool launch. |
| 8 | Security | Syft and Trivy wrote report files directly. Process output was bounded, but those files could grow until the tool exited. | High | Fixed by capturing JSON through the bounded process channel, then writing the exact accepted bytes to owner-only evidence files. |
| 9 | Security | Each provider response was bounded, but a refresh request could include an unbounded number of unique downloads and exceed the intended total effect. | High | Fixed with a 256-object ceiling, duplicate-path rejection, and a cumulative byte cap equal to the configured provider download limit. |
| 10 | Data integrity | Grype refresh treated any JSON object from `db status` as valid. | High | Fixed with a typed status contract requiring `valid=true`, a non-empty schema, no reported error, and a database file inside the owned cache. The compressed tar is now structurally checked without extraction before import. |
| 11 | Security | New provider, local-state, and subprocess effects had policy checks but no supply-chain audit events. | Medium | Fixed with normal scan lifecycle events plus redacted authorization, subprocess, and cache-promotion events. The URL-secret regression passes. |
| 12 | Simplification | Snapshot manifests allowed duplicate paths and cache inventories had no explicit file-count ceiling. | Medium | Fixed with duplicate rejection and a 4,096-artifact ceiling shared by promotion and revalidation. |

### Correctness review

- Profile and target combinations now select work or return a typed gap. No supported public path can
  return `complete` after selecting zero applicable phases.
- Provider freshness uses the configured cap at every public status and scan call. An upstream build
  timestamp takes precedence over the local check time.
- Assessment merges require the complete target identity, including revision and artifact digest.

### Security review

- Canonical cache ancestry is checked before downloads, imports, promotion, status reads, and run
  workspace creation. Symlinks and paths outside the private root fail closed.
- Every scanner runs offline with a clean environment and exact version, timeout, exit, and output
  rules. Syft and Trivy no longer control evidence-file growth.
- Refresh has separate local-state, provider, and external-tool grants. Redacted audit events cover
  those decisions and the effects they permit.

### Data-integrity review

- CycloneDX bytes are captured once, schema-validated locally, hashed, written as owner-only
  evidence, and handed unchanged to both consumers.
- Provider promotion revalidates a bounded exact inventory and every digest. Grype import also
  validates its compressed archive and typed status before promotion.
- Stored, JSON, MCP, SARIF, terminal, HTML, and PDF projections use the same complete, incomplete,
  or degraded assessment.

### Simplification review

- The unordered code-module batch does not carry the producer/consumer barrier. One crate-private
  service owns the ordered supply-chain run.
- Legacy OSV, Grype, and web-target Trivy registrations are quarantined from production catalogs.
- Public Rust types expose target, evidence, and provider request contracts without exposing cache
  mutation or raw adapter seams.

## Phase 4 — Validate

- Focused development evidence on the finalized mutation-input tree:
  - All-feature workspace tests passed, including 1,177 root library cases and the supply-chain
    adapter, cache, parser, orchestration, refresh, CLI, MCP, storage, and report contracts.
  - Strict Clippy passed for the default, all-feature, and seven derived feature states after two
    test-only lint repairs. Formatting, Rustdoc, advisory, license, secret, shell, spelling, and
    static-analysis lanes are green.
  - The final fast gate passed all 14 enabled lanes with zero failures and eight deliberate
    fast-mode skips.
- Mutation evidence:
  - The one completed DIFF inventory selected 570 mutations: 291 caught, 3 timed out and counted as
    caught, 211 missed, and 65 unviable. It was not repeated.
  - The focused 211-mutant repair run caught 189, timed out on 1, and left 21 named survivors. The
    exact residual recheck caught 21/21 with zero misses, timeouts, or unviable outcomes after final
    lint cleanup.
  - Sealed evidence reconstructs 211/211 viable focused mutations caught, zero missed, and 100% MSI
    at mutation-input SHA-256
    `3ed5928e25409c2819fcc7e3b323cb1ab20a338031be7ed32f25be245de5ae36`.
    Its evidence digest is
    `95f61c56c03bd305cfe1cb5963619760b40c71d208ec75be0b48f24439856cc1`.
- Gate run and receipt: the pre-completion focused-repair gate passed all 19 applicable lanes with
  zero failures and three named web-only skips. It measured 82.40% line coverage, passed 1,664
  strict Nextest cases with six reasoned skips, exercised the migrated PostgreSQL suites, and
  passed CLI/MCP contracts without launching cargo-mutants. The first attempt correctly rejected a
  stale zero-test allowlist entry for `scorchkit-code`; removing that obsolete exception made the
  exact inventory pass.
- Documented skips with reasons: the full repository mutation campaign remains deferred by the
  owner and roadmap item SK-047. Browser, website, and CSS lanes remain not applicable because
  ScorchKit has no web UI.

## Phase 5 — Complete

- Docs updated: the changelog, README, application-security catalog, CLI, configuration, MCP,
  module, report, runner, storage, tool, Codex plugin, operator checklist, and new application
  supply-chain architecture pages describe the shipped profiles, exact tool pins, offline scan
  boundary, provider refresh workflow, cache layout, and unsupported remote targets. The roadmap
  closes SK-037 and promotes SK-038 to the head of the remaining queue.
- AAR submitted: `AAR-012-application-supply-chain` records the ordered producer/consumer design,
  cache and refresh hardening, failed validation attempts, focused mutation repair, reusable rules,
  and a 5/5 effectiveness assessment.
- Archive: this notes/spec pair and TICKET-012 are ready for pipeline-controlled archival. The
  archive invalidates the pre-completion receipt, so delivery reruns the same focused-repair gate
  without launching cargo-mutants.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first MCP cache-status fixture failed because its temporary directory inherited group/other permissions on the build host. | Test setup assumed `tempdir` implied `0700`; the actual process umask produced a wider mode. | Set the fixture root explicitly to `0700` before opening the store. | Every security-sensitive permission test must create the exact mode it claims. |
| 2 | The first database validation attempt failed authentication. | `postgresql://chadpeppers@localhost/...` referred to the Codex host's local database identity, not a valid TCP identity on the separate build host. | Used the same named build-host validation database through its peer-authenticated local role; the focused round-trip passed. | Record host and authentication boundary with every reusable validation URL. |
| 3 | Broad test compilation reported unused test seams and retained parsed SBOM state. | The refresh executor injection was never exercised, and the parsed document was used only in tests. | Removed the unused seam and used the validated document's actual `specVersion` in production evidence. | Treat warnings as design feedback; do not preserve speculative seams. |
| 4 | Review found failed refresh staging would survive an early `?` and block reuse of the snapshot ID. | Atomic promotion protected the current pointer but no scope guard owned pre-promotion state. | Added an armed staging cleanup guard, disarmed only after successful promotion, with focused retention/removal tests. | Every staged effect needs explicit success transfer and failure cleanup ownership. |
| 5 | Review found doctor would accept newer supply-chain binaries although scan execution requires exact reviewed versions. | Doctor's shared version logic modeled only minimum versions. | Exact-pin Syft, OSV Scanner, Grype, and Trivy while retaining minimum semantics for other tools. | Version diagnostics must match the adapter compatibility contract, not merely installation guidance. |
| 6 | Provider and run-workspace ancestors could redirect effects through symlinks. | The first ancestry check compared canonical children to canonical parents but did not require each declared cache slot to remain a real child of the protected root. | Reject symlinks at every known ancestor and compare each canonical directory to the protected root before use. | Security-sensitive cache helpers must own directory creation and ancestry validation together. |
| 7 | Refresh requests could extend database freshness beyond configured policy. | Snapshot status trusted the manifest's requested age and measured only the local check time. | Cap request age with provider configuration and use `upstream_built_at` when supplied. | Context may narrow policy but must never widen it. |
| 8 | A quick artifact scan returned complete after running no phase. | The quick profile assumed a source directory but did not reject other explicit target kinds. | Record a typed unsupported-target gap before returning. | Every profile matrix needs a zero-work negative fixture. |
| 9 | Direct scanner output files were checked only after process exit. | The process limit covered stdout and stderr, not paths owned by the child. | Capture Syft and Trivy JSON through bounded stdout, then persist the accepted bytes. | A bounded artifact contract must control bytes while they are produced. |
| 10 | Provider refresh bounded individual responses but not the full request. | The request shape had no object-count, duplicate-path, or cumulative byte rule. | Add a 256-object ceiling, unique paths, and one cumulative limit. | Bound both each effect and the complete operation. |
| 11 | Grype status validation accepted any JSON object. | Parsing checked shape at the top level but did not verify the provider's success fields or owned database path. | Parse the pinned status contract and require valid, schema, error, and path invariants. | A successful process exit does not replace output-contract validation. |
| 12 | Supply-chain effects were authorized but absent from audit logs. | The ordered service and refresh path bypassed the existing orchestrator event publishers. | Publish lifecycle, authorization, subprocess, and promotion events with URL secret redaction. | Every new effect path needs an audit fixture before delivery. |
| 13 | The first fast gate rejected the new archive dependency and license chain. | The initial tar pin had newly published traversal advisories, and the local-only schema validator introduced the OSI-approved MIT-0 license. | Upgraded tar to 0.4.46 and added a narrow documented MIT-0 allowance. | Run advisory and license policy before locking a new dependency version. |
| 14 | Successive feature-matrix passes exposed strict lints hidden behind earlier compilation failures. | Clippy stops at the first failing workspace crate and feature state. | Removed panic paths, bounded heap buffers, stale docs, and non-idiomatic branches, then reran the complete matrix to green. | Treat the feature matrix as iterative evidence and rerun it after every newly exposed layer is fixed. |
| 15 | The spelling lane rejected exact SPDX identifiers embedded in the official schema. | The spelling tool interpreted license abbreviations and the historical `iMatix` identifier as prose. | Added exact word-level exceptions without excluding the schema from checking. | Prefer narrow immutable-data vocabulary entries over path-wide spelling exclusions. |
| 16 | The first DIFF delivery attempt failed its changed-code mutation floor after two hours. | New security-boundary code had broad functional coverage but insufficient exact branch, boundary, and output-contract assertions. | Sealed the 570-outcome inventory, deduplicated its 211 misses to 68 mutated functions, and added table, boundary, parser, cache, target, subprocess, and refresh tests before exact survivor-only recheck. | Mutation repair must turn each surviving operator into one observable contract; never repeat the complete inventory during focused repair. |
