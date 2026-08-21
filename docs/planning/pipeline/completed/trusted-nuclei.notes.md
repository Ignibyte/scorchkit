---
title: Trusted Nuclei templates and application-specific runtime probes — notes
pipeline_id: 81cd1faf-62db-4af7-8f46-16eab2662845
---

# Trusted Nuclei templates and application-specific runtime probes — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-policy-before-effects-001`: authorize the exact target, capabilities, and effect
    before creating a workspace or Nuclei subprocess.
  - `PR-scorchkit-adapter-execution-descriptor-parity-001` and
    `PR-scorchkit-effect-contract-single-source-001`: one exhaustive descriptor must own protocol,
    strongest effect, invocation, provenance, and artifact claims.
  - `PR-scorchkit-credential-use-separate-grant-001`: authenticated template execution requires an
    independent credential-use grant.
  - `PR-scorchkit-parser-outcome-integrity-001` and
    `PR-scorchkit-scan-coverage-projection-parity-001`: malformed, failed, empty, and clean outcomes
    remain distinct through every public projection.
  - `PR-scorchkit-scoped-tool-artifacts-001`, `PR-scorchkit-secretless-tool-version-probe-001`, and
    `PR-scorchkit-untrusted-finding-channel-redaction-001`: use a private owned workspace, probe the
    tool without secrets, and redact untrusted output at construction and publication.
  - `PR-scorchkit-generated-dast-plan-001`: templates and manifests are context, not authority.
  - `PR-scorchkit-focused-mutation-repair-001`: preserve broad mutation work and mutate only the
    functions changed or repaired by this ticket.
- Recon evidence:
  - The current adapter passes no explicit template path, so Nuclei owns ambient selection.
  - Official Nuclei documentation confirms default community-template selection and automatic
    update checks, plus `-t`, `-duc`, `-dut`, `-ni`, protocol opt-ins, and JSONL controls.
  - The build host does not currently contain Nuclei.
- Operator confirmation: the owner directed the roadmap to continue and granted standing commit
  authorization. The established constraint against repeated full mutation scans remains binding.

## Phase 2 — Design

- Architecture:
  - Added `docs/architecture/trusted-nuclei.md` with the manifest, approval, classifier, policy,
    concrete-address target, process isolation, evidence, and proposal boundaries.
  - Use a strict JSON collection manifest and bounded YAML template inspection. The manifest pins
    one certificate and every exact template byte sequence. Nuclei native verification is a second
    check, not the inventory owner.
  - Add a generic adapter-execution assessment to `scorchkit-core`; Nuclei publishes it through
    typed shared data and the web orchestrator attaches it to the scan result on success or failure.
  - Extend `ScanContext` with the active policy authorizer and effect-specific invocation methods so
    local files and descriptor effects are authorized at the point of use without vendor logic in
    the provider-neutral policy crate.
  - Resolve the canonical target through `PolicyNetwork`, run Nuclei against one authorized concrete
    address, and supply the original authority and SNI. Redirects and authority-changing template
    constructs remain disabled.
  - Pin Nuclei 3.11.1 on the build host. Its 3.10 and 3.11 security hardening is part of the supported
    contract, but ScorchKit still denies JavaScript and every non-HTTP protocol.
- File manifest:
  - `crates/scorchkit-core/src/adapter_execution.rs`, `lib.rs`, `scan_result.rs`, and
    `shared_data.rs`: provider-neutral assessment, input identity, gaps, result attachment, status
    derivation, and typed publication.
  - `crates/scorchkit-config/src/types.rs`: bounded `NucleiConfig` including manifest path, limits,
    rate, concurrency, timeout, and supported version.
  - `src/engine/scan_context.rs` and `src/facade.rs`: carry the policy authorizer, authorize exact
    local state and descriptor effects, and preserve denial-before-effects ordering.
  - `src/trusted_nuclei/{mod,collection,classifier,workspace,invocation,parser}.rs`: module facade,
    bounded single-read trust resolution, strict protocol/effect classifier, private owned copies,
    exact process plans, JSONL normalization, and assessment publication.
  - `src/tools/mod.rs` and `src/tools/nuclei.rs`: register the trusted module and remove the ambient
    invocation/parser ownership from the legacy wrapper.
  - `src/runner/orchestrator.rs` and `src/runner/checkpoint.rs`: honor configured executable paths,
    collect assessments for both result arms, and bind resume state to collection identity.
  - `src/report/{terminal,html,pdf,sarif}.rs`, `src/storage/scans.rs`, `src/mcp/tools.rs`, and MCP
    fixtures: public and durable execution-evidence parity.
  - `src/cli/doctor.rs`: stop recommending ambient template updates; report pinned executable and
    configured collection readiness.
  - `tests/trusted_nuclei.rs` and `tests/fixtures/nuclei/`: explicit build-host loopback integration
    plus inert/tampered/unsupported parser and invocation fixtures. No production private key enters
    the repository.
  - `README.md`, `CHANGELOG.md`, `docs/architecture/{config,tools}.md`,
    `docs/guide/{modules,module-matrix}.md`, `docs/tools/nuclei.md`, and
    `docs/tools-checklist.md`: operator trust ceremony, supported boundary, and pinned installation.
- Regression test plan:
  - Manifest table: unknown schema/fields, duplicate IDs/paths, order identity, absolute/parent/
    symlink/escape paths, missing and non-regular files, exact byte/count limits, digest mismatch,
    certificate mismatch, signature fragment mismatch, altered-after-review bytes, and valid owned
    copy identity.
  - Classifier table: every Nuclei protocol, multi-protocol, workflow/flow/self-contained, method and
    body effect floor, raw/unsafe/redirect/payload/fuzz/OAST/external URL, authority/framing headers,
    exact BaseURL/RootURL paths, stronger declaration acceptance, and weaker declaration denial.
  - Policy table: missing DAST, external-tool, local-state, credential-use, and exploit grants each
    deny before workspace and executor; exact grants accept. Concrete address and changed DNS answer
    decisions are asserted separately.
  - Invocation table: version, validation, and scan argument order; clean environment names only;
    verified certificate content; explicit copied template paths; no ambient/update/remote/AI/cloud/
    workflow/protocol opt-ins; limits and whole-process ownership.
  - Parser table: verified metadata overrides scanner claims; malformed and partial JSONL fail;
    empty successful output remains zero findings with complete assessment; evidence and diagnostics
    are redacted; matched targets cannot escape the concrete execution origin.
  - Projection table: scan status, JSON, terminal, MCP, HTML, PDF, SARIF, checkpoint, and PostgreSQL
    preserve the same assessment without secrets. Resumption rejects or reruns a changed collection.
  - One explicit ignored integration test uses a temporary loopback application and externally
    prepared test certificate/template with the checksum-verified Nuclei 3.11.1 binary. It asserts a
    real request, finding, collection identity, native signature acceptance, and clean completion.
  - Development uses focused unit/integration tests and `gate.sh --fast`; validation runs DIFF only
    if its mutation scope is acceptably narrow, otherwise the ticket records fixed-function scope and
    uses sealed focused evidence. No repository-wide mutation scan is authorized.

## Phase 3 — Implement

- Files and behavior changed:
  - Added the provider-neutral `scorchkit.adapter-execution-assessment/v1` contract, typed shared
    publication, scan integrity derivation, checkpoint retention, and JSON, terminal, MCP, HTML,
    PDF, SARIF, and PostgreSQL projection.
  - Added bounded Nuclei configuration with hard safety ceilings. Missing configuration, missing
    tools, rejected inputs, signatures, versions, execution, and output now produce distinct typed
    gaps instead of a successful empty result.
  - Added strict manifest-relative collection loading, digest and signer-fragment verification,
    deterministic identity, non-symlink regular-file rules, and a private owned runtime copy.
  - Added an HTTP-only classifier. It denies every other protocol, raw and unsafe requests,
    redirects, payloads, fuzzing, external and OAST targets, runtime expressions, credential and
    framing headers, CONNECT and TRACE, ambiguous paths, and DSL response operators. Only a small
    schema-checked set of non-DSL matchers and extractors is accepted.
  - Added exact effect and local-state authorization at the point of use, concrete authorized
    address execution with original Host/SNI, clean environment, explicit template paths, disabled
    updates and unsigned templates, bounded output and artifacts, native signature confirmation,
    redacted parsing, and audit events.
  - Installed the official Linux amd64 Nuclei 3.11.1 archive on the build drive at
    `/mnt/fast/scorchkit/tools/nuclei/v3.11.1/nuclei`; verified SHA-256
    `ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6`; and exposed that file
    through `/usr/local/bin/nuclei`.
  - Added a signed inert loopback fixture and ignored real-binary integration test. The test signing
    key was generated only for the fixture ceremony and securely removed; the repository contains
    the public certificate and signed bytes only.
- Design deviations:
  - Checkpoint resume always reruns Nuclei and removes its stale findings/evidence. Prebinding a
    collection identity before the module would duplicate the verified loader and create a second
    trust path.
  - Adversarial review of ProjectDiscovery's response helper functions showed that matcher DSL can
    resolve DNS. The classifier therefore became stricter than the initial design and rejects all
    DSL matchers/extractors and runtime expressions in response operators.
  - Native validation starts Nuclei's loopback metrics service. Both validation and scan force its
    port to zero, avoiding a fixed listener, while the external-tool process remains policy-bound,
    short-lived, and group-owned.
- Focused implementation evidence:
  - `cargo test --lib trusted_nuclei`: 22 passed after inspection repairs.
  - `cargo test --lib tools::nuclei::tests::`: 4 passed, including process and resolved-address
    denial before invocation.
  - `cargo test --lib engine::scan_context::tests::`: 3 passed.
  - `cargo test --lib runner::orchestrator::tests::`: 10 passed.
  - `cargo test -p scorchkit-core adapter_execution`: 2 passed.
  - `cargo test -p scorchkit-core scan_result::tests::adapter_assessments_drive_top_level_integrity_and_merge`: 1 passed.
  - `cargo test -p scorchkit-config`: 39 passed.
  - `cargo test --lib cli::doctor::tests::`: 21 passed.
  - `cargo test --lib report::`: 36 passed.
  - Real signed loopback Nuclei 3.11.1 integration: 1 passed with one request, finding, verified
    signer, exact version, and complete assessment.
  - `bash bin/gate.sh --fast`: 14 passed, 0 failed, 8 intentionally skipped; mutation was not
    launched. The exact run used `/mnt/fast/scorchkit/cargo-target/ticket-014` and
    `/mnt/fast/tmp` on the build host.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Protocol bypass | Nuclei matcher DSL can resolve DNS and create an undeclared network effect. | High | Fixed: all DSL matchers/extractors and response runtime expressions are denied; only schema-checked non-DSL operators remain. |
| 2 | Resource abuse | Operator-supplied limits were positive but initially had no non-overridable upper ceilings. | High | Fixed: manifest, certificate, template, count, output, artifact, process, rate, concurrency, and request-time limits have hard ceilings with exact-boundary tests. |
| 3 | Coverage integrity | Missing Nuclei configuration or a denied pre-execution grant published incomplete adapter evidence but the module runner could still project a failed/degraded module. | High | Fixed: normal, checkpoint, and phased runners derive the module disposition from typed adapter status; three-mode regression test proves `incomplete` remains `incomplete`. |
| 4 | Local input race | Collection paths were canonicalized and then reopened, allowing a narrow substitution window between validation and byte consumption. | High | Fixed: Linux uses `openat2` with no-symlink resolution; other hosts use no-follow open, identity recheck, and the authorized bytes are consumed from that same handle. Replacement and symlink tests pass. |
| 5 | Resource abuse | Per-file limits did not cap the cumulative bytes and entry count held in memory and copied before the subprocess artifact monitor started. | High | Fixed: collection loading reserves fixed workspace entries and accumulates certificate/template bytes against the configured aggregate budget before workspace creation. |
| 6 | Policy ordering | Concrete DNS answers were authorized only after the private workspace was created, and address-policy denial was labeled as an execution failure. | High | Fixed: every resolved address is authorized before workspace creation; denial is typed as an incomplete unsupported-capability gap and starts no process. |
| 7 | Tool trust | Missing tool paths were skipped before the adapter could publish its own execution assessment. | Medium | Fixed: the orchestrator publishes a redacted typed configuration-unavailable assessment for missing Nuclei binaries in every execution mode. |
| 8 | Evidence parity | Initial report projections omitted parts of adapter identity and terminal counting could count the same module and adapter state twice. | Medium | Fixed: terminal, HTML, PDF, SARIF, checkpoint, MCP/JSON, and PostgreSQL projections carry the full schema and deduplicate display counts; focused report tests pass. |
| 9 | Auditability | Verified collection and successful execution milestones were not explicit audit events. | Medium | Fixed: `nuclei.collection_verified` and `nuclei.execution_completed` publish bounded structured identities and counts. |
| 10 | Listener isolation | Nuclei native validation always starts its metrics listener and defaults to a fixed port. | Medium | Fixed within the external-tool boundary: validation and scan force port `0`, while the short-lived process remains policy-bound and group-owned. |
| 11 | Invocation drift | No single test pinned the version, validation, and scan argument/environment contracts. | Medium | Fixed: a recording-executor test now proves explicit templates, clean environment, concrete target, Host/SNI, limits, artifact budget, and forbidden ambient/update flags across all three stages. |
| 12 | Delivery environment | The first fast gate exposed a wrong PostgreSQL identity, absent Gitleaks/Semgrep path, and an outdated ShellCheck. | Medium | Fixed: build-host validation uses its local socket role; checksum-verified Gitleaks 8.29.0 and ShellCheck 0.11.0 are installed on `/mnt/fast`; the corrected fast gate passed 14/14 lanes. |
| 13 | Regression contract | The legacy external-tool registry test required unconfigured Nuclei to launch one ambient process. | Medium | Fixed: it now proves that no collection means no process plus typed incomplete coverage; the signed loopback test owns configured execution proof. |

Inspection also confirmed that the committed fixture set contains no private signing key, Nuclei has
no ambient community-template selection path, `git diff --check` is clean, the signed loopback
integration still passes, and strict all-feature Clippy is green.

## Phase 4 — Validate

- Tests run (commands and outcomes): focused unit, integration, real signed loopback, strict
  all-feature Clippy, formatting, fixture-secret, and fast-gate checks above are green. The sealed
  mutation scope contains 84 candidates across 14 repaired functions in four files: the
  same-handle collection loader, cumulative budget checks, trusted Nuclei authorization boundary,
  typed incomplete-status projection, and its three execution-mode mappings. No repository-wide
  mutation scan will run.
- Focused mutation repair preserved the 84-case inspection inventory, then selected 39 mutations
  across only nine repaired functions: 32 were caught, six were unviable, and one exact 128-byte
  identity boundary survived. A single-case recheck after adding that acceptance assertion caught
  the survivor. Delivery uses the sealed current-tree one-case evidence at
  `.git/scorchkit-mutants-focused-ticket-014`; the broader inventories were not repeated. The
  first transition-style draft is retained separately for diagnosis and is not delivery evidence.
- Gate run and receipt: the pre-completion `bash bin/gate.sh --focused-repair` run passed 19
  applicable lanes with 0 failures and wrote an exact-tree focused-repair receipt bound to
  `scorchkit-mutants-focused-ticket-014`. Strict all-feature Clippy, 1,780 Nextest cases,
  PostgreSQL integration, CLI/MCP contracts, and 83.15% line coverage were green. The gate verified
  the sealed one-case current-tree mutation evidence and did not launch cargo-mutants.
- Documented skips with reasons: gate 17 browser E2E is not applicable until ScorchKit has a web
  UI; gate 18 website dogfood rendering is not applicable to the terminal security engine; gate 19
  built CSS sheets is not applicable because ScorchKit has no web asset pipeline.

## Phase 5 — Complete

- Docs updated: the changelog, README, configuration, module matrix, tool checklist, operator guide,
  trusted-Nuclei architecture, roadmap, intake, and ticket records describe the implemented trust,
  policy, execution, evidence, and unsupported-protocol boundary.
- AAR submitted: `AAR-014-trusted-nuclei` records five new bug classes and four prevention rules,
  with an effectiveness score of 5.
- Archive: the pipeline-owned `pass complete` transition closes TICKET-014, rewrites its canonical
  links, and archives this spec/notes pair. Delivery then reruns the approved focused-repair gate so
  the receipt binds the archived final tree.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first fast gate could not authenticate to PostgreSQL. | The build-host validation URL named a different database role and selected password authentication. | Switched validation to the build host's local socket URL, `postgresql:///scorchkit_codex_validation_001`. | Keep host-local gate receipts bound to the host's validated database identity. |
| 2 | The first fast gate lacked current Gitleaks and ShellCheck tooling. | Build-host quality-tool provisioning had drifted behind the repository gate contract. | Installed checksum-verified Gitleaks 8.29.0 and ShellCheck 0.11.0 on `/mnt/fast` and exposed stable `/usr/local/bin` links. | Pin and checksum build-host quality tools alongside scanner binaries. |
| 3 | The all-feature test lane expected every registered DAST wrapper to launch one ambient process. | The legacy registry contract did not account for trusted Nuclei's required explicit collection preflight. | Made the contract assert that unconfigured Nuclei publishes typed incomplete coverage without process creation; configured execution remains covered by the real signed loopback test. | Adapter contract tests must model preflight-denied and configured-execution paths separately. |
| 4 | Pre-execution adapter gaps could be elevated to degraded module failures. | Module runners ignored the adapter's typed terminal state when an adapter returned an error. | Added one adapter-aware outcome mapper used by normal, checkpoint, and phased execution. | Treat typed coverage evidence as the source of truth for public execution integrity. |
| 5 | Path validation and reading used separate opens. | The original loader preserved canonical paths but not the validated file descriptor. | Opened without symlink traversal, rechecked identity, authorized the canonical identity, and read the same handle. | Security-sensitive local inputs must bind authorization, validation, and consumption to one handle. |
| 6 | Aggregate trusted-input bytes could exceed the pre-process artifact budget. | Individual file caps were not composed into a collection-wide cap before copying. | Added cumulative byte and fixed-entry budget checks in collection loading. | Every per-item limit needs an aggregate budget at the ownership boundary. |
