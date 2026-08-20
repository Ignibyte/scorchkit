---
title: Deep SAST adapters and pinned rule provenance — notes
pipeline_id: 0b212a7e-0791-459a-88bd-e903deef18ab
---

# Deep SAST adapters and pinned rule provenance — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: authorize before subprocesses; route external tools through the injectable
  bounded executor; make adapter descriptors match invocation, output, provenance, and artifacts;
  distinguish malformed output from a valid empty result; own temporary artifacts per run;
  normalize/redact public evidence at consumption; canonicalize structured evidence before hashing;
  keep implicit catalogs application-only; establish a Git boundary before the next ticket; rerun
  only named repaired mutations after an initial ticket inventory.
- Recon: Semgrep uses `--config auto`; PHPStan invents injection metadata and silently accepts bad
  JSON; CodeQL/Psalm do not exist; language filtering deletes modules without an outcome; the
  primary-language detector stops at the first manifest; finding v2 cannot carry normalized flows;
  CodeContext and ToolInvocation already provide the required policy and bounded-process seams.
- Official scanner contracts: Semgrep accepts local file/directory configurations and `auto`
  fetches registry rules. CodeQL uses `database create` then `database analyze`, can emit SARIF path
  results, bundles core query packs, and supports `--no-download`. Psalm uses `--taint-analysis`
  and its SARIF report includes taint flow.
- Operator confirmation: on 2026-08-19 the owner explicitly delegated the next ticket sequence and
  asked ScorchKit work to continue until the roadmap is complete. TICKET-011 remains within the
  already promoted SK-036 intake and adds no network or target-build effect.

## Phase 2 — Design

- Architecture: code-profile selection retains candidates long enough to evaluate applicability.
  The orchestrator compares every selected module's supported languages with all explicitly
  selected or detected project languages and emits a typed outcome before tool availability or
  execution. Fast/deep metadata controls implicit profiles. Runnable modules continue through the
  shared bounded job executor. Semgrep resolves and verifies its local rules before invocation.
  CodeQL creates one owned database and SARIF file per supported language; Psalm creates one owned
  SARIF file from the PHP root. Both feed a strict shared SARIF decoder. Findings carry a typed
  primary source location, normalized ordered code-flow paths, scanner/rule/config provenance, and
  a redacted structured copy of the scanner result. JSON, storage facades, and SARIF reports consume
  the canonical finding record; compatibility fields and stable identity inputs remain intact.
- Security design: default Semgrep rules are embedded and materialized to a scoped file. A local
  override must be absolute, regular, bounded, valid YAML with a `rules` sequence, free of network
  validator directives, and match an exact lowercase SHA-256 digest. Semgrep runs with metrics and
  version checks disabled when supported by the pinned invocation contract. CodeQL receives an
  explicit language, `--build-mode=none`, fixed thread/RAM limits, a bundled query-suite reference,
  and `--no-download`; only JavaScript/TypeScript, Python, and Ruby are implicitly supported.
  Psalm runs from the authorized PHP root with taint analysis enabled. No wrapper invokes a shell,
  target build command, package manager, upload, or remote scanner service. Report files are read
  through a size-bounded helper before their ownership guards drop.
- Compatibility design: add `Correctness` and analyzer-depth metadata without changing existing
  serialized category names. Add `module_outcomes` and `code_flows` as defaulted, omitted-when-empty
  fields; legacy result/finding JSON remains readable. Keep `modules_run` and `modules_skipped` and
  populate both alongside typed outcomes. Keep the existing four shared profile names; `standard`
  becomes observably fast and `thorough`/`pentest` deep for code scans. Add an optional MCP code
  profile defaulting to `standard`. PHPStan's category and invented OWASP label intentionally
  change because the old values are false security claims.
- File manifest — create: `rules/semgrep/scorchkit-appsec.yml` for the embedded fast pack;
  `src/sast_tools/sarif.rs` for shared strict SARIF normalization and bounded artifact reads;
  `src/sast_tools/codeql.rs` and `src/sast_tools/psalm.rs` for deep adapters;
  `tests/fixtures/sast/codeql-path.sarif.json` and `tests/fixtures/sast/psalm-taint.sarif.json` for
  deterministic path/flow evidence; `docs/tools/codeql.md` and `docs/tools/psalm.md` for operator
  setup and limitations.
- File manifest — modify: `crates/scorchkit-config/src/types.rs` for optional digest-pinned local
  Semgrep rules; `crates/scorchkit-code/src/lib.rs` and `src/engine/code_module.rs` for correctness
  and depth metadata; `crates/scorchkit-core/src/{observation,finding,scan_result,lib}.rs` for flows,
  structured evidence, and typed outcomes; `src/engine/code_context.rs` for all-language detection
  and authorized owned invocations; `src/runner/code_orchestrator.rs` for depth/applicability/outcome
  execution; `src/sast_tools/{mod,semgrep,phpstan}.rs` for registration and corrected adapters;
  `src/adapter_catalog.rs` for IDs, SARIF/rule provenance, and scoped artifacts; `src/report/sarif.rs`
  for flow projection; `src/facade.rs`, `crates/scorchkit-cli/src/lib.rs`, `src/cli/runner.rs`,
  `crates/scorchkit-mcp/src/types.rs`, and `src/mcp/tools.rs` for profile propagation;
  `src/cli/doctor.rs`, `tests/external_tool_contract.rs`, `tests/mcp_tools.rs`, and affected
  `ScanResult` fixtures for execution/contract coverage; `README.md`, `CHANGELOG.md`,
  `docs/tools-checklist.md`, `docs/tools/{semgrep,phpstan}.md`, and architecture guides for the
  shipped behavior. Cargo manifests change only if implementation proves an unavailable shared
  dependency is required.
- Regression test plan: verify built-in pack digest stability, local pinned override acceptance,
  automatic/registry/URL/unpinned/mismatched/oversized/validator-bearing rejection before executor
  invocation, and exact Semgrep arguments/provenance. Verify CodeQL language mapping, no-build
  database-create arguments, bounded analyze arguments, `--no-download`, scoped paths, two-step
  order, cleanup, missing/oversized output, and golden SARIF rule/path/flow/provenance. Verify Psalm
  taint invocation, PHP-only applicability, distinct PHPStan execution, cleanup, and golden taint
  flow. Verify PHPStan valid-empty/findings/malformed outcomes, correctness category, source/rule
  provenance, and absence of invented CWE/OWASP data. Verify every flow path/step survives finding
  serde, redaction, canonicalization, and SARIF re-projection; structured map order does not change
  evidence identity. Verify multi-manifest detection and exact quick/standard/thorough/pentest plus
  explicit-ID matrices. Verify typed run/not-applicable/skipped/failed JSON, legacy compatibility,
  merge behavior, CLI output, MCP optional profile, catalog census (23 application plus one code
  compatibility module), doctor entries, and descriptor/invocation parity. Then run focused tests,
  `bash bin/gate.sh --fast`, and the repository's ticket DIFF delivery gate on the exact tree. Do not
  run the full gate. If the initial DIFF inventory finds survivors, repair and rerun only their
  named functions under the owner's standing direction.
- Design risk review: CodeQL SARIF may place rules in driver or extension components and refer to
  artifacts by index; the shared decoder must resolve both or fail explicitly. Multiple code flows
  and thread flows must not be flattened or deduplicated. An empty `results` array is clean only
  when every run and referenced rule/artifact shape is valid and no invocation reports execution
  failure. Scanner-native structured evidence is redacted recursively before identity. Local rule
  validation happens before the subprocess and the test must prove zero recorded invocations on
  rejection. Auto-detected languages are a coverage hint, not authorization; explicit language
  input replaces detection but never widens policy or tool effects.
- Operator confirmation: the owner's 2026-08-19 delegation authorizes this design within SK-036.
  It does not authorize network downloads, hosted services, target builds, a second pipeline, a
  full gate, a broad repeat mutation run, or a commit.

## Phase 3 — Implement

- Files and behavior changed:
  - Added analyzer depth and a correctness category to the code descriptor contract. Code profiles
    now keep `quick` dependency/secret coverage, select fast application analyzers for `standard`,
    and add CodeQL and Psalm for `thorough` and `pentest`. Explicit valid module IDs remain
    selectable. Multi-manifest detection and typed run, skipped, failed, and not-applicable outcomes
    make coverage visible instead of silently deleting unsupported modules.
  - Replaced Semgrep's registry-backed `--config auto` path with an embedded
    `scorchkit-semgrep-appsec/v1` rule pack. An optional local override must be an absolute regular
    file below the size limit, contain a nonempty YAML rules sequence, contain no network
    validators, and match an exact SHA-256 digest before the executor can run. The invocation is
    offline, disables metrics/version checks, requests dataflow traces, owns its materialized rule
    file, and records the pack identity.
  - Added CodeQL for JavaScript/TypeScript, Python, and Ruby. Each applicable extractor receives an
    owned no-build database-create invocation followed by an offline security-extended analysis
    invocation with fixed threads, RAM, timeout, working directory, query suite, SARIF output, and
    `--no-download`. Added separate Psalm PHP taint analysis. Both own scoped artifacts and feed one
    strict size-bounded SARIF decoder.
  - Reclassified PHPStan as correctness with informational severity, retained its identifiers and
    locations, removed invented injection/OWASP metadata, and made malformed output a typed parser
    failure rather than a clean result.
  - Added ordered code-flow paths and recursively redacted structured scanner evidence to evidence
    v2 without changing finding identity. Semgrep dataflow traces and SARIF thread flows retain
    source, propagation, and sink steps. SARIF reporting reprojects every normalized flow.
  - Updated the application catalog, MCP code catalog and request profile, doctor inventory,
    report/result initializers, public re-exports, configuration, fixtures, operator guides,
    architecture guides, README, changelog, and exact module/executor contracts. The resulting code
    registry contains 24 modules: 23 application modules and the explicit ScoutSuite compatibility
    module. Its 23 external wrappers all use the bounded executor; CodeQL owns two ordered
    invocations per selected language and the other 22 are one-shot.
  - Focused evidence through the end of implementation: workspace all-target/all-feature compiler
    check passed; strict workspace all-target/all-feature Clippy passed with warnings denied; 139
    core tests and 4 core doctests passed; 43 config tests passed; 59 SAST unit tests passed; 13
    external-tool contract tests passed; module-census, MCP, code-profile, and SARIF-report focused
    suites passed earlier on the same implementation tree before the final lint-only repairs.
- Design deviations:
  - `facade.rs` and `crates/scorchkit-cli/src/lib.rs` required no changes. Their existing profile
    fields and validation already carry all four shared profile names. The implementation changed
    the code runner and MCP request path where the profile had previously been discarded or fixed.
  - No dependency or Cargo-manifest change was needed. Existing `tempfile`, `serde_json`,
    `serde_yaml`, and SHA-256 support cover the new artifact and parser contracts.
  - Current architecture census pages were added to the documentation edits after self-review found
    three pre-ticket counts and an inaccurate claim that every SAST wrapper was one-shot.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Codex Security / core confidentiality | Source-language punctuation around credential assignments bypassed recursive evidence and code-flow redaction, allowing scanner-controlled secrets into JSON, SARIF, MCP, and persistence. | Medium | Fixed by recognizing assignment-shaped sensitive keys, recursively redacting structured evidence and flow messages, and reapplying normalization at finding construction, serialization, canonicalization, reports, MCP, and storage. Direct source-syntax and projection regressions are green. |
| 2 | Codex Security / execution surfaces | Root-manifest-only language detection suppressed source-only, nested, Docker, IaC, Kubernetes, and Solidity analyzers; the same preflight also overrode an operator's explicit module selection. | Medium | Fixed with bounded deterministic recursive artifact/language discovery, explicit Docker/IaC/Kubernetes/Solidity mappings, and applicability rules that let explicit selection proceed when language is undetected while retaining typed rejection for known unsupported languages. Registered-module regressions cover the affected paths. |
| 3 | Codex Security / adapter integrity | Semgrep declared no supported languages, so repositories outside the embedded pack appeared successfully covered even though Semgrep loaded zero applicable rules. | Medium | Fixed by declaring the exact embedded-pack language set and emitting `not_applicable` for unsupported repositories. Rust and supported-language coverage regressions are green. |
| 4 | Codex Security / result integrity | A failed analyzer still produced an overall successful `ScanResult`; CLI and MCP treated it as clean, while SARIF asserted `executionSuccessful: true` and omitted module outcomes. | Medium | Fixed with a typed degraded execution status, canonical module outcomes in every result projection, explicit CLI/MCP degraded messaging, and SARIF execution metadata that cannot represent a failed analyzer as an unqualified clean assessment. |
| 5 | Codex Security / subprocess boundary | Psalm ran from the target root with default configuration discovery, allowing target-owned `psalm.xml`, plugins, or autoloaders to execute repository code under a passive scan grant. | Medium | Fixed with a ScorchKit-owned temporary configuration, working directory, home/cache state, clean environment, exact report path, and disabled target configuration/plugin/autoloader/XInclude discovery. The invocation contract and focused external-tool integration test are green. |
| 6 | Codex Security / MCP confidentiality | Raw external-tool diagnostics were copied into failure outcomes and successful MCP JSON without secret redaction. | Low | Fixed by redacting failure reasons at the orchestrator boundary and again in the global MCP error/success projection. A tool-failure fixture proves the original secret is absent. |
| 7 | Codex Security / finding confidentiality | Semgrep rule messages bypassed evidence redaction through the public finding description and then reached reports, MCP, and storage. | Low | Fixed by redacting descriptions during finding construction and at every compatibility/canonical consumption boundary. Message-bearing Semgrep and report regressions are green. |
| 8 | Codex Security / parser integrity | PHPStan accepted arbitrary nonzero exits and interpreted empty stdout as a valid clean analysis, so fatal execution could erase coverage. | Low | Fixed by accepting only the documented clean/findings statuses, requiring a valid JSON document even for zero findings, and converting empty, malformed, partial, or fatal output into a typed failure. Parser and invocation regressions are green. |
| 9 | Codex Security / provenance integrity | A pinned local Semgrep pack was hashed and then reopened by pathname, permitting the consumed bytes to differ from the recorded digest. | Low | Fixed by performing one bounded read and giving Semgrep an owned temporary copy of exactly the verified bytes. Digest mismatch, size, validator, and materialization tests are green. |
| 10 | Codex Security / provenance review | The shared SARIF decoder accepted any nonempty driver name and relabeled findings with the fixed adapter identity. | Rejected as security; accepted as hardening | Suppressed as a vulnerability because the fixed adapter-owned invocation and fresh report path—not the self-declared SARIF field—form the provenance boundary. Hardened anyway by requiring the expected CodeQL or Psalm driver and retaining a mismatch regression. |

- Inspection evidence: Codex Security scan `63418d2f-fb18-4ae5-9a59-4aa2cf2b6a6d` closed nine
  reportable findings (five medium, four low) and rejected one provenance candidate after explicit
  countercontrol review. The immutable pre-fix snapshot is
  `codex-security-snapshot/v1:sha256:76b0ac572c4b394e916e3642b4b7480108ab850dd6b58992e4b10ce786696246`.
- Validation method: critics traced core confidentiality, adapter/process boundaries, and public
  CLI/MCP/report/storage surfaces independently. Disposable public-library harnesses reproduced the
  redaction, applicability, failure-status, and SARIF projection defects without launching external
  scanners; one bounded local Semgrep stdin fixture confirmed the unsupported-language coverage
  claim. No remote target or third-party system was scanned.
- Post-repair evidence: formatting and diff whitespace checks passed; workspace all-target,
  all-feature compilation and strict Clippy passed; 148 core unit tests plus four doctests, 65
  adapter tests, seven code-orchestrator tests, ten code-context tests, 28 report tests, the exact
  Psalm integration contract, and focused MCP/facade/dashboard/remediation regressions passed. The
  final fast gate passed 14 applicable lanes with zero failures and eight expected fast-mode skips.

## Phase 4 — Validate

- Focused development evidence on the finalized mutation-input tree:
  - Root library all-feature coverage exercised 1,105 cases, with four existing live-network cases
    ignored by reason. A new exact Semgrep pack-boundary regression failed once because its fixture
    contained an empty rule list; the fixture was corrected to pad the real embedded rule pack and
    the exact regression then passed.
  - `scorchkit-core` passed 153 unit tests and four doctests. The final direct
    `source_value_range` regression passed after closing both remaining arithmetic branches.
  - Strict workspace all-target/all-feature Clippy passed with warnings denied after the final
    mutation assertions. Formatting, shell syntax, and diff-whitespace checks are green.
- Mutation evidence:
  - The preserved canonical DIFF inventory selected 521 mutations across 32 files and 155
    functions: 296 caught, 14 timed out, 111 missed, and 100 unviable. Every non-mutation DIFF lane
    had already passed. The owner directed that this broad inventory not be repeated.
  - Exact inventory reconciliation selected all and only the 111 survivors across 13 repaired
    files and 34 functions. The first focused run caught 109 and exposed two direct
    `source_value_range` branches. An exact two-mutant check caught both after repair. The final
    canonical exact-tree rerun caught 111/111 with no misses, timeouts, or unviable outcomes.
  - Sealed evidence reconstructs 421/421 viable mutations caught, 100 unviable, zero missed, and
    100% MSI at mutation-input SHA-256
    `d9d9e988f41ef0d3d69ef54d19e9f286fcf3360af0ce6318cb8ca91c750af43a`.
  - The focused verifier initially rejected cargo-mutants' valid `function: null` records for
    module-level constant mutations. It now preserves the raw inventory, maps those records to the
    stable `<module>` scope only for accounting, rejects missing or malformed function fields, and
    covers the behavior in its selftest. Verification passes with evidence digest
    `122a958a0f253658ffa9e5392c83607dcb5e1798c9b649c75069478059946848`.
- Gate run and receipt: the pre-completion focused-repair gate passed all 19 applicable lanes with
  zero failures and three named web-only skips. It exercised 1,105 root all-feature cases, passed
  1,574/1,574 strict Nextest cases with six reasoned skips, measured 81.90% line coverage, passed
  the live migrated PostgreSQL and CLI/MCP suites, and verified the sealed evidence without
  launching cargo-mutants. Its exact-tree receipt records `focused-repair` and the evidence digest.
- Documented skips with reasons: the full repository mutation campaign remains deferred by the
  owner and roadmap item SK-047. Browser/UI lanes remain named not-applicable skips because
  ScorchKit has no web UI.

## Phase 5 — Complete

- Docs updated: the changelog, README, application-security catalog/evidence pages, configuration,
  runner, module, SAST, tool, and individual analyzer guides describe the shipped fast/deep
  profiles, offline rule/query provenance, typed coverage outcomes, code flows, and passive
  execution boundaries. The roadmap closes SK-036 with exact validation evidence and promotes
  SK-037 to the head of the remaining queue.
- AAR submitted: `AAR-011-deep-sast-adapters` records the nine repaired security findings, the
  rejected provenance candidate, the 111-survivor repair, six reusable prevention rules, and a
  5/5 effectiveness assessment.
- Archive: this notes/spec pair and TICKET-011 are ready for pipeline-controlled archival. The
  archive invalidates the pre-completion receipt, so delivery reruns the same focused-repair gate
  without launching cargo-mutants.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Repository-controlled secrets survived in source snippets, flow messages, and finding descriptions. | Redaction recognized narrow key/value syntax and did not cover every public finding channel. | Normalize and redact at construction and every JSON, report, MCP, and storage boundary with realistic source-syntax regressions. | `PR-scorchkit-untrusted-finding-channel-redaction-001` |
| 2 | Several application analyzers were silently suppressed or falsely reported as covering unsupported code. | Manifest-only language detection and empty adapter language declarations were treated as authoritative applicability evidence. | Add bounded artifact discovery, exact adapter language declarations, explicit-selection handling, and typed outcomes. | `PR-scorchkit-analyzer-applicability-artifact-detection-001` |
| 3 | Analyzer failures could appear as a clean CLI, MCP, and SARIF result. | Compatibility projections ignored typed failed outcomes and asserted success independently. | Add degraded execution status and project canonical module outcomes through every surface. | `PR-scorchkit-scan-coverage-projection-parity-001` |
| 4 | Psalm could discover target-owned configuration and execute plugins during a passive scan. | The analyzer inherited the target root, environment, and default configuration discovery. | Use ScorchKit-owned configuration, state, environment, and report paths and disable target discovery. | `PR-scorchkit-passive-analyzer-config-isolation-001` |
| 5 | A pinned Semgrep rule file could change between verification and use. | The adapter hashed one open and later passed the original pathname to Semgrep for a second open. | Materialize exactly the single bounded verified read into an owned file used by the scanner. | `PR-scorchkit-verified-artifact-single-read-001` |
| 6 | Focused evidence rejected valid module-level constant mutations. | The verifier assumed cargo-mutants always supplies a function object. | Accept explicit `function: null`, retain the raw record, and use `<module>` only for scope accounting. | `PR-scorchkit-module-mutation-evidence-001` |
