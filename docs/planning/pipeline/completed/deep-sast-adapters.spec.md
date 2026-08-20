---
title: Deep SAST adapters and pinned rule provenance
pipeline_id: 0b212a7e-0791-459a-88bd-e903deef18ab
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-011
ticket_doc: docs/planning/tickets/closed/TICKET-011-deep-sast-adapters.md
aar: docs/planning/knowledge/aar/AAR-011-deep-sast-adapters.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-011
created: 2026-08-19
---

# Deep SAST adapters and pinned rule provenance — spec

## Intent

Replace ambiguous static-analysis coverage with reproducible fast and deep capabilities. Semgrep
uses only digest-identified local rules. Deep profiles add optional offline CodeQL analysis for a
safe no-build language set and Psalm taint analysis for PHP. A shared strict SARIF boundary
preserves paths, flow steps, rule/query provenance, confidence, and redacted scanner-native
evidence. Typed module outcomes explain unsupported languages and other non-run states. PHPStan is
retained as correctness analysis instead of being mislabeled as an injection scanner.

## Scope

- In: Semgrep rule governance; CodeQL and Psalm adapters; PHPStan correction; fast/deep module
  metadata and selection; multi-language detection; typed outcomes; evidence-v2 code flows and
  structured evidence; shared SARIF normalization; CLI/MCP/facade/catalog/doctor/docs changes;
  deterministic fixtures and focused integration contracts.
- Out: hosted SAST dependency; network rule/query downloads; automatic third-party-tool install;
  unapproved target builds; CodeQL PHP; runtime validation; source/runtime correlation; unrelated
  legacy parser migration.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When Semgrep runs through the reproducible profile, ScorchKit shall use a local rule pack, record its SHA-256 identity, and reject automatic, registry, URL, unpinned, or digest-mismatched configuration before process execution. | Configuration, invocation, non-execution, and provenance tests. |
| REQ-002 | When a supported no-build language selects CodeQL in a deep profile, ScorchKit shall create and analyze a scoped bounded database without downloading queries, then preserve SARIF paths and query/tool provenance. | Recording-executor invocation tests and CodeQL SARIF golden tests. |
| REQ-003 | When PHP taint analysis is requested in a deep profile, ScorchKit shall run Psalm separately from PHPStan and preserve every reported source-to-sink flow location. | Profile matrix, recording-executor, and Psalm SARIF flow tests. |
| REQ-004 | When a selected deep analyzer does not support the repository language, ScorchKit shall emit a typed not-applicable outcome that names the detected and supported languages without claiming that the analyzer ran. | Multi-language selection and serialized outcome tests. |
| REQ-005 | When static results are normalized, ScorchKit shall retain every available flow step, rule identity, confidence, and redacted scanner-native result in evidence v2 and SARIF projection. | Core round-trip, shared SARIF parser, redaction, and report tests. |
| REQ-006 | When implicit code profiles are selected, `standard` shall use fast analyzers while `thorough` and `pentest` add deep analyzers; explicit module IDs shall remain available under a valid profile. | Exact profile-selection tests across CLI, facade, and MCP entry points. |
| REQ-007 | When PHPStan reports a defect, ScorchKit shall classify it as correctness, preserve its source location and identifier, and shall not invent a CWE or OWASP security classification. | PHPStan parser, descriptor, and catalog tests. |
| REQ-008 | When CodeQL, Psalm, Semgrep, or PHPStan output is empty, malformed, partial, oversized, or scanner-reported as failed, ScorchKit shall distinguish a valid empty result from an execution or parsing failure and shall clean up every scoped artifact. | Asymmetric parser fixtures, bounded-artifact tests, and descriptor parity tests. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Embed the default Semgrep pack and identify it as `scorchkit-semgrep-appsec/v1` plus its SHA-256 digest. Permit only an absolute local override paired with an exact digest. | Installed binaries remain reproducible; local extension is possible without allowing implicit network fetches. |
| 2 | Keep `quick` as secrets/SCA, make `standard` the fast application-code profile, and reserve CodeQL/Psalm for `thorough`, `pentest`, or valid explicit IDs. | Makes frequent and deep SAST observably different without adding a fifth shared scan-profile name. |
| 3 | Model analyzer depth in the code descriptor and add a `Correctness` category for PHPStan. | Selection and catalog consumers need typed metadata rather than module-ID special cases. |
| 4 | Limit CodeQL's first implicit support set to JavaScript/TypeScript, Python, and Ruby; create databases with no-build mode and analyze bundled security-extended suites with `--no-download`. | These languages do not require ScorchKit to execute untrusted target build commands or fetch query packs. |
| 5 | Run CodeQL and Psalm through owned `ToolInvocation` values with scoped directories, explicit working directories, bounded process output, bounded report reads, and cleanup guards. | File-producing analyzers must match the adapter artifact contract and shared execution safety boundary. |
| 6 | Use one strict SARIF decoder for CodeQL and Psalm and keep legacy parser compatibility helpers only where an existing public helper already exists. | Prevents two subtly different implementations of rule, path, flow, and malformed-output handling. |
| 7 | Add normalized code flows and redacted structured evidence to finding v2 without changing stable finding identity inputs. | Flow changes enrich proof but do not create a new vulnerability identity for the same rule and sink. |
| 8 | Add defaulted typed module outcomes to `ScanResult` while retaining the existing run/skipped fields. | New consumers get accurate coverage; existing serialized results and callers remain readable. |
| 9 | Detect all root-manifest languages, preserve the compatibility primary language, and apply language applicability inside the orchestrator after profile/ID selection. | Multi-language repositories receive explicit per-analyzer coverage instead of first-manifest filtering or silent removal. |
| 10 | Do not download, install, authenticate to, or upload results to any scanner service in this ticket. | Keeps the engine agent-neutral, local, optional, and within the existing passive external-tool effect. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-011-deep-sast-adapters.md`
- AAR: `docs/planning/knowledge/aar/AAR-011-deep-sast-adapters.md`
- Architecture: `docs/architecture/sast.md`, `docs/architecture/application-security-catalog.md`,
  `docs/architecture/application-security-evidence.md`, `docs/architecture/tools.md`

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
