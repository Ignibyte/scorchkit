---
title: TICKET-011-deep-sast-adapters
status: done
ticket_number: 011
type: feature
created: 2026-08-19
closed: 2026-08-20
intake:
pipeline_spec: docs/planning/pipeline/completed/deep-sast-adapters.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-011
---

# Deep SAST adapters and pinned rule provenance

## Summary

Ship reproducible fast and deep static-analysis capabilities. The fast path replaces Semgrep's
network-fetched `auto` configuration with a digest-identified local rule pack. The deep path adds
optional CodeQL analysis for explicitly supported no-build languages and Psalm taint analysis for
PHP. Shared SARIF normalization preserves source-to-sink flows, query/rule provenance, confidence,
and redacted scanner-native evidence. Typed module outcomes make unsupported-language coverage
visible, while PHPStan remains available as a distinct correctness signal.

## Why

SK-034 established enforceable adapter contracts and SK-035 established durable evidence. The
existing Semgrep wrapper still downloads an unpinned configuration, language filtering silently
removes analyzers, PHPStan findings are mislabeled as injection vulnerabilities, and no deep
source-flow analyzer exists. Those gaps prevent ScorchKit and its preferred Codex host from making
defensible statements about static-analysis coverage or provenance.

## EARS Requirements

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

## Scope

- In: embedded and digest-pinned local Semgrep rules; CodeQL and Psalm adapters; PHPStan
  reclassification; fast/deep selection; multi-language detection; typed module outcomes; shared
  SARIF/result parsing; full code-flow and structured-evidence preservation; CLI, MCP, facade,
  catalog, doctor, architecture, and operator documentation; deterministic local fixtures.
- Out: hosted commercial SAST services as a required dependency; network query/rule downloads;
  target build-command execution; PHP through CodeQL; runtime validation; automatic installation
  or licensing of third-party tools; source/runtime attack-path correlation owned by SK-040.

## Locked decisions

- The default Semgrep source is a self-contained rule pack embedded in the binary. An operator may
  select an absolute local rule file only with an exact SHA-256 digest; network and registry
  references are not representable as approved sources.
- `quick` remains secrets and dependency analysis. `standard` adds fast source/correctness tools.
  `thorough` and `pentest` add deep source analyzers. A valid explicit module selection may request
  a deep analyzer directly.
- CodeQL initially supports JavaScript/TypeScript, Python, and Ruby because CodeQL can extract
  those languages without running target build commands. It uses bundled query packs with
  `--no-download`. PHP is intentionally unsupported.
- Psalm is the PHP security/taint adapter. PHPStan is reclassified to `correctness` and does not
  receive generic injection metadata.
- CodeQL and Psalm share one strict SARIF decoder. Normalized flow steps are first-class evidence
  data, and the redacted scanner-native result remains attached as structured evidence.
- `ScanResult` retains its compatibility `modules_run` and `modules_skipped` fields and adds a
  defaulted typed outcome collection for run, not-applicable, skipped, and failed states.
- All subprocesses remain behind the policy-gated bounded executor. File-producing analyzers use
  scoped owned directories and bounded reads; ScorchKit does not execute a target build command in
  this ticket.

## Recon

- `src/sast_tools/semgrep.rs` invokes `semgrep scan --config auto`; Semgrep documents that `auto`
  downloads a registry configuration, while a local path uses local rules.
- `src/sast_tools/phpstan.rs` assigns every correctness message medium severity and OWASP A03 and
  treats malformed JSON as a clean result.
- No CodeQL or Psalm adapter is registered. The code registry currently contains 22 modules: 21
  application modules and one explicit ScoutSuite compatibility module.
- `CodeOrchestrator::filter_by_language` removes modules before execution and leaves no typed
  record. Auto-detection returns only the first matching manifest and the CLI does not apply that
  filter to auto-detected languages.
- `FindingRecordV2` has typed primary locations and redacted evidence but no normalized code-flow
  collection or structured-evidence constructor. SARIF output therefore cannot project flows.
- `CodeContext` already provides policy-gated, injectable process execution; `ToolInvocation`
  already supports owned arguments, timeouts, output limits, environment policy, and working
  directories.
- Official CodeQL guidance requires a database-creation step followed by database analysis and
  supports SARIF path results. Its CLI supports `--no-download`; the standard bundle carries core
  query packs. Official Psalm guidance enables taint analysis with `--taint-analysis` and states
  that SARIF reports include taint flow.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/deep-sast-adapters.spec.md`
- Canonical intake: `docs/planning/intake/INTAKE-deep-sast-adapters.md`
- Dependencies SK-034 and SK-035 are closed. No second pipeline is active.

## Log

- 2026-08-19: opened.
- 2026-08-19: plan locked from SK-036 intake after source recon and official scanner-contract
  review; owner delegated next-ticket ordering and directed continued execution.
- 2026-08-20: independent security inspection found nine reportable defects; all were repaired and
  mapped to focused regressions. One SARIF driver-label candidate was rejected as a vulnerability
  after countercontrol review and retained as parser hardening.
- 2026-08-20: the preserved 521-mutant DIFF inventory's exact 111 survivors were repaired and the
  final focused rerun caught 111/111. Sealed reconstruction is 421/421 viable caught with 100
  unviable, zero missed, and 100% MSI; no broad mutation rerun was launched.
- 2026-08-20: the pre-completion focused-repair gate passed 19 applicable lanes with zero failures,
  three named web-only skips, 81.90% line coverage, 1,574 strict tests, PostgreSQL integration, and
  CLI/MCP contracts.
