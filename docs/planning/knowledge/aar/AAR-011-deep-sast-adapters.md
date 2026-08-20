---
aar: AAR-011-deep-sast-adapters
ticket: TICKET-011
pipeline: deep-sast-adapters
status: submitted
opened: 2026-08-19
submitted: 2026-08-20
effectiveness: 5
---

# AAR-011 — Deep SAST adapters and pinned rule provenance

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | CodeQL, Psalm, and Semgrep all create subprocess or filesystem effects. | Yes; every invocation stays behind the sealed code context and no target build is launched. |
| `PR-scorchkit-executor-contract-001` | Two new file-producing wrappers need multi-step process execution. | Yes; extend CodeContext with an owned-invocation seam instead of bypassing the shared executor. |
| `PR-scorchkit-adapter-execution-descriptor-parity-001` | CodeQL emits SARIF and owns a database/report directory; Psalm owns a SARIF report. | Yes; output and temporary-artifact metadata must change with the concrete adapters. |
| `PR-scorchkit-parser-outcome-integrity-001` | PHPStan and many legacy wrappers still conflate bad output with clean output. | Yes; every touched parser uses the existing typed outcome contract. |
| `PR-scorchkit-scoped-tool-artifacts-001` | CodeQL databases and SARIF reports can be large and collide if paths are shared. | Yes; use per-run guards and bounded artifact reads. |
| `PR-scorchkit-canonical-evidence-identity-001` | Scanner-native SARIF is stored as structured evidence. | Yes; reuse recursive canonicalization and length-prefixed identity construction. |
| `PR-scorchkit-public-evidence-revalidation-001` | SARIF messages and properties can contain secret-like values. | Yes; structured results and flow messages are redacted before durable attachment and again at consumption. |
| `PR-scorchkit-default-catalog-explicit-compatibility-001` | PHPStan changes category and two modules join the code registry. | Yes; exact application/compatibility census and profile behavior must remain explicit. |
| `PR-scorchkit-ticket-diff-baseline-001` | TICKET-011 follows the committed TICKET-010 evidence boundary. | Yes; the new DIFF begins at `0113b63` and the next ticket cannot start until this one has a canonical boundary. |
| `PR-scorchkit-focused-mutation-repair-001` | The owner prohibited broad repeat mutation scans after repairs. | Yes; preserve the initial ticket inventory and rerun only named repaired functions if survivors appear. |

## What happened

Planning confirmed that the existing executor and evidence contracts were sufficient extension
points. Implementation added typed depth, outcomes, and flows plus strict adapters without a
parallel SAST engine. CodeQL and Psalm use the same bounded process and owned-artifact seams as
existing tools. Semgrep now resolves an embedded or exactly pinned local pack before process
execution. Scanner-native flow evidence is normalized and redacted at the domain boundary.

The implementation self-review found three current architecture pages with the old registry count
and the old one-shot claim. They now distinguish 24 registered code modules, 23 external wrappers,
and CodeQL's two ordered invocations per applicable language. Independent security critics then
found nine reportable confidentiality, applicability, execution-integrity, process-isolation,
parser, and provenance defects. All nine were repaired; a tenth SARIF driver-label candidate was
rejected as a vulnerability after its actual adapter-owned provenance boundary was traced, then
accepted as parser hardening.

The canonical DIFF mutation inventory selected 521 mutations and exposed 111 survivors. Under the
owner's standing no-repeat direction, only those exact survivors were rerun. The final exact-tree
repair catches 111/111 and reconstructs 421/421 viable outcomes caught, 100 unviable, zero missed,
and 100% MSI. A latent evidence-verifier assumption about cargo-mutants module-level records was
fixed without rewriting the raw evidence or changing mutation inputs. The pre-completion
focused-repair gate passed all 19 applicable lanes with 81.90% line coverage, 1,574 strict tests,
live PostgreSQL integration, CLI/MCP contracts, and the sealed mutation proof.

## Novel findings

- Analyzer applicability is a security claim. Manifest absence cannot suppress Docker, IaC,
  Kubernetes, Solidity, or source-only analyzers, and an empty supported-language declaration
  cannot mean “all languages” when the owned rule pack is narrower.
- A partial scan may remain a useful result, but every public projection must say it is degraded.
  A failed analyzer cannot become a clean CLI checkmark, MCP success claim, or SARIF invocation.
- A passive analyzer is still an execution engine. Target-owned configuration, plugins, autoloaders,
  cache state, and inherited environment must be isolated even when the adapter never launches a
  target build command.
- A digest proves only the bytes that were hashed. File-based scanners must consume an owned copy
  of the same bounded read instead of reopening a mutable pathname.
- Redaction must cover every untrusted finding channel, including descriptions, source-like
  snippets, flow messages, structured evidence, and external-tool failure diagnostics.
- cargo-mutants legitimately represents module-level constant mutations with `function: null`.
  Evidence should preserve that raw shape and use a stable synthetic scope only for accounting.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-finding-channel-redaction-gaps-001` | Realistic credential syntax, flow messages, rule messages, and tool diagnostics could reach durable/public projections without redaction. | Independent confidentiality traces and disposable public-library harnesses. |
| `BF-scorchkit-manifest-only-analyzer-applicability-001` | Root-manifest detection permanently suppressed several artifact analyzers and explicit selection did not recover them. | Registered-module applicability harness. |
| `BF-scorchkit-unsupported-language-clean-coverage-001` | Semgrep's empty language declaration represented an unsupported-language zero-rule run as successful coverage. | Bounded Semgrep stdin fixture and orchestrator trace. |
| `BF-scorchkit-failed-scan-success-projection-001` | Failed module outcomes became an overall clean CLI, MCP, and SARIF assessment. | Public-library failure fixture and SARIF projection. |
| `BF-scorchkit-passive-analyzer-target-config-001` | Psalm could discover target-owned configuration and plugins under a passive subprocess grant. | Process/configuration trace against Psalm's documented discovery behavior. |
| `BF-scorchkit-parser-empty-failure-conflation-001` | PHPStan accepted fatal nonzero exits with empty stdout as a clean scan. | Adapter exit/parser contract review. |
| `BF-scorchkit-pinned-rule-reopen-race-001` | Semgrep verified one read but consumed a later pathname open, breaking digest/content identity. | Inode/content lifetime trace and adapter contract review. |
| `BF-scorchkit-module-mutation-function-null-001` | Focused evidence rejected valid cargo-mutants module-level constant records. | Final evidence verification after the 111-survivor repair. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-untrusted-finding-channel-redaction-001` | Normalize and redact every untrusted description, evidence value, flow message, and tool diagnostic at construction and each durable/public projection. | Protecting only structured evidence or constructor inputs leaves parallel output channels exposed. |
| `PR-scorchkit-analyzer-applicability-artifact-detection-001` | Derive applicability from bounded source/artifact discovery plus exact adapter capabilities; do not treat missing root manifests or empty declarations as proof of coverage. | Applicability decides whether a security control ran and must not silently erase relevant analyzers. |
| `PR-scorchkit-scan-coverage-projection-parity-001` | Project canonical module outcomes and degraded status through CLI, MCP, JSON, reports, and SARIF. | A failed analyzer must never appear as an unqualified clean assessment on another surface. |
| `PR-scorchkit-passive-analyzer-config-isolation-001` | Run passive analyzers with ScorchKit-owned configuration, state, environment, and outputs while disabling target configuration/plugin discovery. | Analyzer configuration can execute target-controlled code even when target builds are forbidden. |
| `PR-scorchkit-verified-artifact-single-read-001` | Make a file-consuming scanner use an owned copy of the same bounded bytes whose digest and schema were verified. | Reopening a mutable path separates recorded provenance from consumed behavior. |
| `PR-scorchkit-module-mutation-evidence-001` | Preserve cargo-mutants `function: null` module records and map them to `<module>` only for nonempty scope accounting. | Raw mutation evidence must remain faithful while verifier schemas accommodate legitimate tool output. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5/5. Recalled rules directly constrained subprocess authorization, artifact ownership, parser
integrity, structured-evidence normalization, catalog selection, and mutation strategy. Independent
inspection found nine material defects before delivery, and every one received a focused repair and
regression. The preserved broad inventory became an exact repair ledger, avoiding a second broad
mutation run while still proving 421/421 viable outcomes caught on the finalized mutation tree.
