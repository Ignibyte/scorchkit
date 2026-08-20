---
aar: AAR-012-application-supply-chain
ticket: TICKET-012
pipeline: application-supply-chain
status: submitted
opened: 2026-08-20
submitted: 2026-08-20
effectiveness: 5 - highly effective
---

# AAR-012 — Application supply-chain SBOM and vulnerability evidence

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `CONSTITUTION.md` §§0, 3, 7, 14, 15, 18, 19 | Required pipeline, evidence, test, architecture, inspection, and focused-mutation boundaries. | Yes — fixes phase order and forbids a broad mutation rerun. |
| `SECURITY.md` | Provider, cache, subprocess, credential, redaction, and target authorization invariants. | Yes — separates scan-time offline behavior from refresh effects. |
| `PR-scorchkit-public-mode-dependency-contract-001` | Existing producer/consumer ordering rule. | Yes — requires an explicit Syft barrier through every public mode. |
| `PR-scorchkit-provider-transport-quarantine-001` | Existing native-provider quarantine. | Yes — forbids scanner-owned database and registry traffic. |
| `PR-scorchkit-executor-contract-001` and `PR-scorchkit-adapter-execution-descriptor-parity-001` | Existing bounded process and descriptor contracts. | Yes — drives exact clean-environment invocation tests. |
| `PR-scorchkit-parser-outcome-integrity-001` | Existing malformed-versus-empty rule. | Yes — prevents fatal OSV/Grype/Trivy output from looking clean. |
| `PR-scorchkit-scoped-tool-artifacts-001` | Existing artifact ownership rule. | Yes — makes the SBOM and scanner reports per-run owned files. |
| `PR-scorchkit-provider-consumption-validation-001` | Existing provider-envelope rule. | Yes — requires cache and tool descriptors to be revalidated at use. |
| `PR-scorchkit-public-evidence-revalidation-001` | Existing public projection rule. | Yes — carries incomplete coverage and redaction through every sink. |
| `PR-scorchkit-verified-artifact-single-read-001` | TICKET-011 Semgrep provenance repair. | Yes — consumers receive the exact SBOM bytes that were validated and hashed. |
| TICKET-011 completed notes | Deep-adapter inspection and exact-tree delivery evidence. | Yes — provides the immediate parser, isolation, redaction, and focused-validation baseline. |
| `.git/scorchkit-ticket-012-readiness.md` | Read-only pre-promotion research against official tool contracts and the build host. | Yes — locks tool versions, invocation shapes, cache layout, EARS requirements, and file manifest without contaminating TICKET-011. |

## What happened

- ScorchKit gained agent-neutral application supply-chain contracts for explicit local source,
  archive, and image-layout targets. The ordered service runs OSV against declared lockfiles,
  generates one CycloneDX 1.6 SBOM with Syft, validates and hashes that document, then gives the
  exact accepted bytes to Grype and Trivy.
- Scan-time execution is offline and clean-environment by construction. Provider refresh is a
  separate policy-authorized operation with bounded downloads, typed cache state, checksums,
  structural validation, same-filesystem staging, failure cleanup, and atomic promotion.
- Coverage, gaps, module outcomes, correlations, SBOM identity, and provider snapshot identity now
  survive CLI, MCP, report, SARIF, and PostgreSQL projections. Missing or failed applicable work is
  incomplete, never clean.
- Inspection repaired twelve security, correctness, data-integrity, and simplification findings.
  Validation added direct branch and boundary assertions for the completed DIFF inventory's 211
  survivors without repeating the broad mutation run.
- The final focused evidence caught 211/211 viable mutations at 100% MSI. The delivery gate passed
  19 applicable lanes, including 82.40% line coverage, 1,664 strict Nextest cases, PostgreSQL, and
  CLI/MCP contracts.

## Novel findings

| ID | Finding | Consequence |
|---|---|---|
| `BF-scorchkit-refresh-stage-orphan-001` | An early refresh failure left its staging directory behind. | Reusing the snapshot ID failed, and abandoned provider bytes remained on disk. |
| `BF-scorchkit-aggregate-provider-limit-gap-001` | Each provider object was bounded, but one request could contain unbounded unique downloads. | Aggregate network and disk effects could exceed the policy owner's intended operation budget. |
| `BF-scorchkit-tool-report-file-unbounded-001` | Syft and Trivy could write report files outside the bounded process-output channel. | A child process could grow an owned artifact until exit despite the executor's stdout/stderr limit. |
| `BF-scorchkit-empty-artifact-profile-success-001` | The quick profile accepted an artifact target while selecting no supply-chain phase. | An unsupported target/profile combination could be reported as a complete clean assessment. |

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-refresh-stage-orphan-001` | Refresh staging ownership transferred only on success but had no cleanup guard for earlier errors. | Adversarial lifecycle review and the failed-refresh reuse fixture. |
| `BF-scorchkit-aggregate-provider-limit-gap-001` | Per-response limits were mistaken for a complete request budget. | Security review of multi-object OSV refresh requests. |
| `BF-scorchkit-tool-report-file-unbounded-001` | File-producing tool modes bypassed the shared bounded output channel. | Process-effect review of Syft and Trivy descriptors. |
| `BF-scorchkit-empty-artifact-profile-success-001` | Profile selection did not assert that every supported public combination selected work or a typed gap. | Exact quick-profile artifact fixture. |
| Validation process | The first focused delivery gate rejected a stale zero-test allowlist entry after `scorchkit-code` gained package-local tests. | Strict Nextest suite inventory. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-offline-scan-refresh-separation-001` | Keep provider refresh outside scan execution; scans consume only explicit validated snapshots. | Scanner defaults otherwise introduce hidden network, telemetry, registry, and credential effects. |
| `PR-scorchkit-single-verified-sbom-001` | Generate one SBOM, validate and hash its bounded bytes once, and give consumers owned copies of those exact bytes. | Recataloging or reopening the source breaks producer/consumer identity and enables provenance drift. |
| `PR-scorchkit-cache-stage-ownership-001` | Give staged cache state an armed cleanup owner and transfer ownership only after verified atomic promotion. | Atomic pointer replacement alone does not clean failed pre-promotion effects. |
| `PR-scorchkit-aggregate-effect-budget-001` | Bound both each external object and the complete operation's object count and cumulative bytes. | Individually bounded effects can still compose into an unbounded request. |
| `PR-scorchkit-source-artifact-coverage-separation-001` | Preserve declared source dependencies and shipped artifact contents as distinct coverage classes and correlate only supplied valid identities. | Merging them invents equivalence and hides gaps between the repository and delivered application. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5 - highly effective. Recalled transport, subprocess, parser, cache, and verified-artifact rules
changed the implementation before delivery: scan-time provider traffic was removed, consumers use
one verified SBOM, failed staging is cleaned, cache identity is revalidated, and incomplete coverage
cannot project as clean. Inspection produced twelve repaired findings, while focused mutation
evidence and the full non-mutation delivery gate supplied exact executable proof.
