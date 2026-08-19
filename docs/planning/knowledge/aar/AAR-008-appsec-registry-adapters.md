---
aar: AAR-008-appsec-registry-adapters
ticket: TICKET-008
pipeline: appsec-registry-adapters
status: submitted
opened: 2026-08-17
submitted: 2026-08-17
effectiveness: 5
---

# AAR-008 — Application-security registry and scanner adapter foundation

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Scanner classification and selection precede effect construction. | Yes; it keeps default-catalog narrowing enforceable rather than advisory. |
| `PR-scorchkit-executor-contract-001` | Existing wrappers already share a bounded execution seam. | Yes; the new adapter contract should extend, not replace, that seam. |
| `PR-scorchkit-effect-contract-single-source-001` | MCP hardening already proved the value of one exhaustive behavior inventory. | Yes; adapter metadata must not create a competing inventory. |
| `PR-scorchkit-facade-visibility-preservation-001` | TICKET-007 found that refactors can expose private constructors. | Yes; representative negative visibility tests belong in design. |
| WORK-085 and WORK-093 | Earlier SAST and correlation work reused a deliberately small finding type. | Yes; it justifies deferring schema v2 to a separate ticket. |
| WORK-096 and WORK-116 | Runtime rules and API-spec consumers already provide reusable application seams. | Yes; later DAST tickets should deepen those seams rather than duplicate discovery. |

## What happened

ScorchKit now exposes an application-security catalog by default across CLI, MCP, agent planning,
jobs, and named profiles. The complete legacy registry remains available through explicit module
IDs and compatibility selection, but it cannot enter an implicit application profile. A versioned
adapter contract describes security domain, lifecycle, targets, strongest effect, output,
provenance, and temporary-artifact ownership across all four scanner families.

Nuclei and Semgrep now return typed no-findings, findings, or malformed-output outcomes. External
tool invocations support explicit environment and working-directory policy. Inspection corrected
effect and credential under-classification, output-shape drift, profile-selection bypasses, parser
integrity gaps, and SQLMap's shared temporary directory. No new scanner or effect class was added.

The DIFF gate passed its non-mutation lanes but could not start cargo-mutants because two isolated
workers required 48 GiB of scratch and 32 GiB was available. Under the owner's fixed-functions-only
direction, validation selected the 23 inspection-repaired functions. Sealed evidence caught all 48
viable mutations, classified 28 as unviable, and recorded no misses or timeouts. The focused-repair
gate passed 19 applicable lanes with 79.11% line coverage and 1,469 strict Nextest cases.

## Novel findings

- The existing registry is broad enough that adding tools is now less important than making tool
  relevance, lifecycle stage, effect class, output contract, and provenance machine-readable.
- Compatibility selection and policy authorization are independent. Explicitly naming a legacy
  adapter makes selection intentional but does not grant credential use, exploitation, or any
  other effect.
- Parser success is an evidence-integrity boundary. Syntactically valid but schema-invalid output
  cannot be treated as either a finding or a clean scan.
- Temporary-artifact metadata is only useful when it matches runtime ownership. Shared fixed paths
  violate both descriptor truth and run isolation.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-adapter-output-contract-drift-001` | Descriptor output shapes disagreed with the data consumed by several concrete parsers. | Cross-family descriptor inspection. |
| `BF-scorchkit-explicit-profile-bypass-001` | Explicit module IDs survived an unknown profile because profile validation happened only on the implicit-selection path. | Selector adversarial tests. |
| `BF-scorchkit-ambient-credential-adapter-001` | Prowler and ScoutSuite could inherit ambient cloud credentials without a separate credential-use grant. | Authorization inspection and recording-executor tests. |
| `BF-scorchkit-parser-no-findings-conflation-001` | Schema-invalid or partial Nuclei and Semgrep output could be accepted as findings or reported as no findings. | Malformed-output fixtures and mutation repair. |
| `BF-scorchkit-shared-tool-tempdir-001` | SQLMap used one shared fixed output directory while its descriptor claimed no temporary artifacts. | Artifact-ownership inspection. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-default-catalog-explicit-compatibility-001` | Keep implicit host and profile catalogs application-only; require exact IDs or a named compatibility surface for retained non-core adapters. | Product relevance must be enforced at selection rather than left to agent prompting. |
| `PR-scorchkit-adapter-execution-descriptor-parity-001` | Assert every adapter descriptor's output, effect, provenance, and artifact claims against its concrete invocation and parser. | Machine-readable metadata becomes a security boundary when hosts use it for planning and authorization. |
| `PR-scorchkit-credential-use-separate-grant-001` | Require a separate exact credential-use grant before an external adapter can inherit or receive credentials, even when its scan and subprocess effects are already allowed. | Explicit tool selection and subprocess authority do not imply credential authority. |
| `PR-scorchkit-parser-outcome-integrity-001` | Distinguish no records, valid findings, malformed records, and scanner-reported failure; never convert partial output into a clean result. | A clean scan is a security claim and requires complete valid evidence. |
| `PR-scorchkit-scoped-tool-artifacts-001` | Give each external-tool run scoped owned artifacts and make descriptor ownership match cleanup behavior. | Shared fixed paths allow cross-run contamination and contradict provenance claims. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5/5. The recalled policy, executor, single-inventory, visibility, and focused-repair rules shaped the
delivered design and caught seven material issues before completion. The result narrows Codex's
default security surface without coupling the engine to Codex, preserves explicit compatibility,
and establishes enforceable contracts for the deeper SAST, supply-chain, and DAST work that follows.
