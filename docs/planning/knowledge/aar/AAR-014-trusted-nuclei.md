---
aar: AAR-014-trusted-nuclei
ticket: TICKET-014
pipeline: trusted-nuclei
status: submitted
opened: 2026-08-20
submitted: 2026-08-21
effectiveness: 5 - strong
---

# AAR-014 — Trusted Nuclei templates and application-specific runtime probes

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | The existing wrapper authorizes only at generic process launch. | Yes; it moved descriptor and grant validation ahead of workspace creation. |
| `PR-scorchkit-adapter-execution-descriptor-parity-001` | Nuclei protocol and invocation behavior currently exceed the catalog's one intrusive label. | Yes; the plan requires an exhaustive protocol/effect classifier. |
| `PR-scorchkit-credential-use-separate-grant-001` | Application probes may receive authenticated headers in later profiles. | Yes; credential use remains an independent exact grant. |
| `PR-scorchkit-parser-outcome-integrity-001` | JSONL can be empty because nothing matched or because templates were skipped. | Yes; execution coverage and parser outcome are separate. |
| `PR-scorchkit-scoped-tool-artifacts-001` | Nuclei otherwise discovers home, config, cache, and template state. | Yes; the plan isolates all runtime state and explicit inputs. |
| `PR-scorchkit-secretless-tool-version-probe-001` | The build host requires a new pinned Nuclei install. | Yes; version support must be proven before any credentials exist. |
| `PR-scorchkit-generated-dast-plan-001` | Agent-authored templates could otherwise become executable authority. | Yes; proposed templates are non-executable until external review and signing. |
| ProjectDiscovery Nuclei runtime and protocol documentation | Current flags and protocol capabilities were checked against the primary vendor documentation. | Yes; it justified explicit `-t`, `-duc`, `-dut`, `-ni`, and the HTTP-only first boundary. |

## What happened

- The ambient Nuclei wrapper was replaced with an explicit, versioned local collection. ScorchKit
  verifies the collection manifest, exact template and certificate bytes, native Nuclei signer,
  application-HTTP protocol class, strongest effect, local-state grants, resolved target
  addresses, and pinned Nuclei 3.11.1 before creating the isolated runtime workspace.
- Adapter execution is now a provider-neutral typed contract carried through scan results,
  checkpoints, JSON/MCP, terminal, HTML, PDF, SARIF, and PostgreSQL. Missing inputs, denied
  capabilities, invalid output, and execution failures cannot be reported as a clean scan.
- Adversarial inspection found and repaired same-path reopen races, per-file-only budgeting,
  address authorization after workspace creation, incomplete-status elevation, invocation drift,
  missing-binary evidence, audit, report, and stale registry gaps.
- Validation used the owner-approved focused path. The initial 84-case inspection scope exposed 24
  survivors. Repairs were limited to nine affected functions; the second scope selected 39 cases,
  caught 32, found six unviable, and left one exact 128-byte identity boundary for a one-case
  recheck. The repository-wide mutation inventory remains deferred.

## Novel findings

| ID | Finding | Why it matters |
|---|---|---|
| `BF-scorchkit-trusted-input-reopen-race-001` | Canonical paths were reopened after validation instead of consuming the validated handle. | A local replacement race could make verified identity and consumed bytes disagree. |
| `BF-scorchkit-adapter-incomplete-status-elevation-001` | Module runners could translate typed incomplete adapter evidence into failed/degraded module state. | Public coverage claims could disagree by execution mode and projection. |
| `BF-scorchkit-preprocess-aggregate-budget-gap-001` | Certificate and template files were individually bounded but not accumulated before workspace creation. | Many valid-sized inputs could exceed the complete operation's artifact budget before the subprocess monitor existed. |
| `BF-scorchkit-address-authorization-artifact-order-001` | Resolved addresses were authorized after creating the private tool workspace. | A denied target still caused a local filesystem effect. |
| `BF-scorchkit-compound-guard-mutation-gap-001` | Tests covered rejection families but not each independent side and exact boundary of compound guards. | Changed operators could weaken a fail-closed predicate without changing existing test outcomes. |

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-trusted-input-reopen-race-001` | Validation and consumption used different opens. | Adversarial path-replacement review. |
| `BF-scorchkit-adapter-incomplete-status-elevation-001` | Normal, checkpoint, and phased runners derived terminal state independently. | Three-mode execution-status inspection. |
| `BF-scorchkit-preprocess-aggregate-budget-gap-001` | Per-file limits were mistaken for a complete pre-process budget. | Workspace resource-abuse review. |
| `BF-scorchkit-address-authorization-artifact-order-001` | Workspace creation preceded concrete-address authorization. | Policy-effect ordering review. |
| `BF-scorchkit-compound-guard-mutation-gap-001` | Exact identity, count, path, inode, event, and effect-floor boundaries were under-asserted. | Focused 84-case mutation inventory. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-authorize-validate-consume-one-handle-001` | Bind local-input authorization, validation, and byte consumption to one no-follow file handle and recheck its identity. | Canonical path strings do not close replacement races. |
| `PR-scorchkit-adapter-terminal-state-authority-001` | Derive every module and scan terminal state from the adapter's typed assessment and assert the result plus emitted event in every runner mode. | Status enums alone do not prove that lifecycle and public coverage projections agree. |
| `PR-scorchkit-preprocess-budget-composition-001` | Reserve fixed workspace entries and accumulate all trusted input bytes and entries before creating artifacts or a subprocess. | Runtime artifact monitors cannot bound effects that occur during preflight. |
| `PR-scorchkit-compound-guard-boundaries-001` | Assert each independent predicate and exact accepted/rejected boundary; express disjoint flag sets with typed unions instead of mutation-equivalent bit operators. | Family-level rejection tests can miss single-operator weakening, while equivalent mutants add no behavioral signal. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Planning recall changed the design by separating proposal from approval, requiring two
independent trust checks, and rejecting non-application protocols instead of treating all Nuclei
templates as one intrusive web scan. Adversarial inspection found four distinct production boundary
classes, and focused mutation exposed the fifth at an exact compound-guard boundary. All five were
repaired before delivery, their prevention rules were added to the knowledge index, the real signed
loopback integration passed, and the pre-completion focused-repair gate was green without repeating
a broad mutation inventory.
