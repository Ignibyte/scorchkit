---
aar: AAR-015-source-runtime-correlation
ticket: TICKET-015
pipeline: source-runtime-correlation
status: submitted
opened: 2026-08-21
submitted: 2026-08-21
effectiveness: 5 - strong
---

# AAR-015 — Source-to-runtime attack-path correlation and focused verification

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-canonical-evidence-identity-001` | Attack paths need stable identity across ordering and map serialization. | Yes; path/facet/selection identities will use canonical length-prefixed inputs. |
| `PR-scorchkit-identity-schema-label-parity-001` | A path record and its identity algorithm can evolve independently. | Yes; both schemas are explicit and tested through storage. |
| `PR-scorchkit-finding-observation-transaction-001` | Paths need append-preserved transitions similar to finding evidence. | Yes; storage will lock the path identity and append transitions in one transaction. |
| `PR-scorchkit-untrusted-finding-channel-redaction-001` | HTTP proof and scanner metadata feed path and selector output. | Yes; selectors retain names and routes but never secret values. |
| `PR-scorchkit-scan-coverage-projection-parity-001` | A negative verification can be incomplete or failed. | Yes; coverage is typed and projected instead of collapsed to false. |
| `PR-scorchkit-operation-coverage-method-route-001` | Runtime evidence can name the right URL but wrong operation. | Yes; request selectors and comparability bind method plus normalized route. |
| `PR-scorchkit-adapter-terminal-state-authority-001` | Legacy correlators infer "confirmed" from titles. | Yes; typed path state becomes authoritative and legacy chains stay unverified. |
| `BF-scorchkit-correlation-delimiter-collision-001` | Finding-v2 previously exposed ambiguous concatenated correlation parts. | Yes; the path identity design forbids delimiter joins. |

## What happened

- Added a provider-neutral attack-path contract over canonical finding-v2 records. Stable typed
  facets connect source and runtime members without consulting titles or agent analysis, while
  scanner confidence remains unchanged.
- Reproduced state requires source flow, HTTP evidence bound to its own target revision, shared
  weakness, a precise application facet, and comparable deployment provenance. Missing proof stays
  typed as a gap instead of becoming a clean negative.
- Added inert focused selectors and an append-only verification state machine. Complete comparable
  negatives can mitigate reproduced paths; later comparable proof appends a regressed transition.
- Added identity-locked PostgreSQL storage, canonical MCP output, and validated JSON, terminal, and
  Mermaid reports. Legacy title/module chains remain separately labeled unverified output.
- Adversarial inspection repaired 15 production findings. Focused mutation selected 216 cases in 14
  changed or repaired functions; the exact survivor campaign finished at 216/216 caught and 100%
  MSI without running a repository-wide mutation inventory.

## Novel findings

| ID | Finding | Why it matters |
|---|---|---|
| `BF-scorchkit-evidence-provenance-splice-001` | A current finding revision could be combined with append-preserved HTTP evidence from an older revision. | Individually valid records could falsely prove reproduction in a deployment where the observed runtime behavior never occurred. |
| `BF-scorchkit-transition-audit-erasure-001` | Verification history retained an attempt identity without its outcome, coverage, conditions, and evidence. | An append-only identity is not independently auditable when the state-changing facts cannot be reconstructed. |
| `BF-scorchkit-correlation-cross-product-budget-001` | Finding and result limits did not bound nested finding detail or a nonmatching source/runtime cross-product. | An attacker-controlled inventory could consume unbounded comparison work without ever reaching the result ceiling. |
| `BF-scorchkit-durable-raw-column-divergence-001` | MCP decoded raw finding/evidence JSON without proving parity with duplicated identity, schema, time, and projection columns. | Corrupt or partially updated rows could cross an API boundary as canonical evidence. |
| `BF-scorchkit-method-only-correlation-001` | A shared HTTP method could create a candidate across unrelated application surfaces. | Generic transport attributes are too weak to establish that two observations describe the same path. |
| `BF-scorchkit-report-before-validation-001` | Report helpers projected nested paths before validating their canonical identity and state history. | Tampered durable data could be rendered as trusted attack-path output even when storage invariants were violated. |

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-evidence-provenance-splice-001` | Historical runtime evidence inherited the current parent finding's revision during proof evaluation. | Adversarial provenance trace from durable evidence to reproduced state. |
| `BF-scorchkit-transition-audit-erasure-001` | Transition identity outlived the attempt facts needed to rebuild it. | State-machine and storage round-trip inspection. |
| `BF-scorchkit-correlation-cross-product-budget-001` | Count ceilings covered inputs and outputs but not nested detail bytes or pair evaluations. | Resource-exhaustion inspection. |
| `BF-scorchkit-durable-raw-column-divergence-001` | Raw JSON was treated as authoritative while duplicated durable columns were ignored. | MCP persistence-boundary inspection. |
| `BF-scorchkit-method-only-correlation-001` | Method was classified as a precise shared facet. | False-link correlation matrix. |
| `BF-scorchkit-report-before-validation-001` | Public projections trusted caller-provided nested records. | Report boundary tamper tests. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-proof-evidence-own-provenance-001` | Evaluate every proof condition from the evidence record's own provenance and require explicit comparability before combining records. | Parent or current metadata must not upgrade historical evidence. |
| `PR-scorchkit-transition-audit-reconstruction-001` | Persist every state-changing outcome, coverage decision, condition, evidence reference, and time, and rebuild transition identity on read. | Append-only history is useful only when each transition can be independently verified. |
| `PR-scorchkit-correlation-work-budget-001` | Bound input count, nested detail size, pair evaluations, and output count independently before and during correlation. | No single result limit bounds all work in a many-to-many matcher. |
| `PR-scorchkit-durable-canonical-parity-001` | At durable API boundaries, compare canonical raw JSON with every duplicated identity, schema, time, and projection column and fail closed on divergence. | Redundant storage fields are integrity assertions, not optional caches. |
| `PR-scorchkit-correlation-facet-strength-001` | Classify correlation facets by evidentiary strength; generic method or weakness matches may suggest a candidate but cannot prove reachability alone. | Shared generic properties are common across unrelated application surfaces. |
| `PR-scorchkit-projection-validate-canonical-001` | Validate nested canonical records, ordering, identities, state, and coverage before every public projection. | Rendering is a trust boundary even when persistence validated earlier. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Recalled identity, redaction, transaction, operation-coverage, and typed-state rules
changed the design before implementation by separating weak candidates, reachability, reproduced
proof, and complete comparable negative verification. Adversarial inspection then found six
reusable integrity and resource-boundary patterns, all repaired before delivery. Focused mutation
exposed clause-level observability gaps without repeating a repository-wide run, and the completed
evidence proves 216/216 viable mutations caught at 100% MSI. The pre-completion focused-repair gate
passed all 19 applicable lanes with no failures.
