---
aar: AAR-030-model-analysis
ticket: TICKET-030
pipeline: model-analysis
status: submitted
opened: 2026-08-24
submitted: 2026-08-24
effectiveness: 4 - strong
---

# AAR-030 — Provider-neutral model analysis roles and evaluations

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-provider-consumption-validation-001` | Model adapters are public external-response boundaries. | Yes — exact schema, provider, model, role, and response kind will be revalidated at consumption. |
| `PR-scorchkit-attribution-not-authorization-001` | Provider/model identity can look privileged. | Yes — provenance remains attribution; the engagement independently authorizes every process, service, credential, and scanner effect. |
| `PR-scorchkit-model-access-claim-boundary-001` | Daybreak or another model may be named without being provisioned. | Yes — readiness reports unavailable and ScorchKit never claims, enrolls, selects, or substitutes access. |
| `PR-scorchkit-public-evidence-revalidation-001` | Model text crosses storage and public projections. | Yes — model inputs/output are bounded, normalized, redacted, and revalidated at durable reads. |
| `PR-scorchkit-durable-canonical-parity-001` | Analysis exists in both canonical finding JSON and a child table. | Yes — the plan adds exact identity/schema/time/raw parity validation before public finding projection. |
| `PR-scorchkit-proof-evidence-own-provenance-001` | Model conclusions cite scanner evidence. | Yes — each record binds sorted exact input evidence digests and never creates evidence. |
| `PR-scorchkit-bounded-validator-mutation-table-001` | Roles, locations, limits, and eligibility have many independent branches. | Yes — the regression plan uses direct boundary and invalid-arm tables. |
| `PR-scorchkit-workflow-gap-no-broad-substitution-001` | Missing model capability could be hidden by another model or broader scan. | Yes — no alternative binding is searched and no scanner work is triggered. |
| `docs/architecture/ai.md` and `AAR-004` | The legacy typed provider surface must remain compatible and validates at consumers. | Yes — `[ai]` stays unchanged while the new role layer is separate and disabled by default. |

## What happened

- Added a provider-neutral six-role contract with exact provider/model resolution, closed
  readiness, host/service/local adapters, complete analysis provenance, and a deterministic
  five-class evaluation corpus while preserving legacy `[ai]` behavior.
- Added policy-owned process and service execution with separate credential-use authorization,
  no redirects, mandatory redaction/no retention, bounded time/input/output, and decision events
  before effects.
- Extended append-only analysis storage and public/report projections with independent durable
  child validation while keeping scanner evidence, finding identity, lifecycle, and authority
  unchanged.
- Adversarial inspection repaired public-construction redaction bypasses, evaluation metadata
  drift, serialized-envelope undercounting, durable child ordering/parity, audit coverage, safe
  readiness/report labels, and sensitive bearer-header handling before validation.

## Novel findings

| ID | Finding | Why it matters |
|---|---|---|
| `BF-scorchkit-model-typed-redaction-bypass-001` | Public request and response structs could be directly constructed or deserialized without the redaction performed by safe constructors. | Rust types and constructors improve ergonomics but do not establish a trust boundary; every consumer must reject noncanonical secret-bearing values. |
| `BF-scorchkit-versioned-corpus-metadata-drift-001` | Corpus validation checked version, count, IDs, and class coverage but accepted altered prompts, expected verdicts, and refusal requirements. | A version label cannot prove deterministic evaluation semantics unless every immutable case dimension is pinned. |
| `BF-scorchkit-envelope-overhead-budget-gap-001` | The request byte ceiling summed instructions and input content but omitted JSON framing, evidence digests, and identity metadata. | Field limits can all pass while the actual process or network object exceeds its advertised aggregate ceiling. |
| `BF-scorchkit-analysis-child-order-drift-001` | Durable analysis children were loaded in timestamp order while canonical findings sort them by identity. | A valid append-preserved child set can still produce nondeterministic or noncanonical public root documents when ordering contracts differ. |

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-model-typed-redaction-bypass-001` | Directly constructed input, instruction, summary, and identity fields were not all required to already be canonically redacted. | Adversarial untrusted-value and public-constructor trace. |
| `BF-scorchkit-versioned-corpus-metadata-drift-001` | A modified expected answer retained a valid corpus schema and passed `validate`. | Deterministic evaluation-contract inspection. |
| `BF-scorchkit-envelope-overhead-budget-gap-001` | Aggregate content could stay below 512 KiB while the serialized request crossed 512 KiB. | Resource-ceiling boundary review. |
| `BF-scorchkit-analysis-child-order-drift-001` | Validated storage readback reattached children in an order different from `Finding::canonical_appsec`. | Durable/public projection parity review. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-public-typed-canonical-redaction-001` | Treat public typed structs as constructible without their safe constructors; require canonical redaction again at every consumer, durable, and public boundary. | Public fields and deserialization can bypass constructor normalization. |
| `PR-scorchkit-immutable-corpus-exact-validation-001` | Validate a versioned built-in evaluation corpus against its complete immutable case metadata, expected answers, and refusal requirements, not only schema and class coverage. | Corpus identity must bind evaluation semantics, not just shape. |
| `PR-scorchkit-serialized-envelope-budget-001` | Enforce transport input ceilings over the complete serialized envelope after field-level bounds. | Payload sums omit framing and metadata overhead. |
| `PR-scorchkit-child-projection-canonical-order-001` | Load append-preserved child records in the same unique ordering used by canonical root normalization before reattaching them. | Canonical root and child persistence order must not drift. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Recalled knowledge materially improved the design by requiring exact no-substitution resolution,
consumer-side envelope checks, durable child parity, and policy-owned service access before those
boundaries reached validation. The initial functional tests still missed truth-table seams around
exact ceilings, independent compound predicates, canonical ordering, constants, and thin dispatch.
One completed 287-mutant DIFF exposed those gaps; survivor-only repairs and exact follow-ups then
produced sealed evidence for 253/253 viable mutations caught at 100% MSI. The authenticated
focused-repair gate passed all 19 applicable lanes with no failures and three named web-only skips.
