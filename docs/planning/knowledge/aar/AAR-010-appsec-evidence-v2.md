---
aar: AAR-010-appsec-evidence-v2
ticket: TICKET-010
pipeline: appsec-evidence-v2
status: submitted
opened: 2026-08-19
submitted: 2026-08-19
effectiveness: 5
---

# AAR-010 — Version application-security evidence and finding identity

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| PR-scorchkit-store-invariants-falsification-001 | Storage must update identity and evidence history atomically. | Yes — drove the transaction and child-record design. |
| PR-scorchkit-provider-consumption-validation-001 | Agent/provider output is untrusted until consumed. | Yes — kept agent analysis labeled and separate. |
| PR-scorchkit-effect-contract-single-source-001 | Effects have a single provider-neutral contract. | Yes — prevented adapter- or agent-owned domain types. |
| PR-scorchkit-workspace-gate-scope-001 | Delivery scope must match the exact tree. | Yes — requires a post-archive DIFF receipt. |
| PR-scorchkit-facade-visibility-preservation-001 | Extracted core types retain facade identity. | Yes — `Finding` remains the public compatibility type. |
| PR-scorchkit-adapter-execution-descriptor-parity-001 | Adapter contracts describe behavior without owning it. | Yes — provenance enriches output without changing execution effects. |
| PR-scorchkit-parser-outcome-integrity-001 | Malformed tool output is not no-findings. | Yes — parser enrichment preserves typed outcomes. |
| PR-scorchkit-ticket-diff-baseline-001 | Ticket validation is tied to its baseline. | Yes — TICKET-010 starts after committed TICKET-009. |
| PR-scorchkit-focused-mutation-repair-001 | Focused mutation mode is narrowly governed. | Yes — the completed DIFF inventory became the exact repair ledger after the owner stopped repeat broad runs. |
| PR-scorchkit-green-baseline-reuse-001 | Green evidence is reusable only for matching scope/tree. | Yes — each phase records exact focused evidence. |

## What happened

ScorchKit now owns a provider-neutral `scorchkit.finding/v2` application-security observation
contract in `scorchkit-core`. It carries typed locations, scanner provenance, redacted evidence,
stable finding and evidence identities, correlation keys, and separately labeled agent analysis.
The existing `Finding` remains the compatibility facade, and legacy JSON upgrades during
deserialization without deleting old fields.

Semgrep and Nuclei prove source and runtime producer paths. JSON, SARIF, HTML, PDF, terminal, and
PostgreSQL consumers derive from the same canonical record. Migration 009 keeps the current tracked
finding while appending distinct evidence and agent-analysis observations transactionally. Direct
public-field mutation cannot bypass HTTP redaction because serialization and attachment normalize
again.

Adversarial inspection found nondeterministic map hashing, an incorrect stored identity-schema
label, ambiguous delimiter-joined correlation keys, oversized implementation seams, and a public
field redaction bypass. The completed DIFF mutation baseline then exposed 25 under-asserted seams.
The owner stopped repeat broad scans, so validation repaired and reran exactly those survivors. The
sealed result reconstructs 109/109 viable mutations caught, 48 unviable, no survivors, and 100% MSI.
The final non-mutation gate passed all 19 applicable lanes with 79.44% line coverage and 1,494
strict Nextest cases.

## Novel findings

- Stable evidence identity needs canonical structure, not merely stable field selection. A
  `HashMap` serialized through ordinary JSON can change identity even when its semantic content is
  unchanged.
- Record schema and identity algorithm are separate versioned contracts. Persisting the former in
  an identity-schema column prevents safe future algorithm migration.
- Public compatibility fields require normalization at every durable boundary. Constructor-only
  redaction is insufficient while callers can mutate a field before serialization or storage.
- Equivalent cross-scanner findings and distinct scanner evidence have opposite deduplication
  needs: the finding identity converges, while evidence identity retains provenance and payload.
- Mutation assertions are strongest when they observe the immediate branch contract. A downstream
  serde round trip can normalize a faulty first pass and accidentally hide a surviving mutation.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-evidence-map-identity-nondeterminism-001` | Equivalent header maps could hash differently because JSON identity input retained randomized map order. | Adversarial identity review and reversed-order regression. |
| `BF-scorchkit-identity-schema-label-drift-001` | PostgreSQL stored the finding-record schema where the identity-algorithm schema was required. | Migration/storage contract review. |
| `BF-scorchkit-correlation-delimiter-collision-001` | Joined correlation keys could encode different namespace/value partitions as the same byte sequence. | Adversarial identity-boundary construction. |
| `BF-scorchkit-public-evidence-redaction-bypass-001` | A caller could mutate public HTTP evidence fields after construction and serialize raw secret-bearing values. | Direct public-field serialization test. |
| `BF-scorchkit-mutation-incidental-normalization-001` | Round-trip assertions let faulty first-pass redaction and independent deduplication branches survive mutation. | Exact 25-survivor focused rechecks. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-canonical-evidence-identity-001` | Recursively canonicalize unordered structured evidence and length-prefix every identity component before hashing. | Stable identity must depend on semantic content, not map iteration or delimiter placement. |
| `PR-scorchkit-identity-schema-label-parity-001` | Version and persist record schemas and identity algorithms separately, with exact storage round-trip assertions for both labels. | Schema-label drift blocks safe compatibility and algorithm migration. |
| `PR-scorchkit-public-evidence-revalidation-001` | Reapply redaction and normalization whenever public compatibility evidence crosses serialization, finding, report, or persistence boundaries. | Mutable public fields make constructor-only protection incomplete. |
| `PR-scorchkit-finding-observation-transaction-001` | Serialize equivalent finding identities and append distinct evidence/analysis inside one transaction guarded by the identity lock. | Finding convergence must not overwrite observations or permit partial persistence. |
| `PR-scorchkit-mutation-branch-directness-001` | Kill a repaired mutation with an assertion on the immediate branch contract before relying on downstream round trips. | Later normalization can mask an incorrect earlier branch and create incidental coverage. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5/5. Recalled storage, provider, effect, facade, parser, baseline, and focused-repair rules all
changed the delivered design or validation strategy. They kept the core agent-neutral, preserved
compatibility, prevented evidence loss and secret leakage, and turned the broad survivor inventory
into a bounded exact repair proof without rerunning the repository-wide campaign. Inspection and
mutation work found material defects before archival, and every ticket requirement has direct
core, producer, report, storage, or gate evidence.
