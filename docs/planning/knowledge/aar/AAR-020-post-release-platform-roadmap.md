---
aar: AAR-020-post-release-platform-roadmap
ticket: TICKET-020
pipeline: post-release-platform-roadmap
status: submitted
opened: 2026-08-21
submitted: 2026-08-21
effectiveness: 5 - strong
---

# AAR-020 — Document the post-release API extension and frontend roadmap

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-model-access-claim-boundary-001` | The roadmap adds a model-provider candidate after the website established optional Daybreak use. | Yes; model selection remains outside engine authority and output remains labeled analysis. |
| `PR-scorchkit-host-workflow-tool-contract-001` | Conversation UI could be mistaken for a second execution path. | Yes; UI remains a client of typed MCP/API tools and headless operation stays complete. |
| `PR-scorchkit-public-census-contract-001` | Nine new candidate identifiers need one canonical order. | Yes; the roadmap owns the order and links each row to one intake artifact. |
| `PR-scorchkit-durable-canonical-parity-001` | The future API and team suite will project durable findings and evidence. | Yes; candidate requirements call for canonical identity and provenance checks at every API boundary. |
| `docs/architecture/runner.md` | The proposed hook pipeline overlaps existing hooks and events. | Yes; SK-051 evolves the current seam instead of creating a second lifecycle. |
| Rustal source recon | The proposed console could accidentally couple the engine to a separate framework and database. | Yes; the console is an optional API client and may not write ScorchKit storage directly. |

## What happened

- Extended the canonical roadmap from the existing SK-043 through SK-048 queue to a post-release
  SK-049 through SK-057 platform sequence without changing the current delivery order.
- Specified a versioned provider-neutral control API, isolated capability-declared extensions,
  typed run preprocessors and hooks, provider-neutral model-analysis roles, append-only triage,
  conversation-native views, an optional Rustal local console, an authenticated team suite, and a
  signed extension catalog.
- Kept the product local-first and headless-complete. CLI, MCP, conversation views, Rustal, CI, and
  later team clients share one application service and never write canonical storage directly.
- Kept scanner evidence immutable and separated from labeled model analysis, hook proposals, and
  operator dispositions. Engine policy remains the only authority for effects.
- Added one candidate intake with observable EARS requirements for each roadmap row and recorded
  when the currently skipped web gates must become executable delivery checks.
- Adversarial inspection found seven design or documentation defects; all were corrected before
  validation. The fast gate and the 19 applicable DIFF lanes passed without a broad mutation run.

## Novel findings

- A local API still needs an explicit principal-establishment contract. Loopback alone does not
  authenticate a caller, and client-supplied identity metadata cannot authorize effects.
- An extension may request an effect without receiving direct access to canonical persistence.
  Treating storage as an extension capability would let plugins bypass validation, provenance, and
  append-only history.
- The conversation workbench and Rustal console are two projections of the same application
  service, not separate products or execution engines. This keeps local prompt-driven operation
  complete while allowing a fuller suite later.
- UI quality gates should become applicable in the ticket that introduces the executable UI, not
  when an architectural candidate first appears in the roadmap.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Recalled model-access, host-workflow, durable-parity, public-census, and evidence-
provenance rules determined the architecture before the candidate specs were written. Inspection
then caught and fixed an inverted extension flow, an undefined local principal, direct-storage
ambiguity, a potentially exposed Rustal bind, an unnecessary catalog dependency, premature triage
ownership, and Markdown whitespace. The result is an implementation-ready sequence that remains
explicitly unshipped, agent neutral, Codex preferred, policy owned, and local first. Candidate
structure checks, whitespace and pipeline checks, the 14-lane fast gate, and the 19 applicable DIFF
lanes passed without a full or repository-wide mutation campaign.
