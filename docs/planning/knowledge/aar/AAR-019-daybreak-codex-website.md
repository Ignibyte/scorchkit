---
aar: AAR-019-daybreak-codex-website
ticket: TICKET-019
pipeline: daybreak-codex-website
status: submitted
opened: 2026-08-21
submitted: 2026-08-21
effectiveness: 5 - strong
---

# AAR-019 — Position the website around Codex and Daybreak Blue

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-public-census-contract-001` | The website will add new product claims and external documentation links. | Yes; add a dependency-free copy contract rather than relying on visual review alone. |
| `PR-scorchkit-site-executable-scratch-001` | The site still lives on the non-executable shared mount. | Yes; validate an exact local-scratch copy. |
| `PR-scorchkit-proof-evidence-own-provenance-001` | Daybreak reasoning could be mistaken for deterministic scanner evidence. | Yes; make the three-layer boundary explicit. |
| `PR-scorchkit-host-workflow-tool-contract-001` | Codex is becoming the leading public workflow. | Yes; describe only the shipped plugin and MCP boundary. |
| `PR-scorchkit-workflow-gap-no-broad-substitution-001` | Daybreak may not be provisioned on every surface. | Yes; prohibit silent model and scan fallback claims. |
| `AAR-018-public-documentation-sync` | The site was just rebuilt and validated. | Yes; preserve the design and make a narrow positioning change. |
| Official OpenAI Docs | The page needs current Daybreak capabilities and access qualifications. | Yes; link the primary model and Trusted Access pages. |

## What happened

- Repositioned the website hero, navigation, metadata, and main Codex section around an
  agent-neutral engine with Codex as the preferred host and Daybreak Blue as optional defensive
  reasoning for separately approved and provisioned users.
- Added a three-layer explanation: Codex and Codex Security own orchestration and semantic review,
  Daybreak owns optional model reasoning, and ScorchKit owns authorization, deterministic scanner
  execution, evidence, and durable results.
- Added primary OpenAI model and Trusted Access links plus explicit statements that ScorchKit does
  not grant model access, silently select a model, authorize a target through model choice, or turn
  a model conclusion into scanner evidence.
- Added a dependency-free website content contract and synchronized the engine README, Codex plugin
  guide, workflow architecture, roadmap, and changelog.
- The website content check, typecheck, scratch production build, loopback preview, and
  desktop/mobile inspections passed. The exact ScorchKit tree passed the 19-lane DIFF gate.

## Novel findings

- A public model claim has two independent boundaries: who can select the model on which product
  surface, and what authority or provenance that model does not gain inside the engine. Stating
  only that access is approved is insufficient.
- A small source-level content contract can keep changing model-access language, official links,
  metadata, agent neutrality, and evidence provenance synchronized without adding a browser-test
  dependency to a static marketing repository.
- Product positioning is clearest when the host, reasoning model, and evidence engine are shown as
  separate layers instead of describing the model as part of the scanner.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-model-access-claim-boundary-001` | Public host/model claims must distinguish model access and selection from engine authorization and scanner evidence, and link the current official access source. | Model availability is identity and product-surface specific, while ScorchKit authority and evidence must remain deterministic and provider neutral. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Recalled provenance, host-workflow, no-broad-substitution, public-content, and
scratch-build rules determined the design before copy was written. The result makes Codex and
Daybreak prominent without adding an OpenAI dependency or weakening agent neutrality. Four-part
inspection found no reportable issue; the content contract, TypeScript check, production build,
desktop/mobile preview, fast gate, and exact-tree DIFF gate all passed. The DIFF selected no viable
Rust mutations and did not start a full or repository-wide mutation campaign.
