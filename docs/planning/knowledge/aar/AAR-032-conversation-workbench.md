---
aar: AAR-032-conversation-workbench
ticket: TICKET-032
pipeline: conversation-workbench
status: submitted
opened: 2026-08-24
submitted: 2026-08-24
effectiveness: 4 - strong
---

# AAR-032 — Conversation-native application-security workbench

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-host-workflow-tool-contract-001` | Selected view tools already have exact MCP contracts and executing duplex tests. | Yes — kept the UI as metadata/resource adaptation over existing results. |
| `PR-scorchkit-attribution-not-authorization-001` | UI actions could otherwise look like a trusted human channel. | Yes — all actions use ordinary same-server `tools/call`. |
| `PR-scorchkit-projection-validate-canonical-001` | Finding, triage, and path display cross durable boundaries. | Yes — selected only existing fail-closed public projections. |
| `PR-scorchkit-local-frontend-bind-boundary-001` | A frontend can accidentally create a new listener. | Yes — this ticket adds no listener or direct control client. |
| `AAR-020-post-release-platform-roadmap` | It defined optional frontend and delivery-gate obligations. | Yes — gates 17–19 become executable. |
| Official MCP Apps specification (2026-01-26) | The requested conversation view now has a stable provider-neutral standard. | Yes — avoided vendor metadata and dependencies. |

## What happened

- Added a standards-based, capability-negotiated MCP Apps resource over the existing posture,
  finding, and attack-path tools without changing their text or structured result contracts.
- Kept the resource self-contained and database-free, with restrictive content policy metadata,
  no external assets or browser-owned authority, and all finding changes routed through the
  existing authorized MCP tool.
- Replaced delivery gates 17–19 with executable local-browser interaction, representative-render,
  accessibility, responsive-layout, CSS-digest, and source-policy evidence.
- Adversarial inspection corrected a plausible-looking test fixture and renderer that did not
  follow the exact canonical posture and model-analysis serialization paths.
- The completed DIFF gate passed all 22 lanes, including 85.62% line coverage, 2,196 strict cases,
  authenticated PostgreSQL, browser/render/CSS evidence, and 20/20 viable mutations caught with
  five unviable and zero survivors.

## Novel findings

| ID | Finding | Why it matters |
|---|---|---|
| `BF-scorchkit-ui-fixture-projection-drift-001` | The initial UI fixture and renderer used plausible posture field names and read model analysis from a sibling of the canonical `appsec` envelope. | A browser test can pass against an invented shape while real canonical values silently render as empty. |
| `BF-scorchkit-loopback-harness-event-loop-starvation-001` | A synchronous browser child blocked the same Node process that owned its loopback fixture server. | The child waited for a response that the blocked parent could not serve, turning a deterministic local proof into a timeout. |

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-ui-fixture-projection-drift-001` | Real posture metrics and nested model analysis would have appeared blank even though the original representative fixture passed. | Data-contract and canonical-projection inspection. |
| `BF-scorchkit-loopback-harness-event-loop-starvation-001` | The first browser run timed out before loading its fixture. | Local browser-harness bring-up. |
| `BF-scorchkit-postgres-init-env-auth-drift-001` | The first DIFF attempt stopped before mutation because the local validation role could connect but could not create the disposable release-recovery database. | Authenticated all-feature delivery test; fixed by restoring the required test-role privilege and proving the exact failed case before the one completed DIFF run. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-ui-fixture-canonical-shape-001` | Derive interactive-view fixtures from the exact serialized public DTO and pin every consumed path against the canonical producer contract. | Plausible hand-authored payloads are not evidence that a view renders real application data. |
| `PR-scorchkit-loopback-harness-nonblocking-driver-001` | When a test process owns a loopback fixture server, drive browser or subprocess clients asynchronously so the owner can continue servicing requests. | Synchronous child waits can starve the in-process server and manufacture timeouts. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Recalled knowledge materially kept the workbench as a presentation adapter over existing canonical
MCP results, prevented UI-owned authorization, storage, listeners, and vendor branches, and made the
former browser/render/CSS skips executable before delivery. Inspection still found that a
plausible hand-authored fixture could pass while real canonical values rendered blank, producing a
new exact-DTO fixture rule. The completed 25-mutant DIFF had zero survivors, and its sealed evidence
lets completion prove the unchanged mutation inputs without repeating cargo-mutants.
