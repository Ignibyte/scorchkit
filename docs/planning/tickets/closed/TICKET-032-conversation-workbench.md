---
title: TICKET-032-conversation-workbench
status: done
ticket_number: 032
type: feature
created: 2026-08-24
closed: 2026-08-24
intake: docs/planning/intake/INTAKE-conversation-workbench.md
pipeline_spec: docs/planning/pipeline/completed/conversation-workbench.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-032
---

# Conversation-native application-security workbench

## Summary

Add an optional provider-neutral MCP Apps workbench that renders the existing canonical scan,
finding/evidence/triage, and attack-path results while keeping every tool complete for headless
clients and routing every action back through ordinary authorized tools.

## Why

SK-049 and SK-053 established one validated application-service and durable triage boundary. The
next roadmap step can now improve inspection and comparison without giving a frontend its own data,
authorization, or effect path.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a host does not negotiate MCP Apps, every selected ScorchKit tool shall retain complete model-readable text and the existing `scorchkit.mcp.tool-result/v1` structured result without requiring the UI resource. | Headless duplex MCP tests compare exact compatibility text and structured results with UI-capable discovery. |
| REQ-002 | When a host negotiates `io.modelcontextprotocol/ui` with the supported MIME type, ScorchKit shall advertise that extension and associate the selected read tools with one versioned `ui://` resource using standard nested tool metadata. | Exact server-capability, tool-inventory, metadata, resource-list, resource-read, MIME, and URI tests. |
| REQ-003 | When the component receives a successful selected-tool result, it shall render only the validated structured result for scan summaries, finding detail, scanner evidence, model analysis, user triage, coverage gaps, and attack paths with those layers visibly distinct. | Representative browser render matrix and canonical-projection source/shape tests. |
| REQ-004 | When a user requests a component action, the component shall issue an ordinary same-server MCP `tools/call` and ScorchKit shall repeat its existing principal, engagement, capability, effect, audit, validation, and concurrency checks before any state change. | Browser action-call E2E plus spoofed-attribution and unauthorized no-write MCP/control regressions. |
| REQ-005 | When host capabilities or display context differ, the component shall branch only on negotiated capabilities and host context, use safe inline fallbacks, and never branch on a host or vendor name. | Capability matrix, source contract, theme/size/browser, and text-only fallback tests. |
| REQ-006 | When a host fetches the UI resource, ScorchKit shall return one bounded self-contained HTML5 document with no external connection/resource/frame origins, no requested browser permissions, and no interpolation of result data into executable markup. | Resource metadata assertions, static security contract, CSP/browser execution, and malicious-text rendering test. |
| REQ-007 | When a keyboard, screen-reader, narrow-screen, high-contrast, or reduced-motion user opens the workbench, the component shall expose semantic headings, labeled controls, focus visibility, status announcements, responsive layout, and non-color-only state labels. | Browser accessibility and responsive-state assertions plus CSS asset-drift gate. |
| REQ-008 | When the delivery gate runs for a tree that ships the workbench, gates 17, 18, and 19 shall execute browser interaction, representative dogfood rendering, and built-asset drift checks instead of reporting web-not-applicable skips. | Gate selftest and DIFF delivery output showing executable PASS results for gates 17–19. |

## Scope

- In: the standard MCP Apps resource/metadata/capability bridge, three canonical result views,
  ordinary tool actions, accessibility, browser/render/asset validation, and documentation.
- Out: Rustal, team identity, direct storage/control HTTP, frontend policy, new effects, remote
  targets, vendor branches, external assets, or a second canonical result contract.

## Locked decisions

- One self-contained provider-neutral MCP Apps resource serves all selected views.
- Existing tool text and structured result contracts remain authoritative and compatible.
- UI actions re-enter existing MCP/control authorization; the view has no privileged channel.
- Delivery uses the ordinary DIFF gate, never the no-argument FULL gate.
- Per the owner's direction to stop repeated broad mutation testing and repair only named
  survivors, the completed zero-survivor DIFF is sealed under
  `.git/scorchkit-mutants-focused-ticket-032`. Pre-completion and post-archive delivery may use
  `--focused-repair` only while its exact mutation-input hash remains unchanged; any mutation-input
  change revokes this scope.

## Recon

- The official MCP Apps standard is stable as of 2026-01-26 and locked `rmcp` 1.8 exposes the
  required extension capabilities, metadata, and resource-content fields.
- Existing canonical projections cover the requested data; no migration or new service is needed.
- The previous web skips must become executable lanes because this ticket ships interactive HTML.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/conversation-workbench.spec.md`

## Log

- 2026-08-24: opened.
- 2026-08-24: locked one standard MCP Apps resource over three existing read tools with headless
  parity, ordinary authorized tool actions, no new listener/storage/result schema, and executable
  delivery gates 17–19.
- 2026-08-24: implementation and adversarial inspection completed; canonical DTO fixture drift
  and a loopback browser-driver starvation bug were repaired before validation.
- 2026-08-24: the completed DIFF gate passed all 22 lanes, recorded 85.62% line coverage and 2,196
  strict cases, and caught all 20 viable mutations in the 25-mutant selection with five unviable
  and zero survivors. No second broad mutation run was needed.
- 2026-08-24: sealed the zero-survivor result for non-mutation delivery reuse at mutation-input
  hash `e115b5cc5e64ceb9c1ec8f8c4c0c40608deb973815cde090b71310bb7c2d8727`; the verifier
  reconstructs 20/20 viable caught and evidence digest
  `f31db49ed364b2e8875997dbc180459fb0f029175eca09f7000670e97aad37d1`.
- 2026-08-24: the pre-completion focused-repair gate passed all 22 lanes and verified the sealed
  evidence without launching cargo-mutants; completion/archive and exact-tree delivery remain.
