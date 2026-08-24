---
title: Conversation-native application-security workbench
pipeline_id: 4f250516-2ed5-45b7-885d-e45adfd2ce20
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-032
ticket_doc: docs/planning/tickets/closed/TICKET-032-conversation-workbench.md
aar: docs/planning/knowledge/aar/AAR-032-conversation-workbench.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-032
created: 2026-08-24
---

# Conversation-native application-security workbench — spec

## Intent

Ship an optional, standards-based MCP Apps workbench for the canonical scan-summary, finding,
evidence, triage, and attack-path projections. Hosts without MCP Apps support retain the complete
text and structured MCP contracts. The component is a presentation adapter only: it owns no
authorization, storage, evidence, or host-vendor behavior.

## Scope

- In: one versioned self-contained `ui://` resource; standard MCP Apps capability and tool
  metadata; scan-summary, finding/evidence/triage, and attack-path rendering; ordinary tool-call
  actions; headless parity; accessibility; executable browser, render, and asset-drift gates.
- Out: Rustal or another standalone console, new scanner or model effects, direct control HTTP or
  PostgreSQL access, frontend-owned policy/state, external UI origins, live remote targets, a
  vendor-specific adapter, or a new mutable result contract.

## Acceptance criteria (EARS)

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

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Use the stable MCP Apps extension identifier `io.modelcontextprotocol/ui`, MIME `text/html;profile=mcp-app`, and nested `_meta.ui.resourceUri`. | These are the current provider-neutral standard and are supported by locked `rmcp` 1.8. |
| 2 | Serve one self-contained resource at `ui://scorchkit/conversation-workbench/v1`. | One reviewed template avoids divergent contracts and external asset trust. |
| 3 | Associate `project_status`, `finding_show`, and `correlate_findings`; keep all existing tools and their text/structured results unchanged. | These three validated projections cover the requested views while preserving headless compatibility. |
| 4 | UI actions call existing tools such as `finding_update_status`; no UI-only storage or HTTP endpoint is added. | Existing control authorization remains the sole mutation boundary. |
| 5 | Declare no external CSP domains, dedicated origin, or browser permissions; insert result data through DOM text APIs only. | The workbench needs no ambient network or browser capability. |
| 6 | Use inline vanilla HTML/CSS/JavaScript and no package-manager or framework dependency. | The static view remains reproducible, inspectable, and portable across compliant hosts. |
| 7 | Convert gates 17–19 into executable local Chrome/resource/render/asset checks in delivery modes. | Shipping an interactive component makes the old not-applicable skips false. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-032-conversation-workbench.md`
- AAR: `docs/planning/knowledge/aar/AAR-032-conversation-workbench.md`
- Architecture: `docs/architecture/mcp.md`, `docs/architecture/control-api.md`,
  `docs/architecture/finding-triage.md`, `docs/architecture/source-runtime-correlation.md`

## Phase plan

| Phase | Deliverable | Exit evidence |
|---|---|---|
| 1 Plan | ticket, AAR, spec, notes, recalled knowledge | operator confirmation |
| 2 Design | architecture, file manifest, regression plan | operator confirmation |
| 3 Implement | code per design | self-review |
| 3.5 Inspect | adversarial ledger with dispositions | lead review |
| 4 Validate | tests run and delivery gate green | matching receipt |
| 5 Complete | docs, submitted AAR, archive, closed ticket | archive complete |
| Delivery | gate rerun after archive, commit/PR | matching receipt |
