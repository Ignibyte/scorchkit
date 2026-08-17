---
title: Typed MCP contracts and principal-aware tool boundaries
pipeline_id: 3d9a79cb-9135-4523-80ed-d97895e77777
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-006
ticket_doc: docs/planning/tickets/closed/TICKET-006-mcp-contract-hardening.md
aar: docs/planning/knowledge/aar/AAR-006-mcp-contract-hardening.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-006
created: 2026-08-17
---

# Typed MCP contracts and principal-aware tool boundaries — spec

## Intent

Ship a transport-neutral MCP contract layer that returns versioned native structured content without
breaking text-only clients, gives every tool an exact safety/effect classification and annotations,
and carries caller attribution without allowing host identity to bypass ScorchKit engagement policy.
This boundary lands before SK-033 extracts it into a dedicated crate.

## Scope

- In: response/error envelope, legacy text compatibility, output schema, read/state/effect inventory,
  complete tool annotations and metadata, local request principal context, focused MCP/plugin/docs
  changes, schema snapshots, direct-adapter/router-inventory and duplex transport tests,
  authorization negatives.
- Out: remote MCP, authentication/TLS/host validation, principal-to-engagement grants, new scanner
  behavior or effects, non-MCP host rewrites, and workspace extraction.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When any advertised MCP tool succeeds, ScorchKit shall return a versioned `structuredContent` object containing the tool identity, tool class, caller context, and semantic result while retaining the prior text payload. | Schema snapshots plus direct-adapter and duplex transport tests. |
| REQ-002 | When a routed MCP tool fails after parameter decoding, ScorchKit shall return a versioned structured error with `isError=true`, caller context, and a terminal-safe message without changing the existing fail-closed decision. | Structured-error contract and authorization-negative tests. |
| REQ-003 | When tools are listed, ScorchKit shall advertise one complete read, local-state, or external-effect classification and conservative `readOnly`, `destructive`, `idempotent`, and `openWorld` annotations for every tool. | Exact 30-tool inventory snapshot and annotation truth-table tests. |
| REQ-004 | When a local MCP request is handled, ScorchKit shall attach a local-process principal context and separately label client implementation metadata as untrusted attribution; neither value shall grant an engagement, target, capability, or effect. | Context construction, spoofing, and no-engagement transport negatives. |
| REQ-005 | When a read-class tool runs, ScorchKit shall not mutate ScorchKit state or start target/external-provider effects; tools that can mutate state or contact external entities shall be classified at the stronger boundary. | Classification review and focused state/effect regressions. |
| REQ-006 | When an MCP client consumes a result through the result adapter or duplex framing, the same version, class, principal, structured payload, text compatibility, and error semantics shall be observable. | Transport-independent adapter/router-inventory suite and duplex MCP suite. |
| REQ-007 | When the MCP contract changes, the Codex plugin workflows and server instructions shall consume structured content when available without adding another authorization or command path. | Plugin contract, instruction review, and workflow documentation tests. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Preserve legacy text content beside the new native structured result. | SK-031 workflows and generic MCP clients already consume the text JSON. |
| 2 | Own tool class, annotation expectations, and response class in one exhaustive 30-tool contract inventory. | Independent strings in macros and wrappers would drift and could mislabel an effectful tool as read-only. |
| 3 | Classify by strongest possible behavior, not the default profile or happy path. | `scan` may accept pentest effects and `auto_scan` may persist, so optimistic static hints are unsafe. |
| 4 | Local-process principal is transport attribution; client implementation is explicitly untrusted. | MCP initialization metadata is self-asserted and cannot become authorization evidence. |
| 5 | Keep `do_*` business handlers and policy decisions unchanged; adapt only at the router boundary. | Contract migration should not silently alter scans, storage, or authorization. |
| 6 | Reserve authenticated principal extensions and principal-to-engagement binding for SK-037. | No remote transport exists today, and claiming remote enforcement early would create a false security boundary. |
| 7 | Use one normal DIFF mutation pass; repair only named survivors and defer any full campaign. | The owner explicitly stopped repeated broad mutation scans after repairs. |
| 8 | Advertise one shared object-root output schema and preserve a versioned discriminator for each concrete tool result. | Existing domain results do not all derive schema metadata; the envelope gives clients stable routing, provenance, error, and class fields without coupling MCP to every storage/scanner type before SK-033. |
| 9 | Encode routed business failures in the same envelope and leave pre-route parameter failures to rmcp. | A principal and tool contract exist only after successful route/context extraction; inventing them for malformed protocol input would be misleading. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-006-mcp-contract-hardening.md`
- AAR: `docs/planning/knowledge/aar/AAR-006-mcp-contract-hardening.md`
- Architecture: `docs/architecture/mcp.md`, `docs/architecture/agent.md`

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
