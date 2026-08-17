---
title: TICKET-006-mcp-contract-hardening
status: done
ticket_number: 006
type: feature
created: 2026-08-17
closed: 2026-08-17
intake:
pipeline_spec: docs/planning/pipeline/completed/mcp-contract-hardening.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-006
---

# Typed MCP contracts and principal-aware tool boundaries

## Summary

Replace ScorchKit's JSON-in-text-only MCP surface with a versioned structured result envelope while
preserving the existing text block for compatible clients. Give every advertised tool one explicit
read, local-state, or external-effect contract; publish conservative MCP annotations; and attach a
transport-derived caller context that is attribution only and never grants scan authorization.

## Why

SK-031 made Codex a first-class host but had to teach its workflows to decode JSON from text because
the server advertises neither output schemas nor complete safety hints. SK-032 fixes that boundary
before the workspace extraction in SK-033 freezes crate direction. It also establishes the principal
seam needed by the future authenticated remote transport without presenting local client metadata as
authentication.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When any advertised MCP tool succeeds, ScorchKit shall return a versioned `structuredContent` object containing the tool identity, tool class, caller context, and semantic result while retaining the prior text payload. | Schema snapshots plus direct-adapter and duplex transport tests. |
| REQ-002 | When a routed MCP tool fails after parameter decoding, ScorchKit shall return a versioned structured error with `isError=true`, caller context, and a terminal-safe message without changing the existing fail-closed decision. | Structured-error contract and authorization-negative tests. |
| REQ-003 | When tools are listed, ScorchKit shall advertise one complete read, local-state, or external-effect classification and conservative `readOnly`, `destructive`, `idempotent`, and `openWorld` annotations for every tool. | Exact 30-tool inventory snapshot and annotation truth-table tests. |
| REQ-004 | When a local MCP request is handled, ScorchKit shall attach a local-process principal context and separately label client implementation metadata as untrusted attribution; neither value shall grant an engagement, target, capability, or effect. | Context construction, spoofing, and no-engagement transport negatives. |
| REQ-005 | When a read-class tool runs, ScorchKit shall not mutate ScorchKit state or start target/external-provider effects; tools that can mutate state or contact external entities shall be classified at the stronger boundary. | Classification review and focused state/effect regressions. |
| REQ-006 | When an MCP client consumes a result through the result adapter or duplex framing, the same version, class, principal, structured payload, text compatibility, and error semantics shall be observable. | Transport-independent adapter/router-inventory suite and duplex MCP suite. |
| REQ-007 | When the MCP contract changes, the Codex plugin workflows and server instructions shall consume structured content when available without adding another authorization or command path. | Plugin contract, instruction review, and workflow documentation tests. |

## Scope

- In: MCP output envelope and output schema; structured tool errors; exact tool-class inventory;
  complete annotations; local caller/principal context; direct-adapter/router-inventory, duplex,
  schema, authorization, and compatibility tests; MCP/plugin/roadmap/operator documentation.
- Out: remote MCP transport, authentication, TLS, host validation, principal-to-engagement mapping
  (SK-037); workspace crate extraction (SK-033); scanner behavior changes; new scan capabilities,
  effects, targets, configuration values, or provider-specific core dependencies.

## Locked decisions

- Preserve the existing tool names, parameters, business handlers, and legacy text payloads.
- Treat active scans and external provider/process calls as external effects even when intended to
  be non-destructive; static annotations are conservative for the strongest accepted profile.
- Treat local stdio process identity as a transport fact, not authentication. Treat client name and
  version as untrusted attribution only.
- Keep engagement policy as the sole authorization source. Principal context cannot widen scope or
  satisfy a missing grant.
- Use the normal DIFF gate once for validation. If it exposes mutation survivors, rerun only the
  repaired functions; do not repeat a broad or full mutation campaign.

## Recon

- `rmcp` 1.8 supports `structuredContent`, generated `outputSchema`, all four standard annotations,
  request-context extraction, and transport-injected typed extensions.
- The rmcp typed-JSON adapter would replace the legacy text payload with the new envelope. A local result adapter is
  therefore required to carry the old text and the new structured object together.
- Request `client_info` identifies the client implementation but is self-asserted. The current
  server is local stdio only, so SK-032 can establish local-process attribution while leaving an
  authenticated extension mandatory for the future remote constructor.
- Existing `do_*` methods already centralize policy and persistence. The MCP router should wrap
  those results rather than duplicate or move business behavior during this contract ticket.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/mcp-contract-hardening.spec.md`

## Log

- 2026-08-17: opened.
- 2026-08-17: plan confirmed by the owner's approved back-to-back SK-029 through SK-033 sequence and
  local-commit direction; remote transport, push, PR, and broad mutation reruns remain out of scope.
- 2026-08-17: implementation and inspection complete; one DIFF baseline selected 54 mutations and
  found two `tool_title` survivors, both caught by the exact repaired-function recheck. The focused
  delivery gate verifies 13/13 viable mutations caught, 100% MSI, and all 19 applicable lanes green.
