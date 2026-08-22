---
title: Add authenticated remote MCP
pipeline_id: 73a09db1-abaa-46f3-a430-8c883f9f5f8b
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-022
ticket_doc: docs/planning/tickets/closed/TICKET-022-authenticated-remote-mcp.md
aar: docs/planning/knowledge/aar/AAR-022-authenticated-remote-mcp.md
created: 2026-08-22
---

# Add authenticated remote MCP — spec

## Intent

Ship SK-044 as an optional authenticated Streamable HTTP MCP host behind a same-host TLS terminator.
Transport credentials select a stable principal and bind it to the immutable configured engagement
before protocol routing; every engine policy and existing local stdio behavior remains authoritative.

## Scope

- In: validated remote-host configuration; trusted-proxy TLS declaration; loopback-only binding;
  environment-indirect bearer credentials and constant-time digest matching; exact
  principal-to-current-engagement bindings; bounded per-principal stateful sessions; path,
  Host/Origin, forwarded-protocol, body, and concurrency guards; remote principal projection;
  startup/shutdown wiring; CLI, loopback, contract, secret, and documentation coverage.
- Out: direct TLS certificates; non-loopback backend listeners; OAuth/OIDC; arbitrary forwarded
  identity headers; multi-engagement selection; tenants/RBAC; remote queue administration; a
  general control API; policy, evidence, scanner, or MCP tool-inventory changes.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When remote MCP is selected without a complete authenticated transport configuration, an eligible configured engagement, and the trusted-reverse-proxy TLS policy, ScorchKit shall fail before binding a listener. | Configuration matrices and startup-denial tests. |
| REQ-002 | When the trusted-reverse-proxy TLS policy is selected, ScorchKit shall accept only a loopback backend bind and shall require one exact HTTPS forwarding assertion on every request. | Bind-address and forwarded-protocol matrix tests. |
| REQ-003 | When a remote request arrives, ScorchKit shall validate its path, Host authority, optional Origin, bounded body, and concurrency budget before MCP protocol routing. | Request-guard and loopback transport tests. |
| REQ-004 | When bearer authentication succeeds, ScorchKit shall derive a stable principal from an environment-backed credential digest and bind it to the exact configured engagement before routing; absent, malformed, duplicate, mismatched, disabled, or expired bindings shall fail closed. | Authentication, secret, binding, and engagement-state matrices. |
| REQ-005 | When a principal creates or uses an MCP session, ScorchKit shall isolate that session from every other valid principal and enforce the configured per-principal session ceiling. | Cross-principal session and capacity tests. |
| REQ-006 | When client initialization metadata claims a privileged identity, ScorchKit shall retain it only as explicitly untrusted attribution and shall never derive the transport principal, engagement, target, capability, or effect from it. | Spoofed-client end-to-end tests. |
| REQ-007 | When a remote tool executes, ScorchKit shall preserve the same target, capability, effect, cancellation, rate, output, redaction, persistence, and audit enforcement used by local MCP. | Authorized and denied loopback tool matrices plus existing contract suites. |
| REQ-008 | When local `scorchkit serve` is used, ScorchKit shall preserve the existing stdio protocol, local-process principal, stateless fallback, and durable-host lifecycle. | Local transport regression tests and CLI contracts. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Keep `serve` as stdio and make `serve --remote` the sole explicit remote selector. | Existing clients remain compatible and remote exposure cannot happen from configuration alone. |
| 2 | Support only same-host `trusted_reverse_proxy` TLS termination with a loopback backend and exact `X-Forwarded-Proto: https`. | This provides an explicit TLS boundary without introducing certificate lifecycle or trusting a network-reachable cleartext hop. |
| 3 | Resolve bounded bearer-token environment references once at startup, retain only SHA-256 digests, and compare digests in constant time. | Credential values stay out of serializable config, diagnostics, logs, and long-lived runtime strings. |
| 4 | Require every binding to name the exact active configured engagement UUID and reject missing, disabled, expired, duplicate, or mismatched bindings before listening. | The current single-engagement architecture can provide an enforceable identity binding without inventing premature tenant selection. |
| 5 | Give every binding its own stateful rmcp service and session manager with a configured ceiling. | Session lookup is intrinsically scoped to the authenticated principal and negotiated client attribution remains available. |
| 6 | Require a fixed `/mcp` path, non-empty Host and Origin allowlists, a body ceiling, and a global in-flight request ceiling before protocol parsing. | Remote input and resource use are bounded, and DNS-rebinding/browser-origin controls are explicit. |
| 7 | Project the host-owned subject as `authenticated_bearer`; keep initialization name/version as `trusted=false`. | Transport authentication and caller-supplied attribution remain visibly separate. |
| 8 | Reuse the existing `ScorchKitServer`, job/webhook services, tool inventory, and engine policy without remote-only business methods. | Remote transport cannot become a parallel authorization or execution path. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-022-authenticated-remote-mcp.md`
- AAR: `docs/planning/knowledge/aar/AAR-022-authenticated-remote-mcp.md`
- Architecture:
  - `docs/architecture/mcp.md`
  - `docs/architecture/config.md`
  - `docs/architecture/agent.md`

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
