---
title: TICKET-022-authenticated-remote-mcp
status: done
ticket_number: 022
type: feature
created: 2026-08-22
closed: 2026-08-22
intake:
  - docs/planning/intake/INTAKE-authenticated-remote-mcp.md
pipeline_spec: docs/planning/pipeline/completed/authenticated-remote-mcp.spec.md
---

# Add authenticated remote MCP

## Summary

Add an optional authenticated Streamable HTTP MCP host behind an explicitly declared same-host TLS
terminator. Every accepted request is bound from a runtime bearer credential to a stable principal
and the configured engagement before rmcp routing, while local stdio behavior remains unchanged.

## Why

SK-032 established a typed local MCP principal contract but deliberately kept the transport on
stdio. SK-044 is the next roadmap item and closes the remote-host gap without treating loopback,
proxy headers, session identifiers, or client-supplied implementation metadata as authorization.

## EARS Requirements

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

## Scope

- In: remote MCP configuration and validation; environment-indirect bearer credentials; hashed
  runtime authentication; principal-to-current-engagement binding; loopback-only trusted proxy
  termination; HTTPS assertion; exact path, Host, and Origin validation; stateful per-principal
  session isolation and ceilings; request body/concurrency bounds; CLI selection; lifecycle,
  contract, loopback, secret, and documentation coverage.
- Out: direct certificate/key termination; non-loopback backend listeners; OAuth/OIDC discovery;
  multi-engagement selection; tenant/RBAC support; client metadata as authority; remote webhook
  queue administration; a general control API; changes to engine policy or scanner evidence.

## Locked decisions

- `scorchkit serve` remains local stdio; `scorchkit serve --remote` is the only remote selector and
  refuses absent or invalid `[mcp.remote]` configuration.
- SK-044 supports only `trusted_reverse_proxy` TLS termination. The backend bind must be loopback,
  and every request must carry exactly one `X-Forwarded-Proto: https` assertion.
- Each bounded binding names a subject, environment-variable token reference, and the exact UUID of
  the one configured engagement. Startup resolves tokens, hashes them, rejects duplicate digests,
  and never retains a serializable credential value.
- Each binding owns a distinct bounded rmcp session manager. A session ID presented with another
  valid credential is unknown, so sessions cannot cross principals.
- rmcp's normalized Host and Origin enforcement remains defense in depth behind ScorchKit's
  pre-routing request guard. Missing Origin is valid for non-browser clients; a supplied Origin must
  match the non-empty allowlist.
- The owner request to finish the next three roadmap tickets confirms this bounded plan and design.

## Recon

- The current host composes one immutable `AppConfig`; binding to its exact engagement ID provides
  a fail-closed principal-to-engagement boundary without prematurely adding multi-tenant config.
- rmcp 1.8 exposes Streamable HTTP request parts to tool handlers and has normalized Host/Origin
  validation, but request authentication, TLS policy, input bounds, principal/session isolation,
  and engagement eligibility remain ScorchKit-owned responsibilities.
- Stateful sessions retain negotiated client implementation metadata. Selecting a separate
  transport service and session manager after bearer verification binds session lookup to the
  authenticated principal without trusting a caller-supplied subject header.
- The existing MCP result envelope already separates transport principal from untrusted client
  attribution; its context extractor can select a host-owned remote principal while preserving the
  local-process default.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/authenticated-remote-mcp.spec.md`

## Log

- 2026-08-22: opened.
- 2026-08-22: promoted `INTAKE-authenticated-remote-mcp.md` as SK-044 and recorded the owner's
  next-three delivery request as plan and design confirmation.
- 2026-08-22: implemented the bounded trusted-proxy transport, credential-derived principals,
  isolated stateful sessions, shared server lifecycle, CLI selector, tests, and operator docs.
- 2026-08-22: adversarial inspection repaired session-allocation leaks, authentication timing,
  engagement-state time-of-check gaps, authorization-header retention, listener lifecycle, and
  independent validation-boundary coverage.
- 2026-08-22: authoritative DIFF validation passed 19 applicable lanes at 84.55% line coverage and
  100% MSI across 147 mutants; strict nextest, PostgreSQL integration, and CLI/MCP contracts passed.
