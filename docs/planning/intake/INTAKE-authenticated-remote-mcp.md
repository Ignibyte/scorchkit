---
title: INTAKE-authenticated-remote-mcp
status: candidate
created: 2026-08-17
ticket: TICKET-022
pipeline_spec: docs/planning/pipeline/active/authenticated-remote-mcp.spec.md
---

# Authenticated remote MCP transport

## Problem or opportunity

MCP is intentionally local stdio only. Remote exposure without authenticated principals,
principal-to-engagement binding, host validation, and a TLS termination policy would make powerful
application-security effects remotely reachable without a trustworthy authority boundary.

## Proposed outcome

ScorchKit can optionally serve MCP remotely only when a verified transport principal is bound to an
engagement and every request retains the same target, capability, effect, audit, and output bounds
as local operation.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When remote MCP starts without an authenticated transport and declared TLS termination policy, ScorchKit shall refuse to listen. | Startup denial tests. |
| REQ-002 | When a remote request arrives, ScorchKit shall bind the verified principal to an eligible engagement before routing any tool. | Principal and engagement matrix tests. |
| REQ-003 | When client metadata claims a privileged identity, ScorchKit shall retain it as untrusted attribution and shall not grant capabilities from it. | Spoofed-client transport tests. |
| REQ-004 | When a remote tool runs, ScorchKit shall preserve local policy, cancellation, rate, output, redaction, and audit contracts. | End-to-end authorized loopback tests. |

## Scope notes

- In: authenticated transport, principal binding, TLS/host policy, remote lifecycle and audit tests.
- Out: unauthenticated wrappers, public-by-default listeners, agent identity as authorization.
