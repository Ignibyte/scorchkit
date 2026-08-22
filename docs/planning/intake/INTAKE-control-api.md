---
title: INTAKE-control-api
status: candidate
created: 2026-08-21
ticket:
pipeline_spec:
---

# Versioned provider-neutral control API

## Problem or opportunity

ScorchKit exposes a Rust facade, CLI, local MCP tools, and durable stores, but it has no single
versioned application-service boundary for optional frontends or remote operators. Building UI or
automation directly on CLI output, MCP routing, or database tables would duplicate policy and
integrity decisions.

## Proposed outcome

ScorchKit exposes one local-first control API for configuration resolution, self-description,
engagements, targets, jobs, findings, evidence, modules, reports, and event streams. Later domain
work, including triage, extends the same versioned boundary. CLI, MCP, CI, conversation components,
Rustal, and remote clients adapt the same commands and queries.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a client requests self-description, ScorchKit shall return versioned configuration, command, query, event, module, capability, and result schemas without requiring the client to inspect internal tables or Rust types. | Schema snapshots, compatibility fixtures, and generated-client checks. |
| REQ-002 | When configuration is resolved for a run, ScorchKit shall produce one effective configuration and decision log from safe defaults, organization, project, and run layers, and no later layer shall widen the engagement's target, capability, or effect grants. | Configuration precedence and policy-clamp matrix. |
| REQ-003 | When an API command can cause an effect, ScorchKit shall bind a verified local or remote transport principal and eligible engagement before creating a network client, filesystem traversal, credential handle, or process. | Absence, spoofing, scope, capability, and effect denial tests. |
| REQ-004 | When a job changes state, ScorchKit shall expose bounded ordered progress through a versioned event stream while preserving cancellation, recovery, and terminal-state contracts. | Event ordering, reconnect, lag, cancellation, and recovery tests. |
| REQ-005 | When durable findings or evidence cross the API, ScorchKit shall verify canonical identity and provenance against every duplicated durable projection and fail closed on mismatch. | Corrupt-row and canonical-parity PostgreSQL tests. |
| REQ-006 | When a local API transport starts, ScorchKit shall use an operating-system-protected socket or an explicitly authenticated loopback transport and shall not derive authority from client-supplied identity metadata. | Socket-permission, loopback-authentication, and spoofed-metadata tests. |
| REQ-007 | When no remote transport is explicitly configured, ScorchKit shall expose the API only through a local transport; remote listening shall reuse the authenticated principal, host-validation, and TLS policy established by SK-044. | Startup and transport matrix tests. |

## Scope notes

- In: provider-neutral application service, versioned schemas, authenticated local transport,
  optional HTTP/event adapters, self-description, configuration resolution, canonical durable
  projections.
- Out: frontend implementation, public-by-default listeners, client database access, model
  selection, or authorization through configuration alone.
