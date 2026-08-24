---
title: TICKET-027-control-api
status: done
ticket_number: 027
type: feature
focused_repair: approved
created: 2026-08-23
closed: 2026-08-23
intake: docs/planning/intake/INTAKE-control-api.md
pipeline_spec: docs/planning/pipeline/completed/control-api.spec.md
---

# Add a versioned provider-neutral control API

## Summary

Ship one versioned, provider-neutral application-service boundary for ScorchKit configuration,
engagements, targets, jobs, findings, evidence, modules, reports, and ordered events. Expose it to
library callers and through an explicitly authenticated loopback HTTP transport without allowing a
client, transport, or duplicated database projection to become authorization or evidence truth.

## Why

SK-048 established reproducible releases, so later extensions and frontends can now depend on a
stable shipped contract. Without SK-049, CLI, MCP, future extensions, and optional frontends would
continue binding independently to root internals or PostgreSQL tables and would duplicate policy,
identity, and lifecycle decisions.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a client requests self-description, ScorchKit shall return versioned configuration, command, query, event, module, capability, result, and error schemas without requiring inspection of internal tables or Rust types. | Exact schema snapshots, compatibility fixtures, and an external package consumer test. |
| REQ-002 | When configuration is resolved for a run, ScorchKit shall produce one effective configuration and ordered decision log from safe defaults, organization, project, and run layers, and each later layer shall only retain or narrow targets, capabilities, effects, modules, time, concurrency, and output budgets. | Four-layer precedence, omission, exact-boundary, and widening-denial matrices. |
| REQ-003 | When a command can cause local-state or external effects, ScorchKit shall bind a transport-established principal to the exact enabled, unexpired engagement and complete policy authorization before storage mutation, network-client, filesystem traversal, credential resolution, or process construction. | In-process and HTTP success tests plus missing principal, spoofed metadata, missing/mismatched engagement, target, capability, and effect denial tests at the production service boundary. |
| REQ-004 | When a job is created or changes state or durable progress, ScorchKit shall expose a bounded, monotonically sequenced `scorchkit.control.event/v1` stream with replay, explicit expired-cursor failure, cancellation, recovery, lineage, and terminal-state parity. | Journal/store wrapper contract, event ordering/replay/overflow/reconnect tests, and existing lifecycle regression suite. |
| REQ-005 | When durable findings or evidence cross the API, ScorchKit shall deserialize and normalize the canonical raw record, compare every duplicated identity, schema, provenance, time, parent, and projection field, and fail closed on mismatch. | Fresh-schema PostgreSQL round trips and independently corrupted raw/duplicated projection tests. |
| REQ-006 | When a local HTTP API transport starts, ScorchKit shall require an environment-backed bearer credential, bind only loopback, authenticate before routing, remove credentials before downstream handling, and ignore client-supplied identity metadata for authority. | Startup matrix, constant-time credential match, header scrubbing, spoofing, loopback, and live HTTP contract tests. |
| REQ-007 | When no control transport is explicitly selected, ScorchKit shall open no listener; when any non-loopback or unsupported remote control listener is configured, startup shall fail closed and direct the operator to the existing authenticated MCP profile until team identity and isolation exist. | Default/no-listener and bind-address matrix tests plus configuration documentation. |
| REQ-008 | When CLI, MCP, library, or HTTP clients perform an overlapping control operation, they shall adapt the same application-service command or query and shall never receive a direct canonical storage handle. | Architecture/source contract plus representative CLI/MCP/service parity tests. |
| REQ-009 | When a request, page, result, event, or subscriber reaches a configured bound, ScorchKit shall reject or truncate only at the documented deterministic boundary with a typed versioned error or continuation cursor and shall not allocate an unbounded body, collection, or channel. | Body, page, result, event-journal, subscriber, and serialized-response boundary tests. |

## Scope

- In: a package-owned v1 control contract and self-description; one root application service;
  four-layer narrowing configuration; current engagement and principal projection; project target,
  DAST job, canonical finding/evidence, module, JSON report, and event operations; in-process and
  explicitly authenticated loopback HTTP adapters; bounded pagination and errors; CLI/MCP reuse for
  overlapping operations.
- Out: frontend implementation; direct public listeners; tenant/RBAC or multi-engagement routing;
  OAuth/OIDC or direct TLS; direct client database access; model selection; extension execution;
  triage redesign; making configuration, target registration, or principal metadata authorization.

## Locked decisions

- The package-owned control contract is provider neutral and does not depend on the root
  composition, CLI, MCP, PostgreSQL, or an agent vendor.
- The root application service remains the only owner of composed policy, execution, and durable
  adapters; transports deserialize and authenticate but do not implement business rules.
- Local HTTP is opt-in, loopback-only, and bearer-authenticated from an environment reference.
  Non-loopback control listening remains unsupported until SK-056.
- The active configured engagement is the only eligible engagement in this local-first ticket.
  Authenticated principal identity remains attribution plus binding, never an effect grant.
- Durable findings and evidence are emitted only after canonical raw/projection parity succeeds.
- Event replay is bounded and sequence based; an expired cursor is an explicit typed error rather
  than a silently incomplete stream.
- Development uses `bash bin/gate.sh --fast`. The owner's stopped-campaign direction approves only
  the six original survivor names and the sealed TICKET-027 focused-repair evidence for validation
  and delivery; no additional DIFF, full, or repository-wide mutation campaign is authorized.

## Recon

- Existing `Engine`, `ScanJobService`, `JobStore`, `EventBus`, PostgreSQL CRUD, registry
  descriptors, MCP principal binding, and report projections provide reusable composition seams.
- `JobStore` is the reliable mutation point for job revisions; a bounded journaling decorator can
  observe in-memory and PostgreSQL transitions without treating best-effort broadcast as recovery
  evidence.
- Current finding/evidence writes validate canonical identity, but generic read functions expose
  storage rows without revalidating duplicated projections; the control boundary must add this
  verification before serialization.
- `AppConfig` loads one file and has no layered merge contract. SK-049 needs a separate typed run
  resolution contract that cannot broaden engagement authority or expose secrets.
- Existing remote MCP proves loopback binding, environment-backed bearer verification,
  principal-to-engagement matching, credential scrubbing, and bounded request patterns. Control HTTP
  should reuse those invariants without sharing MCP sessions or accepting client identity headers.
- The workspace allow-list currently names 13 internal packages and must include the new stable
  control-contract package and its exact dependency direction.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/control-api.spec.md`
- Operator directed continuation through roughly SK-052 and explicitly prohibited full mutation
  reruns; DIFF validation is the delivery mode for this ticket.

## Log

- 2026-08-23: opened.
- 2026-08-23: linked and promoted `INTAKE-control-api`; plan confirmed by the operator's standing
  continuation and DIFF-only direction.
