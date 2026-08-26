---
title: INTAKE-team-suite
status: promoted
created: 2026-08-21
ticket: TICKET-034
pipeline_spec: docs/planning/pipeline/active/team-suite.spec.md
---

# Authenticated multi-user ScorchKit suite

## Problem or opportunity

Local files and PostgreSQL are sufficient for one operator, but a shared service requires tenant
and project isolation, durable queues, object storage, identity, RBAC, quotas, backup, and recovery.
Adding those concerns inside a frontend or remote wrapper would bypass the engine's principal,
engagement, and evidence contracts.

## Proposed outcome

ScorchKit gains an explicit service deployment profile for authorized teams while retaining the
complete local profile. Every remote client uses the same control API, policy kernel, canonical
evidence, and audit model.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a remote user or service authenticates, ScorchKit shall bind the verified principal to an organization, project role, and eligible engagement before returning private data or accepting a command. | Identity, RBAC, anti-enumeration, and engagement matrix. |
| REQ-002 | When two tenants or projects use the service concurrently, ScorchKit shall isolate database rows, queue messages, object artifacts, cache entries, encryption context, and event streams across every read, write, retry, and cleanup path. | Cross-tenant adversarial and corrupt-context tests. |
| REQ-003 | When shared jobs exceed reviewed rate, concurrency, storage, or effect budgets, ScorchKit shall queue, reject, or cancel them predictably without weakening per-engagement authorization. | Quota, fairness, cancellation, and exhaustion tests. |
| REQ-004 | When credentials, evidence, reports, or extension artifacts are stored remotely, ScorchKit shall encrypt, redact, retain, expire, and audit them according to explicit organization and engagement policy. | Secret, retention, key-rotation, and audit fixtures. |
| REQ-005 | When backup, restore, upgrade, rollback, or disaster recovery is rehearsed, ScorchKit shall preserve canonical target, engagement, job, finding, evidence, triage, extension, and audit identities. | Disposable full-stack recovery matrix. |
| REQ-006 | When the service profile is not enabled, ScorchKit shall retain its local CLI/MCP/API and local storage operation without requiring team identity, object storage, or a remote queue. | Local-profile compatibility tests. |

## Scope notes

- In: authenticated service profile, organizations/projects, RBAC, isolation, shared queues, object
  storage, quotas, encryption, retention, audit, backup and recovery.
- Out: public anonymous scanning, direct frontend database access, authorization from agent identity,
  or removing the local deployment profile.
