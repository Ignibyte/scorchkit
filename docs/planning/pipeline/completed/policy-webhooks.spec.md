---
title: Restore policy-owned durable webhook delivery
pipeline_id: ce4989ad-6acd-4c9c-a916-6c6821a2979d
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-021
ticket_doc: docs/planning/tickets/closed/TICKET-021-policy-webhooks.md
aar: docs/planning/knowledge/aar/AAR-021-policy-webhooks.md
created: 2026-08-21
---

# Restore policy-owned durable webhook delivery — spec

## Intent

Ship SK-043 as a durable webhook application service: redact eligible security events before they
enter PostgreSQL, authorize all network effects through engagement policy, deliver from a bounded
lease-and-retry worker outside scan execution, and expose sanitized queue and audit state. This
restores the compatibility surface only after replacing the removed sender's unsafe ownership
model.

## Scope

- In: validated destination configuration; explicit webhook policy capability; provider-neutral
  delivery records, state machine, store, and worker; PostgreSQL migration and store; awaited
  durable event-sink seam; pre-persistence redaction and bounds; policy-owned HTTP delivery;
  credential indirection; CLI queue queries and one-shot worker; durable MCP host worker; tests and
  operator documentation.
- Out: arbitrary scanner callbacks or HTTP shapes; direct template network effects; raw response
  persistence; altering scanner evidence; a generic broker; queue mutation through MCP; making
  scan results depend on webhook health; SK-044 remote MCP transport or SK-045 Windows ownership.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When webhook configuration is loaded, ScorchKit shall validate a stable destination identity, an HTTP(S) URL without embedded credentials, bounded queue, payload, timeout, redirect, retry, and backoff settings, and an optional environment-variable reference for authorization. | Configuration unit tests and compatibility fixtures. |
| REQ-002 | When an eligible application-security event is enqueued, ScorchKit shall redact the serialized event before persistence, enforce the payload and pending-queue bounds, and persist only the destination identity and redacted delivery material. | Secret-fixture, oversize-payload, queue-capacity, and stored-record tests. |
| REQ-003 | When a webhook destination is resolved, connected to, or redirected, ScorchKit shall authorize the destination hostname and every resolved address through engagement-owned network policy under an explicit webhook-delivery capability before constructing or continuing the request. | Direct, loopback, private, metadata, mixed-answer, rebinding, and redirect policy tests. |
| REQ-004 | When delivery is due, ScorchKit shall claim work with revision and lease ownership, recover expired claims, process a bounded batch outside scan execution, and transition each item through bounded retries to a visible succeeded or exhausted terminal state. | Store contract, worker timing, conflict, recovery, success, and exhaustion tests. |
| REQ-005 | When webhook authentication is configured, ScorchKit shall resolve the credential only for an authorized claimed attempt and shall keep its value out of queue records, audit records, errors, logs, reports, and MCP or CLI responses. | Missing-secret and cross-sink secret-canary tests. |
| REQ-006 | When enqueue fails, ScorchKit shall retain scan success semantics and publish a sanitized diagnostic; when an attempt fails, ScorchKit shall additionally preserve the sanitized failure in delivery state and immutable audit history. | Scan-lifecycle fault-injection and audit tests. |
| REQ-007 | When a queue record changes, ScorchKit shall persist its new revision and matching audit event atomically, reject stale writers, and expose deterministic list and detail projections. | PostgreSQL transaction, compare-and-swap, ordering, and projection tests. |
| REQ-008 | When a durable host starts with webhook destinations configured, ScorchKit shall attach the durable event sink and run recovery and due-delivery processing; when durable storage is unavailable, it shall reject that webhook-enabled host configuration without disabling ordinary scans. | MCP and CLI host wiring and startup tests. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Queue records persist destination IDs, already-redacted event payloads, and the exact non-secret engagement snapshot that must authorize later attempts. | URL and credential material remain runtime configuration, while asynchronous effects retain their original authority boundary. |
| 2 | Authentication is an environment-variable reference to a complete `Authorization` header; embedded URL credentials are invalid. | Secrets are resolved at the latest useful point and never enter serializable configuration projections. |
| 3 | Every request and redirect uses `Capability::WebhookDelivery` with `EffectClass::ActiveSafe` through `build_service_client`. | Attribution cannot substitute for engagement-owned authorization, including DNS answers and redirects. |
| 4 | Durable enqueueing is an awaited lifecycle sink, while delivery and retry work remain asynchronous to the scan result. | The broadcast event bus is intentionally lossy, but webhook availability must not determine scan success. |
| 5 | Queue writes use revision CAS, recoverable leases, and an audit event in the same transaction. | Concurrency, crash recovery, and operator evidence need one enforceable ownership model. |
| 6 | A delivery reads status metadata only and never persists a remote response body. | A destination's response is untrusted and unnecessary for delivery evidence. |
| 7 | PostgreSQL is required for webhook-enabled production hosts; the in-memory store is test-only. | The feature promises durability and must not silently fall back to process memory. |
| 8 | CLI provides deterministic queue inspection and one-shot due processing; MCP runs the worker but does not add remote queue-mutation tools in this ticket. | Operators get an explicit recovery surface without broadening the current MCP administration boundary ahead of SK-044. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-021-policy-webhooks.md`
- AAR: `docs/planning/knowledge/aar/AAR-021-policy-webhooks.md`
- Architecture:
  - `docs/architecture/runner.md`
  - `docs/architecture/jobs.md`
  - `docs/architecture/hooks.md`
  - `docs/architecture/mcp.md`

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
