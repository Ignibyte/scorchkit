---
title: TICKET-021-policy-webhooks
status: done
ticket_number: 021
type: feature
created: 2026-08-21
closed: 2026-08-22
intake:
  - docs/planning/intake/INTAKE-policy-webhooks.md
pipeline_spec: docs/planning/pipeline/completed/policy-webhooks.spec.md
---

# Restore policy-owned durable webhook delivery

## Summary

Restore webhook delivery as a durable, policy-owned application service. Security events are
redacted before they enter PostgreSQL, delivered by a bounded worker that is independent of scan
success, and exposed through typed queue and audit state without persisting destination secrets.

## Why

Webhook configuration remains readable for compatibility, but the unsafe fire-and-forget sender
was removed because it bypassed the current network-policy, redaction, and lifecycle boundaries.
SK-043 is the first outstanding roadmap item and closes that deliberate product gap without
reviving the old sender's authority or availability assumptions.

## EARS Requirements

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

## Scope

- In: webhook configuration and validation; explicit policy capability; provider-neutral queue and
  audit contracts; PostgreSQL persistence; pre-persistence redaction; event filtering; authorized
  HTTP delivery; bounded worker, leases, retries, and recovery; typed CLI status and worker
  operations; MCP durable-host lifecycle integration; documentation and tests.
- Out: scanner-template callbacks; arbitrary request bodies or methods; treating webhook
  attribution as authorization; modifying raw scanner evidence; making scan success depend on
  webhook availability; a general-purpose message broker; public remote administration of queues.

## Locked decisions

- Queue records contain a stable destination ID, redacted event, and the exact non-secret
  engagement snapshot required for later authorization, never the configured destination URL or an
  authorization value. Runtime configuration remains the only map from an ID to a destination.
- Authentication configuration names an environment variable whose value is the complete
  `Authorization` header; URL userinfo is rejected and authenticated destinations cannot redirect.
- `Capability::WebhookDelivery` with `EffectClass::ActiveSafe` is required for every delivery and
  redirect hop. DNS answers and connection establishment use the existing policy-owned service
  client rather than a webhook-specific network bypass.
- Redaction and payload-size enforcement happen before the first queue-store call. Delivery never
  persists an unredacted intermediate form or a response body.
- PostgreSQL is the durable production store. In-memory storage exists only for deterministic
  contract tests and local composition tests.
- Delivery attempts are asynchronous to scans. Enqueue failures are observable but do not change
  the scan's terminal result.
- Queue updates and audit events share one storage transaction and use revision compare-and-swap;
  leases make abandoned in-flight work recoverable.
- The owner request to finish the next three roadmap tickets is the plan and design confirmation
  for this bounded SK-043 implementation.

## Recon

- The legacy sender posted directly from an event handler and had no durable queue, current
  network-policy ownership, bounded retry lifecycle, or credential-safe audit model. It is prior
  behavior to replace, not code to restore.
- The current event bus is intentionally lossy broadcast telemetry. Durable webhook enqueueing
  therefore needs an explicit awaited sink seam at lifecycle publication points rather than a
  broadcast subscriber that can lag or disappear.
- `build_service_client` already enforces scheme, hostname, DNS-answer, connection, and redirect
  authorization. Webhook delivery should supply a new capability to that shared primitive.
- The job store established the repository's revision/CAS, lease-recovery, event-history, and
  PostgreSQL contract patterns; the delivery queue can reuse those semantics without coupling its
  domain types to the job domain.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/policy-webhooks.spec.md`

## Log

- 2026-08-21: opened.
- 2026-08-21: promoted `INTAKE-policy-webhooks.md` as SK-043 and recorded the owner's next-three
  delivery request as plan and design confirmation.
- 2026-08-22: completed implementation, inspection, and validation; the exact pre-completion DIFF
  gate passed 19 applicable lanes at 84.39% coverage and 97.52% MSI.
