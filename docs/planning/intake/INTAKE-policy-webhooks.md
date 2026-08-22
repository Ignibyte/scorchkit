---
title: INTAKE-policy-webhooks
status: promoted
created: 2026-08-17
ticket: TICKET-021
pipeline_spec: docs/planning/pipeline/active/policy-webhooks.spec.md
---

# Policy-owned redacted webhook delivery

## Problem or opportunity

Webhook configuration remains readable for compatibility, but delivery is disabled because the old
path did not own network policy, redaction, retry bounds, or queue lifecycle.

## Proposed outcome

Application-security events can be delivered through a policy-owned, redacted, bounded queue that
does not extend scan execution or leak evidence and credentials.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an event is enqueued for webhook delivery, ScorchKit shall redact it before persistence and network construction. | Secret fixtures and stored-record tests. |
| REQ-002 | When a webhook destination is resolved or redirected, ScorchKit shall authorize the hostname and every address through the engagement-owned network policy. | Loopback, redirect, mixed-answer, private, and metadata-address tests. |
| REQ-003 | When delivery fails, ScorchKit shall apply bounded retries outside scan execution and shall expose a terminal delivery state. | Queue timing and exhaustion tests. |
| REQ-004 | When webhook authentication is configured, ScorchKit shall keep credentials out of reports, logs, MCP responses, and persisted payloads. | Cross-sink redaction tests. |

## Scope notes

- In: durable queue, redaction, authorized delivery, bounded retries, delivery audit events.
- Out: arbitrary callbacks from scanner templates, scan-success dependence on webhook availability.
