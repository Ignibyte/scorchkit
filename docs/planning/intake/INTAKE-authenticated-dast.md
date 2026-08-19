---
title: INTAKE-authenticated-dast
status: candidate
created: 2026-08-17
ticket:
pipeline_spec:
---

# Authenticated schema-driven application DAST

## Problem or opportunity

The current ZAP wrapper performs one unauthenticated quick scan and cannot prove that login state,
role separation, API schemas, crawl phases, or active-scan policy were applied correctly.

## Proposed outcome

ScorchKit will drive ZAP Automation Framework plans against an explicitly registered disposable or
staging application, with bounded anonymous and authenticated personas, schema imports, phase
control, and reproducible redacted HTTP evidence.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an authenticated DAST plan starts, ScorchKit shall verify the target, persona, credential use, and requested passive or active effect against the engagement before launching ZAP. | Denial and executor non-invocation tests. |
| REQ-002 | When OpenAPI or GraphQL input is supplied, ScorchKit shall import only in-scope endpoints and preserve their route and operation identities. | Loopback schema and scope fixtures. |
| REQ-003 | When a persona is configured, ScorchKit shall verify successful authentication before scanning and shall report loss of authentication as a coverage failure. | Anonymous, user, admin, and expired-session fixtures. |
| REQ-004 | When a plan executes, ScorchKit shall separate spider, AJAX spider, passive scan, and active scan phases according to the authorized profile. | Generated-plan golden tests and loopback execution tests. |
| REQ-005 | When ZAP reports an alert, ScorchKit shall preserve redacted request and response evidence, persona, route, alert identity, CWE, confidence, and plan provenance. | ZAP output and evidence-v2 fixtures. |

## Scope notes

- In: ZAP Automation Framework, authentication personas, OpenAPI/GraphQL imports, scan phases,
  scope enforcement, redacted evidence.
- Out: application deployment orchestration, scans of public or unregistered targets, business-logic
  exploitation beyond approved test cases.
