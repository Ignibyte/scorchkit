---
title: TICKET-033-rustal-console
status: done
ticket_number: 033
type: feature
created: 2026-08-24
closed: 2026-08-24
intake: docs/planning/intake/INTAKE-rustal-console.md
pipeline_spec: docs/planning/pipeline/completed/rustal-console.spec.md
---

# Add an optional Rustal local operator console

## Summary

Ship a separate, optional `scorchkit-console` Rustal application for local operators. It renders
engagement posture, projects, registered targets, jobs, findings, evidence, correlation and triage
history, mirrors ordered job events with bounded reconnect, and sends every mutation through the
authenticated v1 control API.

## Why

SK-049 established the versioned application-service boundary, SK-053 added durable triage, and
SK-054 proved optional conversation views. A fuller local console can now reuse those contracts
without becoming a second policy, evidence, job, or storage owner. SK-056 depends on proving this
frontend boundary locally before adding tenants or public hosting.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the console starts, ScorchKit shall require an exact loopback bind, an exact loopback control-API URL, an environment-backed bearer, and the configured engagement identity before Rustal listens. | Startup matrix and non-loopback, malformed URL, absent credential, and engagement negative tests. |
| REQ-002 | When an operator navigates the console, ScorchKit shall render bounded server-side views for engagement posture, projects, targets, jobs, findings, evidence, triage history, suppression state, correlations, and degraded coverage using only validated v1 control responses. | API-client envelope tests, rendered-page snapshots, pagination tests, and representative browser navigation. |
| REQ-003 | When a job event is committed, ScorchKit shall consume the authenticated canonical event stream, retain a bounded mirror, resume from the last exact sequence after a bounded reconnect, and expose monotonic same-origin browser updates without placing the control bearer in browser state. | Fragmented-SSE parser, cursor/reconnect, cache overflow, error/reset, and browser event tests. |
| REQ-004 | When an operator adds or removes a registered target, starts or cancels a job, or changes finding triage, ScorchKit shall validate same-origin Host, Origin, body, route identity, and CSRF inputs before sending the exact authenticated control command and shall render the API decision without inferring authority from the page or session. | CSRF, origin, host, body-bound, spoofing, command-shape, denial, and successful mock-API tests. |
| REQ-005 | When engagement posture is displayed, ScorchKit shall keep the active engagement read-only and shall describe target registration and run selections as restrictions within that authority rather than edits to it. | Copy snapshot, absence-of-engagement-write source contract, and denied out-of-scope target test. |
| REQ-006 | When ScorchKit is built or operated without the console, its root workspace, CLI, MCP, configuration, storage, and execution contracts shall remain complete and shall contain no Rustal dependency edge. | Workspace metadata and dependency-direction contracts plus ordinary headless gate lanes. |
| REQ-007 | When the console dependency or UI changes, ScorchKit shall verify the exact approved Rustal source revision and run console format, lint, test, browser, render, and asset-policy checks as executable delivery evidence. | Console preflight, gate selftest, app tests, browser interaction, representative render, and CSS/source policy lanes. |
| REQ-008 | When control data or diagnostics cross the console, ScorchKit shall bound bodies, pages, frames, mirrored events, rendered fields, and errors and shall not expose bearer credentials, sensitive headers, or unredacted transport failures. | Exact-boundary, oversized-response/frame, redaction, HTML-escaping, and no-secret browser snapshot tests. |

## Scope

- In: separate local Rustal app; typed v1 control client; server-rendered navigation and drill-down;
  bounded canonical event mirror; project-target, job, and triage actions; CSRF/origin/Host checks;
  exact Rustal revision preflight; executable console quality lanes.
- Out: active-engagement mutation; direct database or internal service access; public/non-loopback
  hosting; console-owned authentication or RBAC; tenants; object storage; OAuth/OIDC; direct TLS;
  marketplace/catalog; browser access to the control bearer; a Rustal edge in the core workspace.

## Locked decisions

- The active engagement is immutable API authority. V1 console writes are registered-target,
  per-run, job-lifecycle, and finding-triage commands only.
- The app lives outside the root Cargo workspace and consumes `scorchkit-control` plus the exact
  sibling Rustal source revision. A preflight refuses drift before console build, test, or start.
- The browser talks only to the same-origin console. The server alone owns the control bearer.
- Console startup remains loopback-only until SK-056 supplies tenant identity and isolation.

## Recon

- The control API currently exposes 15 queries and 13 commands, including project/target CRUD,
  DAST job lifecycle, event replay, canonical finding/evidence reads, and durable triage.
- `ControlService` owns immutable shared application configuration and exposes no engagement-write command;
  adding a frontend-only engagement editor would be a false authorization surface.
- Rustal 0.48.0 provides the loopback-default app builder, typed state, server-rendered page seam,
  security middleware, and finite SSE response boundary. Its current source is the sibling commit
  `8b741c4c0e4c87542dea575aea9be9acfa3bf728`; it is not published to crates.io or reachable from
  the configured private Git remote in this environment.
- `rustal-website` and `rustal-brain` already use sibling source dependencies. This console keeps
  that dependency in its separate app manifest and adds an exact-revision preflight instead of
  introducing it into ScorchKit's root workspace.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/rustal-console.spec.md`
- Operator direction: continue to the next ticket, commit completed work, and avoid another broad
  mutation run when only named survivor repair is needed.

## Log

- 2026-08-24: opened.
- 2026-08-24: promoted from `INTAKE-rustal-console`; refined engagement editing to preserve the
  immutable control-authority boundary.
