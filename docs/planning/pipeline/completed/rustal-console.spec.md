---
title: Add an optional Rustal local operator console
pipeline_id: ee5066c5-5f66-4260-8da8-3e70a0aa9325
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-033
ticket_doc: docs/planning/tickets/closed/TICKET-033-rustal-console.md
aar: docs/planning/knowledge/aar/AAR-033-rustal-console.md
created: 2026-08-24
---

# Add an optional Rustal local operator console — spec

## Intent

Ship the first full local operator frontend above ScorchKit's provider-neutral application service:
a separately built Rustal console with durable navigation, bounded live job updates, canonical
finding/evidence drill-down, and authorized target, run, cancellation, and triage actions. It must
remain an optional client, keep the control bearer server-side, preserve the immutable engagement
as the sole authority ceiling, and add no Rustal edge to ScorchKit core.

## Scope

- In: separate `apps/scorchkit-console` application and lockfile; exact Rustal source preflight;
  typed control HTTP client; loopback-only Rustal startup; engagement, project, target, job,
  finding, evidence, correlation, suppression, and coverage pages; bounded upstream event mirror;
  same-origin browser updates; CSRF/Host/Origin/body enforcement; target, job, and triage commands;
  executable console quality lanes and public/operator documentation.
- Out: persistent engagement mutation; internal ScorchKit Rust service or PostgreSQL access;
  browser-held control bearer; public bind; console sessions/RBAC; multiple principals or
  engagements; direct TLS; OAuth/OIDC; tenant isolation; object storage; marketplace/catalog;
  Rustal in the root workspace graph; new scanner, storage, or effect semantics.

## Acceptance criteria (EARS)

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

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Treat the active engagement as read-only authority and expose only existing target, per-run, job, and triage commands. | `ControlService` is deliberately composed from immutable configuration; a browser form cannot become a new policy writer. |
| 2 | Keep the console in `apps/scorchkit-console`, outside the root workspace, with its own lockfile and an exact sibling-Rustal revision preflight. | The optional local app can use Rustal without making every core build locate or compile Rustal; source drift fails before app execution. |
| 3 | Use `scorchkit-control` DTOs and authenticated loopback HTTP only; never depend on the root crate, database, CLI output, or MCP routing. | The API is the stable client boundary and already revalidates canonical data and policy. |
| 4 | Resolve the bearer from one named environment variable into a sensitive header held only by the server process. | Browser storage, markup, URLs, logs, and error pages must remain credential-free. |
| 5 | Mirror the canonical upstream SSE stream in one bounded background task and expose finite same-origin SSE replay responses to the browser. | Rustal's current response producer must not block; finite replay plus EventSource reconnect preserves monotonic live updates without an unbounded handler. |
| 6 | Require exact Host on every request and exact same-origin Origin plus an unguessable process CSRF token on every mutation. | Loopback alone does not prevent cross-site requests to a local service. |
| 7 | Render escaped server-side HTML and add only a small self-contained enhancement script; no external assets or client-side authorization branch. | Navigation remains useful without JavaScript, CSP stays restrictive, and authority remains server-side. |
| 8 | Use fast checks during implementation, then one DIFF gate; if it produces survivors, repair and rerun only their exact names. | Honors the operator's direction not to repeat an expensive broad mutation campaign. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-033-rustal-console.md`
- AAR: `docs/planning/knowledge/aar/AAR-033-rustal-console.md`
- Intake: `docs/planning/intake/INTAKE-rustal-console.md`
- Architecture: `docs/architecture/control-api.md`, `docs/architecture/workspace.md`,
  `docs/architecture/rustal-console.md`, and Rustal ADR-0014 at sibling revision
  `8b741c4c0e4c87542dea575aea9be9acfa3bf728`.

## Planned architecture

`apps/scorchkit-console` is an independently locked binary crate. Its manifest depends only on the
stable `scorchkit-control` package, Rustal, and client/rendering utilities; it is not a root
workspace member. `bin/console.sh` resolves the repository-relative sibling Rustal checkout,
verifies its exact Git revision and clean API source, and then runs console format, lint, test,
build, or serve commands. Root workspace dependency tests reject any Rustal edge outside the app.

`ConsoleConfig` validates the exact loopback listener, loopback HTTP control base URL, engagement
UUID, response/event/body ceilings, and bearer environment reference before constructing either a
client or a Rustal `App`. The bearer becomes a sensitive `HeaderValue`; custom `Debug` and public
errors expose neither its name nor value. The browser never receives the control URL or bearer.

`ControlClient` builds typed v1 query/command envelopes and validates response schema, request ID,
principal kind, and engagement binding before accepting a result. Pages request bounded first
pages and make truncation/continuation visible. Mutations use the same exact public commands as CLI
and MCP. An upstream SSE worker parses fragmented frames under byte limits, accepts only `control`
or typed `error` events, checks strictly increasing sequence/schema/identity, retains a fixed newest
window, and reconnects with the last accepted sequence under bounded exponential delay.

Rustal routes render a dashboard, project view, job view, and finding/evidence view through compiled
Askama templates. POST routes validate the configured Host, exact Origin, bounded form body, route
UUIDs, and constant-time CSRF token before dispatch. The same-origin `/events` route returns a
finite standard-SSE replay from the bounded mirror, with an explicit reset event when the browser
cursor expired. A small inline script updates job state/progress text and reconnect health only;
all navigation and mutations remain server-rendered forms.

## File manifest

- Add `apps/scorchkit-console/{Cargo.toml,Cargo.lock,README.md}` and
  `apps/scorchkit-console/src/{main,config,client,event_mirror,http,render}.rs`.
- Add compiled templates and self-contained assets under
  `apps/scorchkit-console/{templates,assets}` plus focused fixtures/tests.
- Add `bin/console.sh`; modify `bin/gate.sh` and gate contracts for exact revision, independent app
  formatting/lint/tests, browser interaction, representative render, and CSS/source policy.
- Modify root workspace/source-boundary tests only to prove the app remains outside the core graph.
- Add `docs/architecture/rustal-console.md`; update `README.md`, `SECURITY.md`, `CHANGELOG.md`,
  `docs/architecture/control-api.md`, `docs/planning/ROADMAP.md`, intake, ticket, spec, notes, AAR,
  and knowledge index.

## Regression plan

1. Configuration tables cover IPv4/IPv6 loopback, unspecified/private/public binds, URL credentials,
   query/fragment/path variants, missing/short bearer, zero/oversized limits, and safe diagnostics.
2. Client tests use a loopback mock API to prove exact headers and typed request shapes, response
   request/principal/engagement validation, error preservation/redaction, and every UI command.
3. Event tests fragment every frame boundary, cover CRLF, duplicate/missing fields, oversized
   lines/frames, non-monotonic IDs, cache overflow, expired cursors, reconnect URLs, and typed reset.
4. Handler tests exercise every GET and POST through Rustal's real dispatch stack, proving Host,
   Origin, CSRF, body, route UUID, redirect, API denial, and no-secret output behavior.
5. Render snapshots use asymmetric canonical DTOs and assert distinct evidence, analysis, triage,
   suppression, correlation, degradation, cancellation, and terminal-state regions.
6. Browser interaction navigates dashboard/project/finding/job, receives monotonic mocked events,
   and submits a triage action. Representative render checks desktop/mobile/high-contrast/reduced
   motion; asset policy rejects external URLs, unsafe DOM sinks, and CSS drift.
7. Run `bash bin/console.sh check` and `bash bin/gate.sh --fast` during implementation. Run one
   `bash bin/gate.sh --diff` for validation and the same receipt-producing mode after archive. Do
   not run the no-argument/full gate or repeat a broad mutation inventory.

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
