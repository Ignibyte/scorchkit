---
aar: AAR-022-authenticated-remote-mcp
ticket: TICKET-022
pipeline: authenticated-remote-mcp
status: submitted
opened: 2026-08-22
submitted: 2026-08-22
effectiveness: 5 - strong
---

# AAR-022 — Add authenticated remote MCP

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Required authentication and binding before remote routing without weakening engine checks. | yes |
| `PR-scorchkit-attribution-not-authorization-001` | Kept bearer-derived subject separate from spoofable initialization metadata. | yes |
| `PR-scorchkit-local-api-principal-boundary-001` | Prevented loopback, proxy metadata, or a claimed subject from becoming authentication. | yes |
| `PR-scorchkit-local-frontend-bind-boundary-001` | Constrained the trusted proxy backend to loopback before team isolation exists. | yes |
| `PR-scorchkit-compound-guard-boundaries-001` | Produced an explicit validator/request-guard boundary matrix before implementation. | yes |
| `mcp-contract-hardening.notes.md` | Preserved the exhaustive 39-tool contract and untrusted client attribution model. | yes |

## What happened

- Added an optional `serve --remote` Streamable HTTP MCP host behind a same-host trusted TLS
  reverse proxy while preserving bare `serve` as the existing stdio transport.
- Added provider-neutral bounded configuration, environment-indirect bearer credentials retained
  only as digests, exact principal-to-current-engagement bindings, request guards, and one isolated
  stateful session manager per authenticated principal.
- Reused the local MCP server's immutable engine, policy, jobs, webhook delivery, storage,
  recovery, tools, resources, prompts, and result contracts. Only the transport-owned principal
  differs; negotiated client name/version remains explicitly untrusted attribution.
- Adversarial inspection found ten lifecycle, identity, redaction, timeout, and integrity defects.
  All were repaired before validation, including rejected-initialization session leaks,
  engagement expiry gaps, raw authorization-header retention, and incomplete shutdown.
- The first DIFF mutation run exposed grouped validator and lifecycle tests at 79.05% MSI plus a
  stale exact-suite inventory entry. Direct boundary tables and helper-level lifecycle tests raised
  the final exact-tree result to 100% MSI. All 19 applicable lanes passed at 84.55% line coverage,
  including 1,928 strict-nextest cases, PostgreSQL integration, and CLI/MCP contracts.

## Novel findings

- Authenticating before stateful protocol routing is insufficient unless the selected principal
  also selects the session manager. A shared manager would let a valid credential probe or reuse a
  different principal's session identifier.
- Stateful initialization can allocate server-side session state even when the first response does
  not establish a usable session. Capacity accounting needs rejected-initialization cleanup, not
  only cleanup on explicit protocol deletion.
- Startup binding to an eligible engagement does not close the authorization gap for a long-lived
  remote listener. The immutable engagement must be rechecked during composition and on each
  authenticated request so disablement and expiry take effect without a restart.
- Canonical URL equality can subsume several parsed-component predicates. Keeping overlapping
  clauses obscures the actual trust boundary and creates mutation survivors without adding a new
  denial behavior.
- Serde-only defaults, exact unique collection ceilings, safe Debug projections, and thin async
  lifecycle wrappers require direct mutation observability even when end-to-end behavior is green.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-rejected-mcp-init-session-leak-001` | A malformed first MCP message could allocate a session without returning its ID and permanently consume bounded principal capacity. | Adversarial inspection of rmcp initialization and session accounting. |
| `BF-scorchkit-remote-engagement-expiry-gap-001` | Engagement eligibility was checked during credential preparation but not again at host composition or on later authenticated requests. | Adversarial inspection of long-lived listener authorization. |
| `BF-scorchkit-remote-authorization-header-retention-001` | The raw bearer header remained attached after identity selection and could cross into downstream protocol routing. | Adversarial inspection of the authentication boundary. |
| `BF-scorchkit-remote-validator-mutation-gap-001` | Grouped tests and overlapping URL predicates left 31 of 148 viable configuration, request, Debug, and lifecycle mutations alive. | First canonical DIFF mutation inventory. |
| `BF-scorchkit-cli-zero-test-inventory-stale-001` | The strict-nextest inventory still classified `scorchkit-cli` as package-local-test-free after this ticket added its first unit test. | First canonical DIFF nextest lane. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-remote-session-principal-001` | Authenticate and select a principal-specific session manager before stateful protocol routing; client and session metadata never select authority. | Prevents valid credentials and caller-controlled session IDs from crossing principal boundaries. |
| `PR-scorchkit-remote-request-lifecycle-001` | Recheck the bound engagement at host composition and every authenticated request, scrub credentials before downstream routing, and bound body reads; the trusted proxy owns pre-header connection budgets. | A long-lived listener must observe current authorization and keep credential and resource boundaries explicit. |
| `PR-scorchkit-rejected-session-cleanup-001` | Reconcile session IDs around stateful initialization and close every newly allocated session when the response does not establish it. | Protocol failure can otherwise become a durable capacity leak without an externally usable session ID. |
| `PR-scorchkit-bounded-validator-mutation-table-001` | Test serde defaults, safe projections, unique exact collection ceilings, each compound clause, and thin lifecycle wrapper behavior independently. | End-to-end denial tests do not necessarily observe which boundary, default, or cleanup path enforced the result. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Recalled principal, attribution, loopback-listener, policy-before-effects, and compound
guard rules determined the design before implementation: the backend is loopback-only, bearer
identity is bound to one immutable engagement, each principal owns isolated stateful sessions, and
client metadata remains untrusted. Inspection then caught ten concrete security and lifecycle
defects, while canonical mutation evidence converted grouped happy-path tests into direct default,
ceiling, projection, request, listener, and cancellation contracts. The final exact-tree DIFF gate
passed every applicable lane at 84.55% coverage and 100% MSI without weakening scope, TLS,
timeouts, output bounds, redaction, or policy enforcement.
