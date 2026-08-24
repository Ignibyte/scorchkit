---
aar: AAR-027-control-api
ticket: TICKET-027
pipeline: control-api
status: submitted
opened: 2026-08-23
submitted: 2026-08-23
effectiveness: 4
---

# AAR-027 — Add a versioned provider-neutral control API

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Control commands can create local-state and scanner effects. | Yes; the root service must authorize before touching stores or constructing effect resources. |
| `PR-scorchkit-attribution-not-authorization-001` | HTTP accepts untrusted headers while projecting a caller. | Yes; only transport authentication creates the principal, and metadata remains non-authoritative. |
| `PR-scorchkit-store-invariants-falsification-001` | Event replay depends on observing every valid job store mutation. | Yes; the design decorates the store rather than inferring changes from polling. |
| `PR-scorchkit-provider-consumption-validation-001` | Package-owned wire types cross into composed engine operations. | Yes; the service revalidates every request and response invariant. |
| `PR-scorchkit-workspace-gate-scope-001` | Stable contracts belong in a new workspace package. | Yes; dependency allow-lists and all workspace gates change in the same ticket. |
| `PR-scorchkit-public-evidence-revalidation-001` | Findings and evidence cross a new public serialization boundary. | Yes; they are normalized and redacted again before projection. |
| `PR-scorchkit-durable-canonical-parity-001` | Existing read CRUD returns duplicated database projections. | Yes; public reads compare canonical raw records with every duplicated field. |
| `PR-scorchkit-projection-validate-canonical-001` | Self-description and reports can make invalid nested state look authoritative. | Yes; schemas and public result builders validate before projection. |
| `PR-scorchkit-local-api-principal-boundary-001` | A loopback HTTP transport needs a real caller boundary. | Yes; the transport requires an environment-backed credential. |
| `PR-scorchkit-local-frontend-bind-boundary-001` | SK-049 is groundwork for later local frontends. | Yes; non-loopback listeners remain rejected until team isolation exists. |
| `PR-scorchkit-remote-request-lifecycle-001` | Existing remote MCP already owns secure request guard patterns. | Yes; HTTP authentication precedes routing and credentials are scrubbed before service dispatch. |
| `PR-scorchkit-bounded-validator-mutation-table-001` | A schema-driven API adds defaults, ceilings, and compound predicates. | Yes; the regression plan isolates every boundary and each invalid arm. |

## What happened

- SK-049 added the dependency-light `scorchkit-control` package and one root `ControlService` used
  by in-process, CLI, MCP, and opt-in authenticated loopback HTTP adapters. The v1 contract
  self-describes 22 operations and 12 schemas while keeping storage, execution, policy, and
  provider composition out of the wire package.
- Commands bind a transport-established principal to the exact enabled, unexpired engagement and
  authorize target/capability/effect before mutation. Queries retain legacy read compatibility.
  Durable finding/evidence reads reconstruct canonical records and compare every duplicated field
  before projection.
- Job create/CAS commits publish through a journaled store decorator. Stable bounded store paging,
  immutable finding cursors, exact recovery candidate snapshots, transactional project deletion,
  and explicit replay continuity errors prevent hidden tails and authorization races.
- New and legacy target/job URLs cross the control boundary only through a secretless canonical
  projection. Credential-bearing, sensitive-query, fragment, or unsafe resume inputs fail before
  persistence without echoing secrets.
- Adversarial inspection closed 22 high-to-medium findings and accepted two documented low risks.
  The final focused-repair gate passed 19 lanes at 84.40% line coverage, 2,001 strict Nextest cases,
  PostgreSQL integration, and CLI/MCP contracts. The owner stopped repeat mutation discovery; the
  sealed exact six-name baseline reproduced six misses and the repaired recheck caught all six at
  100% viable MSI without another broad run.

## Novel findings

- A provider-neutral DTO package is insufficient by itself: every host must still adapt through one
  composed application service or policy and canonical-read decisions drift between transports.
- Pagination bounds must live at the store query. Paging a capped materialized compatibility list
  can return a valid cursor protocol while silently hiding the durable tail.
- Recovery authorization must bind the exact candidate set before any mutation. Authorizing an
  abstraction and then sweeping a changing query permits newly eligible rows to cross the decision.
- Stored URLs are untrusted legacy input even when current write paths validate them. Safe public
  projection and resume both need canonical secretless revalidation.
- Protected source-contract tests observe inline test code as well as production code. White-box
  database fixtures belong outside the adapter file whose neutrality is being mechanically proved.
- A default mutation evidence slot is consumable state. Launching a follow-up before copying the
  completed raw result can erase the only baseline needed for an honest focused receipt.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-control-recovery-moving-candidate-001` | Recovery authorized an incomplete abstraction and could mutate candidates that appeared after the decision. | Adversarial authorization inspection. |
| `BF-scorchkit-control-url-secret-roundtrip-001` | New and legacy target/job projections could persist or emit credentials, fragments, or sensitive query values. | Privacy inspection and legacy-row regression design. |
| `BF-scorchkit-control-materialized-page-tail-001` | Job pagination operated on a silently capped materialized list and could hide durable rows beyond 1,000. | Bounds inspection of the store/service boundary. |
| `BF-scorchkit-focused-baseline-overwrite-001` | A later mutation invocation overwrote the default compact artifact containing the original completed survivor baseline. | Focused-repair evidence assembly during validation. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-control-recovery-exact-candidate-001` | Materialize one bounded sentinel-checked recovery candidate set, authorize every target in that set, and mutate only those exact identities. | A moving recovery query can introduce unauthorized work after the policy decision. |
| `PR-scorchkit-secretless-control-target-001` | Revalidate stored and new control targets as canonical secretless URLs before persistence, public projection, or lifecycle continuation. | Current writers do not make legacy or externally corrupted rows trustworthy. |
| `PR-scorchkit-immutable-store-pagination-001` | Implement continuation at the store with immutable ordered keys and explicit missing-cursor failure; never page a capped compatibility collection. | A bounded materialization can silently hide a durable tail and mutable keys can skip rows. |
| `PR-scorchkit-focused-raw-artifact-preservation-001` | Copy every completed mutation inventory and raw outcome set to a ticket-specific immutable slot before any follow-up invocation. | The default compact slot is overwritten, and summaries or console logs cannot replace raw delivery evidence. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 4/5. Recalled policy-before-effects, principal attribution, store falsification, canonical
parity, and local transport rules directly shaped the service, authenticated loopback host, and
validating read boundary. Inspection nevertheless found critical recovery/deletion races, secret
URL paths, and silent pagination tails, so the initial design was not complete enough for a perfect
score. The final implementation closes each with focused negative/boundary tests and records four
reusable rules.
