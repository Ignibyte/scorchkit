# Control API

ScorchKit exposes one versioned provider-neutral application-service contract for configuration,
engagements, projects, targets, DAST jobs, canonical findings/evidence, application modules,
reports, and ordered events. The stable DTOs and generated JSON Schemas live in the
`scorchkit-control` package; composed authorization, execution, storage validation, and transports
remain in the root package.

```text
library / storage CLI / MCP / loopback HTTP
                    |
              ControlService
          /          |           \
 engagement policy  ScanJobService  validating PostgreSQL readers
                         |
                 JournaledJobStore
                         |
              ordered bounded events
```

The request and response schema is `scorchkit.control/v1`; events use
`scorchkit.control.event/v1`. `Describe` returns the exact operation inventory plus generated JSON
Schemas. Every collection is page-oriented with a deterministic opaque cursor and a v1 ceiling of
200 items. Configured body, response, journal, event, concurrency, page, and subscriber ceilings
can narrow those protocol limits.

## Authority and configuration

The configured enabled, unexpired engagement remains the only authority. A local-process or
transport-authenticated principal is attribution plus an exact engagement binding, never a grant.
Commands recheck the target, capability, and effect before storage mutation or scanner execution.
Every command carries the exact engagement UUID. Cancellation and recovery authorize local-state
administration, recovery preauthorizes the complete interrupted-job target set before changing any
job, and project deletion locks the project while authorizing every registered target before the
transaction commits. Recovery rejects more than 1,000 simultaneous candidates before changing any
job, avoiding both an unbounded command and a silently partial sweep.
Configuration resolution starts from an explicit safe ceiling, then applies organization, project,
and run patches in order. A later layer can retain or remove values and lower budgets; it cannot add
targets, capabilities, effects, or modules or raise a limit.

New registered and job targets are parsed and stored canonically. Inline credentials, fragments,
and credential-shaped query fields are rejected without echoing their values. Target projections
are redacted as well, so legacy rows cannot expose user information, passwords, sensitive query
values, or fragments through the control boundary.

CLI and MCP control operations translate their existing inputs and renderers around the same
service. They do not receive canonical finding/evidence storage rows. Scan-specific orchestration,
finding lifecycle transitions not present in v1, schedules, and intelligence remain separate
application workflows.

## Canonical durable reads

Finding reads deserialize and normalize `raw_finding`, reapply redaction and identity derivation,
and compare every duplicated identity, correlation, module, severity, content, confidence,
lifecycle, timestamp, and scan/project projection. Evidence reads normalize `raw_evidence` and
compare schema, identity, collection time, parent, and scan/project relationships. A malformed or
divergent row fails the complete control query with `canonical_projection_mismatch`; partial data
is never returned. Finding pages use immutable `(first_seen, id)` ordering, evidence pages use
`(collected_at, id)`, and the cursor row itself is revalidated before either continuation query.

## Jobs and events

`JournaledJobStore` observes successful job creates and compare-and-swap commits. It emits compact,
redacted, monotonically sequenced events only after the underlying store accepts the revision. The
process-local journal retains a configured newest window and rejects future or expired cursors.
Live subscribers replay first and then consume broadcast events; lag is repaired from the journal,
or terminates with an explicit reset error when continuity can no longer be proven. Job lists page
at the store boundary using immutable `(created_at, id)` ordering, so the durable 1,000-item
administrative list ceiling cannot silently hide a continuation. Job target projections apply the
same credential and sensitive-query redaction as registered targets.

## Loopback HTTP

The HTTP adapter is compiled with `control-api` and starts only through the explicit
`scorchkit control-api` command. It exposes:

- `GET /v1/description`
- `POST /v1/control`
- `GET /v1/events` using SSE, query `after`, or `Last-Event-ID`

Startup requires an explicit loopback address, one stable subject, the exact active engagement UUID,
and an environment variable containing a 32–4096 byte printable bearer. The token is resolved,
validated, hashed, and zeroized before binding. Each request validates a loopback Host,
authenticates in constant time before routing or body parsing, removes authorization and claimed
identity headers, rechecks engagement eligibility, and applies hard resource bounds. Non-loopback
control hosting, direct TLS, OAuth/OIDC, tenants, RBAC, and multiple selectable engagements remain
unsupported; authenticated remote MCP is the supported remote automation profile.
