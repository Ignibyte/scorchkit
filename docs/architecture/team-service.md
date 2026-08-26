# Authenticated team service

The optional `team` feature adds a multi-user deployment profile without changing local CLI, MCP,
control API, console, or storage defaults. It is a loopback backend for a trusted same-host TLS
proxy, not a public listener or an identity provider.

## Isolation model

```text
TLS proxy
   |
   | exact Host/Origin + bearer
   v
team gateway -- digest binding --> cell A: PostgreSQL A + queue A + journal A
                               |           object root A + key ring A + audit A
                               |
                               `---------> cell B: PostgreSQL B + queue B + journal B
                                           object root B + key ring B + audit B
```

A bearer is configured for exactly one subject, role, cell, organization, project, and engagement.
The gateway hashes every candidate and compares the request digest against the complete binding
table in constant time before parsing JSON or resource identifiers. Request headers and bodies
cannot select or widen those values, and identity-claim headers plus `Authorization` are removed
before routing.

Each cell must resolve to a distinct live PostgreSQL database and a distinct, non-overlapping,
already-canonical object root. Startup migrates the database, requires exactly the configured
project, seals a singleton cell identity, checks the PostgreSQL cluster/database identity, resolves
the complete key ring, and authorizes the exact object root before opening the listener. Database
triggers reject cell-identity and audit-history updates or deletes. A database-scoped connection
lease permits exactly one live team service for a cell; every operation checks that lease before
using the cell. Wrong-cell identifiers are therefore absent rather than dependent on a tenant
predicate in every query.

## Authorization and admission

RBAC is a narrowing layer in front of the unchanged control application service:

| Role | Additional access |
|---|---|
| `reader` | Control queries and authenticated object reads |
| `analyst` | Reader plus finding transitions, suppressions, and correlations |
| `operator` | Analyst plus target/job lifecycle and object writes |
| `administrator` | Operator plus audit reads, retention, key rotation, and recovery verification |

Project create/delete is never available through the team transport because the project is a
provisioning invariant. Every operation still passes the bound engagement and canonical control
service checks. Job starts additionally require the exact canonical target to be registered in the
cell project. Request-rate, active-job, object-size/count/bytes, body, response, concurrency,
journal, event, subscriber, and page limits fail closed per configured boundary.

Every admitted request receives a durable unique request claim. Mutations append an immutable
`pending` audit event before their effect and a terminal `succeeded`, `denied`, or `failed` event
afterward. Startup closes abandoned intents with `outcome_unknown`; it never rewrites history.
Unknown credentials produce only credential-safe host tracing because no cell is known.

## Encrypted objects

`PUT /v1/team/objects/{evidence|report|extension_artifact}` stores nonempty plaintext under its
lowercase SHA-256 identity. Before each operation the service rechecks the canonical root and its
exact `local-state`/`passive` path grant. AES-256-GCM uses a fresh random nonce and authenticates the
schema, cell, object identity, kind, plaintext size, key ID, creation time, and expiry. PostgreSQL
metadata and the exact ciphertext-envelope digest and size must agree on read. Files use immutable
plaintext-and-ciphertext-digest-derived names, private create-new staging, no-follow reads, and
canonical private-root checks. Rotation publishes a new version through metadata and queues the
retired version for durable deletion; retention uses the same restart-recoverable deletion queue.
Responses, manifests, errors, configuration debug output, and audits contain key IDs only. Key
values are canonical base64 32-byte values resolved from `SCORCHKIT_TEAM_*` environments into
zeroizing buffers.

## HTTP surface

The trusted proxy must preserve an allowed public Host, replace Origin according to its browser
policy, and pass the bearer to the loopback backend:

- `GET /v1/team/description`
- `POST /v1/team/control`
- `GET /v1/team/audit?after=&limit=`
- `PUT /v1/team/objects/{kind}`
- `GET /v1/team/objects/{sha256}`
- `POST /v1/team/objects/{sha256}/rotate`
- `POST /v1/team/retention`

The backend does not terminate TLS and does not implement OAuth/OIDC, passwords, browser sessions,
row-shared tenancy, client-selected projects, cross-cell administration, or cloud object-store
credentials. A browser must not own the service bearer.

## Backup and recovery

Recovery manifests use `scorchkit.team.recovery.v1` and bind the cell, organization, project,
engagement, source database identity, ordered migration ledger, exact PostgreSQL custom-format
snapshot digest and size, sorted encrypted-object inventory, ciphertext digests, stored sizes, and
required key IDs and creation time. Each inventory item must also parse as the bounded team-object
envelope for the same cell, object, key, plaintext size, nonce, and expiry metadata. Verification
requires a distinct destination database identity and is repeated against the same bytes
immediately before and after restore. The PostgreSQL qualification lane
uses disposable databases with `pg_dump` and `pg_restore`, checks restored canonical project
identity, and rejects snapshot, object, migration, identity, key-set, and same-destination drift.
In-place restore is deliberately unsupported.

Build and start explicitly:

```bash
cargo build --release --features team
scorchkit team-api --config /etc/scorchkit/team.toml
```

See [Configuration](config.md), [Control API](control-api.md), and [Security policy](../../SECURITY.md).
