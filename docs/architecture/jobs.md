# Scan job control plane

`runner::job` is the provider-neutral lifecycle around DAST execution. It owns authorization
snapshots, monotonic state, durable module progress, cancellation, ownership leases, recovery, and
attempt lineage. CLI, MCP, in-memory, and `PostgreSQL` code adapt this contract; no agent vendor is
part of it.

## Lifecycle

```text
queued ───────> running ───────> succeeded
  │                │  └───────> failed
  │                └──────────> cancelling ──> cancelled
  ├──────────────> cancelled
  └──────────────> interrupted <── expired running/cancelling lease
                         │
                         └── resume creates a linked queued successor
```

Terminal attempts never re-enter execution. Every accepted mutation increments a `u64` revision,
updates its timestamp, and uses compare-and-swap. The in-memory and `PostgreSQL` stores append a
compact audit event for that exact revision atomically with the job update. Stale writers update
neither the job nor its audit trail. Both stores independently reject illegal state changes,
mutable request or identity fields, malformed queued attempts, and forged successor lineage.

## Authorization and effects

Submission and execution both reconstruct a policy-sealed DAST context through `Engine`. Resume
also requires the current engagement to equal the immutable stored snapshot before it creates a
successor. A stored job, target registration, MCP request, or agent instruction never grants scope
or effects.

The current adapter supports DAST. SAST, infrastructure, and cloud job adapters can implement the
same contract later without moving persistence into the shared executor.

## Progress and cancellation

`Orchestrator` publishes owned module-boundary updates through an optional `JobProgressSink`:

- start adds the module to the active set;
- success atomically commits the module ID and its findings;
- unavailable and failed modules leave recoverable outcome markers;
- terminal commit waits until the progress writer has drained.

The channel is bounded to 512 updates. Saturation fails the job instead of allowing unbounded
memory growth. Best-effort `ScanEvent` broadcast remains observability; it is not recovery evidence.

Each running job owns the shared SK-028 `CancellationToken`. Cancellation persists `cancelling`
before signaling the local token. A 500 ms heartbeat notices cancellation written by another
process and refreshes a 15 second ownership lease. Success cannot overwrite cancellation because
both use the same revision predicate. Dropping an in-process run future cancels its scanner and
heartbeat and releases process-local ownership, so abandoned work can be recovered after its lease.

## Recovery and resume

Recovery claims only nonterminal jobs whose lease expired, using compare-and-swap so concurrent
servers cannot both win. MCP runs the pass at startup and every five seconds. CLI exposes an
explicit recovery command.

An interrupted attempt retains findings only for modules whose completion update was committed.
Resume creates a new attempt linked by `root_job_id` and `parent_job_id`, reauthorizes the request,
copies completed evidence, and excludes those modules. Skipped, failed, and active modules run
again. Final result assembly prepends recovered evidence and recomputes its summary without
duplicating findings. In-memory checks and unique database indexes allow only one successor per
parent and one record per root/attempt number, so concurrent resume requests converge on one winner.

## Storage

`JobStore` defines create, read, a deterministic 1,000-record list, bounded recoverable batches,
compare-and-swap, and audit-read operations.
`InMemoryJobStore` supports a process-local stateless MCP session. `PostgresJobStore` stores a JSONB
domain document plus indexed lifecycle columns in `scan_jobs`; `scan_job_audit_events` is the
append-only revision trail. Database creation and updates commit the job and audit event in one
transaction.

## Host adapters

- MCP without a database uses the in-memory store for `scan_job_start`, `scan_job_status`,
  `scan_job_cancel`, and `scan_job_resume`. Project, finding, schedule, resource, and migration
  operations return an explicit database-unavailable error.
- MCP with a configured database uses the `PostgreSQL` store. The legacy synchronous `scan` tool is
  a compatibility wrapper over the same lifecycle.
- CLI `job run` and `job resume` execute in the foreground and convert Ctrl-C into stored
  cancellation. `job list`, `status`, `cancel`, and `recover` operate across processes through
  `PostgreSQL`.

## Evidence

Focused tests cover legal transitions, stale writers and audit events in both stores, authorized
loopback completion, cross-service cancellation, expired-lease recovery, partial-evidence resume,
changed-engagement denial, real CLI process continuity, and stateless MCP over an actual duplex
transport.
