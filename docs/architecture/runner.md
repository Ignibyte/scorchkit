# Orchestration and execution

ScorchKit has one orchestrator per scan family. Orchestrators select modules, publish lifecycle
events, enforce concurrency, run hooks, collect results, and preserve deterministic output order.
They do not authorize a target themselves; they accept a policy-sealed context from `Engine`.

## Family runners

| Runner | Module trait | Target |
|---|---|---|
| `Orchestrator` | `ScanModule` | HTTP(S) URL |
| `CodeOrchestrator` | `CodeModule` | canonical code path |
| `InfraOrchestrator` | `InfraModule` | host, address, endpoint, or CIDR |
| `CloudOrchestrator` | `CloudModule` | cloud account, project, subscription, cluster, or all |

Module registries are centralized by family. Contract tests verify registry counts, unique IDs,
external-tool declarations, and declared invocations.

All four runners submit module futures through the [shared job executor](executor.md). The executor
owns bounded polling, cancellation, the batch wall-time budget, timing, and stable outcome order.
The family runner still owns tool availability, processors, events, findings, and result assembly.

## DAST execution sequence

1. Apply the selected profile and explicit module filters.
2. Check required external binaries and record unavailable modules as skipped.
3. Run typed preprocessing processors and retain only modules within the accepted target,
   capability, credential, and effect ceiling.
4. Run recon producers through one bounded executor batch.
5. Run scanner consumers through a second bounded executor batch.
6. Consume each batch's submission-ordered outcomes, pass immutable finding snapshots to enrichment
   processors, and record their proposals without changing source findings.
7. Sort findings by severity while preserving producer order for equal severities.
8. Run reporting processors, durably publish their typed outcomes, and publish completion.
9. Return one `ScanResult` with modules run/skipped and bounded processor outcomes.

The code runner uses the same preprocessing, immutable enrichment, reporting, cancellation, and
outcome contracts with `CodeScan` authority and its existing best-effort event semantics. Legacy
checkpoint and explicit phased DAST modes keep their pre-existing no-hook behavior; typed processor
support is not added to infra or cloud runners.

## External-tool boundary

Bounded adapters submit a `ToolInvocation` through the context's `ToolExecutor`. The invocation owns:

- program identity and configured executable override;
- argument vector without shell interpolation;
- optional owned stdin;
- strict or lenient exit policy;
- nonzero timeout;
- an 8 MiB cap for each output stream.

The system executor resolves one canonical executable path before spawn. On Unix, the child owns a
new process group. On Windows, ScorchKit creates the child suspended, assigns it and its inheriting
descendants to a kill-on-close Job Object, and resumes it only after ownership succeeds. Success,
nonzero exit, timeout, cancellation, output or artifact overflow, explicit stop, and drop all
terminate and reap the owned process tree within the same two-second bound.

Forty-five DAST adapters and 21 registered external SAST wrappers use this bounded path. Twenty SAST
wrappers submit one invocation. CodeQL submits an ordered database-create and database-analyze pair
for each applicable language. Interactsh owns a long-lived callback session, but it shares
executable resolution, bounded readers, and the platform process-tree owner.

## Native network boundary

Native DAST and infrastructure modules use the context's policy network. Hostnames are authorized
before DNS, every answer is authorized before connection, and sockets use concrete approved
addresses. Raw TLS retains the approved original hostname for SNI. HTTP modules use policy-bound
clients that add redirect authorization.

## Events and processors

The in-process event bus publishes scan, module, finding, and typed processor-outcome lifecycle
events. Its broadcast channel remains bounded best-effort telemetry. Durable DAST job orchestrators
additionally await registered
`DurableEventSink` persistence before broadcast, so a lagging subscriber cannot lose a webhook
enqueue. Sink failures are sanitized diagnostics and never change scanner evidence or the scan's
terminal result. Local processors are awaited and run sequentially within a phase through the same
bounded executor used for tools.

The webhook sink redacts serialized events and enforces payload and pending-record bounds before its
first store call. A separate worker claims due records under revision CAS and a recoverable lease,
then delivers through the policy-owned service client. Delivery and retries occur after and outside
scan execution.

## Failure behavior

A module error emits `ModuleError`, records the module as skipped, and lets independent modules
continue. Caller cancellation or exhaustion of the batch wall-time budget drops queued and active
module futures and aborts the family run with `ScorchError::Cancelled`. A required processor error
aborts the scan. An optional processor error becomes a redacted degraded outcome and its proposal
is ignored. The runner never
converts a timeout, connection failure, parser failure, or missing tool into a positive security
finding unless the module contract explicitly defines that observation.

## Testing contracts

- `tests/external_tool_contract.rs` observes every registered bounded adapter's program, arguments,
  timeout, output limit, and exit policy.
- Process fixtures prove child and descendant cleanup across lifecycle endings.
- The shared executor suite proves bounded overlap, stable outcomes, four-family integration,
  cancellation, batch deadlines, pending loopback HTTP release, and process-tree cleanup.
- Registry and module census tests prevent silent module drift.
- Loopback fixtures prove network behavior without contacting external targets.
- Mutation testing checks that wrappers cannot erase their execution call and remain green.
