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
The family runner still owns tool availability, hooks, events, findings, and result assembly.

## DAST execution sequence

1. Apply the selected profile and explicit module filters.
2. Check required external binaries and record unavailable modules as skipped.
3. Run configured pre-scan hooks.
4. Run recon producers through one bounded executor batch.
5. Run scanner consumers through a second bounded executor batch.
6. Consume each batch's submission-ordered outcomes, run post-module hooks, and accept a valid
   replacement `findings` array.
7. Sort findings by severity while preserving producer order for equal severities.
8. Run post-scan hooks and publish completion.
9. Return one `ScanResult` with modules run and skipped.

Pre-scan hook output is currently informational and is not applied to module selection. Post-scan
output is ignored after the hook completes. These limitations are explicit so a hook cannot appear
to change behavior that the runner does not consume.

## External-tool boundary

Bounded adapters submit a `ToolInvocation` through the context's `ToolExecutor`. The invocation owns:

- program identity and configured executable override;
- argument vector without shell interpolation;
- optional owned stdin;
- strict or lenient exit policy;
- nonzero timeout;
- an 8 MiB cap for each output stream.

The system executor resolves one canonical executable path before spawn. On Unix, the child owns a
new process group. Success, nonzero exit, timeout, cancellation, output overflow, explicit stop, and
drop all terminate and reap the owned process tree. Linux and macOS are supported. Windows remains
disabled until Job Object cleanup proves the same contract.

Forty-five DAST adapters and 23 external SAST wrappers use this bounded path. Twenty-two SAST
wrappers submit one invocation. CodeQL submits an ordered database-create and database-analyze pair
for each applicable language. Interactsh owns a long-lived callback session, but it shares
executable resolution, bounded readers, and process-group cleanup.

## Native network boundary

Native DAST and infrastructure modules use the context's policy network. Hostnames are authorized
before DNS, every answer is authorized before connection, and sockets use concrete approved
addresses. Raw TLS retains the approved original hostname for SNI. HTTP modules use policy-bound
clients that add redirect authorization.

## Events and hooks

The in-process event bus publishes scan, module, and finding lifecycle events. Publishing never
changes scanner evidence. Local hooks are awaited and run sequentially within a hook point through
the same bounded executor used for tools.

Outbound webhook delivery is disabled. The serializable webhook configuration remains readable for
file compatibility, but no HTTP sender exists. Reintroduction requires a policy-owned delivery
service with destination authorization, redaction, queue bounds, and failure tests.

## Failure behavior

A module error emits `ModuleError`, records the module as skipped, and lets independent modules
continue. Caller cancellation or exhaustion of the batch wall-time budget drops queued and active
module futures and aborts the family run with `ScorchError::Cancelled`. A fail-closed hook error
aborts the scan. A fail-open hook error is terminal-escaped, logged, and ignored. The runner never
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
