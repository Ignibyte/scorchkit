# Shared job executor

`scorchkit-executor` owns the common scheduler used by DAST, SAST, infrastructure, and cloud module
work. The root path `scorchkit::runner::job_executor` remains a compatibility re-export. The
scheduler contains no agent, target, policy, transport, finding, event, storage, or terminal code.
Family orchestrators build policy-sealed module futures and submit those futures to the executor.

The same package owns provider-neutral durable job types, the `JobStore` trait, and the in-memory
store. The composed `ScanJobService` remains in the root package because it constructs the sealed
DAST context. PostgreSQL remains a root storage adapter.

## Contract

One executor batch enforces two resources from `ScanConfig`:

| Setting | Executor behavior |
|---|---|
| `max_concurrent_modules` | At most this many futures are polled at once. Zero is rejected as a configuration error. |
| `timeout_seconds` | The complete batch must finish within this wall time. Zero is rejected. |

Per-effect controls remain narrower and still apply. HTTP requests keep the context-owned client
timeout, external tools keep their adapter-specific timeout and output cap, and native sockets keep
their resolver and connection bounds. The batch deadline does not replace any of them.

`JobOutcome` records the submission ordinal, job duration, and family-owned output. The executor may
observe completions in any order, but it sorts outcomes by ordinal before returning them. Family
runners therefore assemble module IDs and equal-severity findings in submission order.

## Cancellation

`CancellationToken` is cloneable. Each family has a cancellation-aware run method, while its
existing run method creates a fresh token and delegates. Cancelling before or during a batch returns
`ScorchError::Cancelled` and drops queued and active futures.

DAST and SAST typed lifecycle processors are raced against the same token. A cancellation that arrives after
the final module or hook is also checked before any family publishes `ScanCompleted`, so a cancelled
scan cannot be reported as successful.

Future drop is the effect cancellation boundary:

- Dropping a pending reqwest future releases its request and connection state.
- Dropping `SystemToolExecutor` terminates its owned Unix process group or Windows Job Object,
  including descendants and the direct child.
- Dropping an isolated extension future releases the same process-tree owner; its parent also
  enforces manifest wall time while the worker enforces Wasmi fuel, memory, stack, and frame limits.
- Native socket futures release their sockets.

Loopback HTTP and local process-tree tests require cleanup within two seconds. The executor does not
return a partial `ScanResult` or persist progress. The provider-neutral job control plane in
`docs/architecture/jobs.md` owns durable state, progress, partial recovery, and transport-facing
cancellation without changing this executor contract.

## Family phases

Bounded concurrency must not race a consumer against data it needs:

- DAST runs recon modules before scanner modules. Each phase is one executor batch.
- Infrastructure runs non-`CveMatch` modules before `CveMatch` consumers.
- SAST and cloud use one batch because their current production registries have no declared
  producer/consumer dependency.

Post-module processors, finding events, completion/error events, and result assembly consume the stable
outcome list after a phase. `ModuleStarted` is published when a module future begins polling, so it
continues to describe real execution rather than queue admission.

Checkpoint mode remains as a legacy serial compatibility path. New CLI and MCP work uses the stored
job lifecycle, whose reliable module-boundary sink preserves completed evidence while the shared
executor remains concurrent and persistence-free.

## Failure boundary

An individual module error remains its family-owned output. The orchestrator emits `ModuleError`,
records the module as skipped, and processes independent outcomes. Caller cancellation and batch
deadline are executor failures and abort the family run. Policy denials and effect failures remain
typed module errors unless they occur in a fatal pre-scan or hook boundary.

A required post-module processor still aborts result assembly, but concurrent siblings in the same
phase may already have completed before that ordered processor is evaluated. Those sibling effects
remain independently policy-authorized; processors do not replace the policy boundary.

## Tests

The executor suite proves:

- actual overlap and a concurrency high-water mark that never exceeds the budget;
- stable output after deliberately reversed completion order;
- zero-budget rejection, pre-cancellation, in-flight cancellation, and deadline handling;
- pending loopback HTTP connection release, owned process-tree termination, and adjacent-effect
  future drop;
- the same overlap, ordering, and cancellation contract through all four family orchestrators;
- DAST recon/scanner and infrastructure fingerprint/CVE dependency barriers.
