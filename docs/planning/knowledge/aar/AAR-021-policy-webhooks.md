---
aar: AAR-021-policy-webhooks
ticket: TICKET-021
pipeline: policy-webhooks
status: submitted
opened: 2026-08-21
submitted: 2026-08-22
effectiveness: 5 - strong
---

# AAR-021 — Restore policy-owned durable webhook delivery

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | The removed sender constructed and used an HTTP client from an event handler. | Yes — the replacement design routes every attempt through the shared policy-owned service client. |
| `PR-scorchkit-derived-network-policy-001` | Webhook DNS resolution and redirects derive additional network effects from one configured URL. | Yes — direct, mixed-answer, rebound, and redirect authorization became acceptance tests. |
| `PR-scorchkit-attribution-not-authorization-001` | A configured destination ID could otherwise be mistaken for permission to contact it. | Yes — runtime attribution and engagement authorization remain separate inputs. |
| `PR-scorchkit-public-evidence-revalidation-001` | Queue state becomes durable operator-visible evidence. | Yes — redaction, bounds, and deterministic projections are enforced at persistence and exposure. |
| `PR-scorchkit-untrusted-finding-channel-redaction-001` | Scan events contain scanner-controlled evidence that crosses into a new delivery channel. | Yes — redaction is required before the first store call or request construction. |
| `PR-scorchkit-local-api-principal-boundary-001` | MCP will host the background worker before authenticated remote MCP exists. | Yes — this ticket avoids adding remotely mutable queue administration. |
| `scan-job-lifecycle.notes.md` | Webhook attempts need crash-safe ownership and history similar to jobs. | Yes — revision CAS, leases, recovery, and transactionally paired audit records are reused as patterns. |
| `mcp-contract-hardening.notes.md` | Status projections can leak or grow without explicit output contracts. | Yes — queue/detail output is typed, bounded, deterministic, and credential-free. |

## What happened

- Replaced the removed fire-and-forget sender with an awaited durable enqueue boundary and a
  separately owned asynchronous delivery worker. Scan success remains independent of webhook
  availability while enqueue and attempt failures stay observable.
- Added bounded credential-indirect destination configuration, an explicit webhook-delivery
  capability, redaction before persistence and again before request construction, policy-owned
  DNS/connect/redirect handling, and ambient-proxy denial.
- Added provider-neutral delivery state, revision CAS, timeout-sized leases, recovery, bounded
  retries, immutable audit records, an atomic in-memory conformance store, PostgreSQL migration and
  adapter, typed CLI operations, and a durable MCP background worker.
- Adversarial inspection found thirteen security, correctness, test, and ownership defects. All
  were repaired before validation, including short leases, redirecting credentials, untrusted sink
  diagnostics, foreground worker execution, inconsistent state replacements, and missing receiver
  idempotency keys.
- The first broad DIFF mutation run exposed a 58.3% state-machine and boundary-test score plus a
  stale exact-suite inventory entry. Direct mutation tables raised the final canonical score to
  97.52% across 316 mutants. The exact completed validation tree passed all 19 applicable lanes,
  1,904 strict-nextest cases, PostgreSQL integration, and CLI/MCP contracts at 84.39% coverage.

## Novel findings

- The current broadcast event bus is explicitly lossy, so subscribing a queue writer would provide
  the appearance of durability without a persistence guarantee. Durable sinks need their own
  awaited lifecycle seam while retaining scan-result independence.
- A delivery ownership lease must be derived from the complete network-attempt deadline plus a
  commit margin. A fixed lease can expire while the authorized effect is still live and permit a
  second worker to duplicate it.
- Even a transactionally durable queue is at-least-once across the receiver-accepted/local-commit
  crash gap. Stable delivery and attempt keys are part of the external effect contract, not merely
  an implementation detail.
- Shared-database integration tests must account for abandoned records from earlier aborted runs.
  A small global queue page cannot prove that a newly inserted fixture is absent or not due.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-webhook-lease-shorter-effect-001` | A fixed 30-second ownership lease could expire during an allowed 300-second HTTP attempt and permit concurrent duplicate delivery. | Adversarial inspection of the claim and request deadlines. |
| `BF-scorchkit-shared-queue-test-page-assumption-001` | A PostgreSQL test assumed its new fixture would appear in the first ten globally due rows despite abandoned records from prior aborted runs. | Strict-nextest and PostgreSQL lanes after the second mutation campaign. |
| `BF-scorchkit-webhook-mutation-state-gap-001` | Happy-path and grouped predicate tests left 118 of 316 viable boundary, transition, adapter, and host mutations alive. | First canonical DIFF mutation inventory. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-effect-lease-covers-deadline-001` | Size ownership leases to cover the complete external-effect deadline plus a bounded commit margin. | Prevents another worker from reclaiming work while the first authorized effect can still be live. |
| `PR-scorchkit-durable-effect-idempotency-001` | Give every durable at-least-once external effect stable operation and attempt identities that receivers can use for deduplication. | A crash after remote acceptance but before local commit cannot be eliminated by queue transactions alone. |
| `PR-scorchkit-durable-worker-foreground-separation-001` | Foreground scans await only durable enqueue; background or explicit worker owners perform bounded network attempts. | Prevents destination batch and timeout settings from becoming scan-response latency or availability dependencies. |
| `PR-scorchkit-shared-db-fixture-recovery-001` | Shared-database tests remove only their own abandoned fixtures and never infer record membership from an arbitrarily small global page. | Keeps retries and aborted test runs from making correct ordered queue reads look nondeterministic. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Recalled network-derivation, policy-before-effects, public-evidence, redaction, and local
principal rules changed the design before implementation from a retrying HTTP sender into a
credential-indirect durable queue with address-level authorization, revision ownership, bounded
operator projections, and no remote administration. Inspection then caught thirteen concrete
security and lifecycle defects, and canonical mutation evidence converted broad happy-path tests
into direct boundary and state-transition contracts. The final exact-tree DIFF gate passed every
applicable lane at 84.39% coverage and 97.52% MSI without weakening any policy, timeout, redaction,
or quality floor.
