---
aar: AAR-035-extension-catalog
ticket: TICKET-035
pipeline: extension-catalog
status: submitted
opened: 2026-08-26
submitted: 2026-08-26
effectiveness: 4 - strong
---

# AAR-035 — Add a signed extension catalog and lifecycle

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | A valid publisher signature may look like authorization to execute. | Useful; catalog trust establishes exact identity only, while registration and every guest HTTP effect retain engagement and broker authorization. |
| `PR-scorchkit-verified-artifact-single-read-001` | Catalog, manifest, and module paths can change between verification and activation. | Useful; bounded no-follow reads retain exact module bytes and propagate manifest/module digests into approval, activation, invocation, and finding provenance. |
| `PR-scorchkit-offline-scan-refresh-separation-001` | Catalog refresh could become part of module selection or execution. | Useful; no refresh/fetch path exists, and invocation consumes an exact local approval while treating only true catalog absence as offline. |
| `PR-scorchkit-extension-persistence-boundary-001` | Catalog metadata could bypass the engine's finding/evidence stores. | Useful; catalog modules reuse `LoadedExtension`, the isolated proposal-only worker, broker, output validation, and ordinary finding provenance. |
| `PR-scorchkit-release-target-header-binding-001` | A signed filename and digest can still describe the wrong artifact kind. | Useful; activation combines signed identities with exact Wasm export/signature/startup health checks before publishing the pointer. |
| `PR-scorchkit-restore-integrity-before-effect-001` | Rollback can replace a healthy active release with changed or revoked bytes. | Useful; rollback reopens, rehashes, health-checks, and revocation-checks the exact prior approval before atomic activation. |
| `PR-scorchkit-dynamic-catalog-global-identity-001` | Multiple signed catalogs may claim the same extension ID. | Useful; one global claim set spans built-ins, explicit manifests, and every locally approved catalog release. |
| `PR-scorchkit-history-not-latest-reconstruction-001` | Upgrade or revocation could rewrite old result attribution to the current version. | Useful; lifecycle transitions and finding provenance remain bound to their immutable approval/catalog/release identities. |
| `PR-scorchkit-adapter-error-provenance-001` | Signature, compatibility, conformance, health, revocation, and policy denials can collapse into one generic failure. | Useful; bounded lifecycle errors preserve the rejecting layer, and negative fixtures assert that they reach artifact, health, revocation, or policy enforcement as intended. |

## What happened

- Added a closed provider-neutral signed-catalog contract and local Ed25519 trust configuration.
  Every release binds publisher/key, payload, manifest, module, compatibility, provenance,
  conformance, normalized permissions, sequence, and validity identities without adding a remote
  transport or catalog-controlled trust source.
- Added explicit inspect, approve, activate, rollback, and status lifecycle operations. Immutable
  content-addressed approvals and append-preserved transitions feed one atomic active pointer;
  current revocation is checked before registration and worker selection, while exact approved
  releases remain usable when a catalog is truly absent.
- Adversarial inspection found eight issues. The high-severity repairs bound approvals to the exact
  reviewed payload/diff, serialized cross-process writers, rejected same-sequence equivocation,
  distinguished dangling catalog paths from absence, and reconstructed active state from the
  complete transition ledger.
- The first 399-mutant DIFF passed every non-mutation lane but scored 72.4% MSI. Owner-approved
  exact repair of its 101 survivors produced sealed evidence for 366/366 viable outcomes caught at
  100% MSI. A fingerprint-identical mirror beside clean pinned Rustal then passed all 22 focused
  delivery lanes, including 86.00% line coverage, 2,290 strict nextest cases, browser, PostgreSQL,
  and CLI/MCP contracts.

## Novel findings

- A monotonic signed sequence is not an equivocation defense unless the accepted sequence is bound
  to exactly one payload digest; equality must mean byte-identical checkpoint ownership.
- An immutable approval file is not committed lifecycle authority by itself. Activation must prove
  that an append-preserved approval transition owns it, under the same cross-process writer lock as
  state publication.
- Offline fallback must distinguish a genuinely absent configured source from every present or
  indeterminate filesystem object. `Path::exists` can turn a dangling symlink into false absence.
- Durable active pointers are trustworthy only when the complete bounded transition history can be
  reconstructed to the same pointers and every link names a previously approved exact identity.
- A mutation in platform-conditioned code can survive on the validation host even when the branch
  is correct. A test-only compilation seam can exercise the alternate branch without changing the
  release build or deleting the preserved mutation coordinate.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-reviewed-approval-subject-drift-001` | Approval recomputed a candidate but did not require the payload and permission-diff digests returned by the operator's preceding inspection. | Adversarial approval-boundary inspection. |
| `BF-scorchkit-lifecycle-writer-split-001` | Concurrent lifecycle writers could lose state, and an approval file published before its transition could be activated as an orphan. | Adversarial concurrency/crash inspection. |
| `BF-scorchkit-catalog-sequence-equivocation-001` | A highest-sequence checkpoint without its payload digest accepted a different signed payload at the same sequence. | Adversarial replay/equivocation inspection. |
| `BF-scorchkit-dangling-catalog-offline-bypass-001` | `Path::exists` classified a configured dangling symlink as offline instead of invalid present state. | Adversarial offline-boundary inspection. |
| `BF-scorchkit-lifecycle-pointer-without-history-001` | Shape-valid lifecycle state could contain duplicate approvals or active pointers not derivable from its transition history. | Adversarial durable-integrity inspection. |
| `BF-scorchkit-platform-cfg-mutation-blindspot-001` | A correct non-Unix create-error predicate remained mutation-invisible on Unix, while a public-mode file masked a neighboring directory predicate. | First exact 101-name repair recheck. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-approval-preview-exact-binding-001` | Bind approval to the exact candidate and normalized-diff digests returned by inspection, and reject either mismatch before durable publication. | Recomputing a valid object does not prove it is the object the operator reviewed. |
| `PR-scorchkit-durable-lifecycle-single-writer-001` | Serialize approval and pointer transitions with one cross-process lock, and require an append-preserved approval transition before activation. | Immutable files published before a state commit must not become ambient authority or race a later writer. |
| `PR-scorchkit-monotonic-sequence-payload-binding-001` | Store the exact payload digest with every accepted highest sequence and treat same-sequence digest changes as equivocation. | Sequence comparison alone cannot distinguish idempotent replay from conflicting signed state. |
| `PR-scorchkit-configured-source-absence-identity-001` | Determine offline status with no-follow metadata and accept only an exact not-found result as absence; validate every present object through the normal source boundary. | Link following and convenience existence checks can turn invalid configured state into permissive fallback. |
| `PR-scorchkit-state-history-reconstruction-001` | Reconstruct bounded durable pointers from the full append-preserved transition ledger and compare the result to every published pointer. | Field-shape validation cannot prove ownership, continuity, or that current state actually occurred. |
| `PR-scorchkit-platform-branch-mutation-seam-001` | Keep platform-conditioned security branches executable in tests on the validation host when doing so preserves release behavior and exact mutation identity. | Otherwise a correct alternate-platform predicate can never be killed by the host's mutation suite. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

The recalled rules correctly shaped the implementation around identity without authority,
single-read artifacts, exact rollback, global module claims, unchanged isolated execution, and
append-only provenance. Inspection then found the less obvious reviewed-subject, single-writer,
equivocation, false-offline, and state-reconstruction gaps before delivery. The mutation campaign
was expensive but bounded to one broad inventory and one exact repair set, and the clean pinned
validation mirror preserved unrelated Rustal work while proving the exact ScorchKit tree. The low
first-pass MSI and three residual repair misses keep the rating at four; the six captured rules make
those lifecycle and testability failures directly preventable in later work.
