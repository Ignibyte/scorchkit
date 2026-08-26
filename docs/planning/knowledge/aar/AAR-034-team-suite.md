---
aar: AAR-034-team-suite
ticket: TICKET-034
pipeline: team-suite
status: submitted
opened: 2026-08-24
submitted: 2026-08-26
effectiveness: 4 - strong
---

# AAR-034 — Add an authenticated multi-user deployment profile

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-attribution-not-authorization-001` | Proxy headers, user-visible roles, and organization/project labels can look authoritative. | Useful; credential bindings select one exact cell before routing, while engagement policy independently authorizes effects. |
| `PR-scorchkit-local-api-principal-boundary-001` | The team backend still runs behind a local proxy. | Useful; loopback remained a routing boundary and exact trusted-proxy credentials provide authentication. |
| `PR-scorchkit-remote-session-principal-001` and `PR-scorchkit-remote-request-lifecycle-001` | Remote MCP already proved authenticate-before-routing, per-request engagement rechecks, header scrubbing, and bounded bodies. | Useful; the team API reused those lifecycle rules for cell selection, RBAC, body bounds, and header removal. |
| `PR-scorchkit-durable-canonical-parity-001` | Tenant metadata could diverge from canonical project, finding, job, and evidence identities. | Useful; each operation revalidates cell/database identity and wrong-cell identifiers remain uniformly absent. |
| `PR-scorchkit-durable-worker-foreground-separation-001` | A multi-user service needs shared durable work rather than request-owned delivery. | Useful; each cell reuses PostgreSQL job and webhook queues with bounded service-owned admission. |
| `PR-scorchkit-restore-integrity-before-effect-001` | Backup/restore can corrupt the active tenant or consume changed input. | Useful; manifests are verified before and after consumption and restoration requires a distinct destination. |
| `PR-scorchkit-authorize-validate-consume-one-handle-001` and `PR-scorchkit-scoped-tool-artifacts-001` | Team object roots add local filesystem effects and cleanup/retention. | Useful; object access is policy-authorized, no-follow, bounded, cell-owned, encrypted, versioned, and audited. |
| `PR-scorchkit-credential-use-separate-grant-001` | Encryption keys and bearer values are credentials even though storage and control effects are otherwise allowed. | Useful; configuration stores only environment references while resolved secrets remain scoped, zeroized, uniqueness-checked, and redacted. |

## What happened

- Added an optional trusted-proxy team service in which each credential selects one exact subject,
  RBAC role, engagement, and hard organization/project cell before request routing. Every cell owns
  its PostgreSQL database, control service, queues, journal, quota state, encrypted object root,
  key ring, append-only audit, and recovery identity; the local profile remains unchanged.
- Adversarial inspection found 15 issues. The highest-risk repairs replaced in-place object changes
  with immutable ciphertext versions and a durable deletion queue, serialized active-job capacity,
  added a database-scoped exclusive service lease, required private roots and resolved-secret
  uniqueness, and bound audits and recovery manifests to complete cell identity.
- One 732-mutant DIFF established the only broad inventory. Exact repair of its 94 survivors plus a
  26-mutant behavior-preserving follow-up produced sealed evidence for 656/656 viable outcomes
  caught at 100% MSI without repeating the broad campaign.
- Validation used a fingerprint-identical disposable ScorchKit mirror beside Rustal's exact clean
  pinned revision because the shared Rustal checkout contained unrelated active work. The final
  focused-repair gate passed all 22 lanes, including browser, PostgreSQL, recovery, CLI/MCP, 2,246
  nextest cases, and 85.85% line coverage.

## Novel findings

- Database-per-cell isolation is incomplete if two service processes can attach to one cell while
  owning separate in-memory journals and admission counters; the database identity also needs a
  connection-lifetime exclusive service lease.
- Crash-safe encrypted-object rotation and retention require immutable published versions plus a
  durable deletion ledger. Overwriting the active path or deleting before commit makes ambiguous
  database outcomes irreconcilable.
- Distinct environment-variable names do not imply distinct credentials or keys. Cross-cell
  isolation must compare resolved secret values at startup while keeping them zeroized and absent
  from diagnostics.
- Mutation source coordinates describe the preserved baseline, not necessarily the repaired tree;
  the immediate predicate truth table must be resolved against that baseline before adding a test.
- A fingerprint-matched validation mirror can safely combine an exact dirty worktree with a clean
  separately pinned sibling, but project-root and database variables must remain scoped to the
  package or fixture that owns them.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-object-version-overwrite-001` | In-place rotation and file-first retention could leave committed metadata referring to lost or overwritten ciphertext. | Adversarial crash-consistency inspection. |
| `BF-scorchkit-cell-service-state-split-001` | Two processes could share one cell database while enforcing different in-memory event and admission state. | Adversarial process-isolation inspection. |
| `BF-scorchkit-resolved-secret-alias-001` | Different configuration references could resolve to the same bearer or encryption key across cells. | Adversarial key-isolation inspection. |
| `BF-scorchkit-mutation-coordinate-misread-001` | Repair assertions targeted neighboring compound guards because survivor coordinates were read against the changed file rather than the preserved baseline. | Exact survivor recheck. |
| `BF-scorchkit-validation-root-fixture-leak-001` | An exported original-root override contaminated a nested pre-commit selftest's disposable repository. | First exact-mirror focused gate. |
| `BF-scorchkit-sibling-database-env-leak-001` | ScorchKit's delivery database URL reached pinned Rustal compilation and displaced Rustal's committed SQLx metadata. | Browser delivery lane. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-immutable-object-publication-001` | Publish encrypted objects as immutable digest-addressed versions and reconcile retirement through a durable transactional deletion ledger. | Database commit ambiguity must not make active metadata point to overwritten or missing ciphertext. |
| `PR-scorchkit-cell-service-exclusive-lease-001` | Hold one database-scoped connection-lifetime lease for every service cell whose correctness includes process-local journals, quotas, or admission state. | A unique database alone does not prevent two owners from splitting non-durable cell state. |
| `PR-scorchkit-resolved-secret-uniqueness-001` | Compare resolved credential and key values across isolation cells at startup, then zeroize the comparison state. | Unique references can alias the same authority or cryptographic material. |
| `PR-scorchkit-mutation-coordinate-baseline-001` | Resolve survivor coordinates against preserved baseline source and assert the immediate predicate truth table before exact recheck. | Source movement and compound guards otherwise make a plausible repair test target the wrong branch. |
| `PR-scorchkit-pinned-sibling-validation-mirror-001` | When a separately pinned sibling checkout is active, validate a fingerprint-identical worktree mirror beside a clean exact-pin sibling and bind the receipt to the original tree. | Delivery must neither reset unrelated work nor silently validate a different ScorchKit source snapshot. |
| `PR-scorchkit-package-database-env-boundary-001` | Expose each database URL only to the package or test lane that owns it, especially when one gate builds independent SQLx consumers. | An ambient live database can override another package's committed query metadata and produce false compile-time failures. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

The recalled rules drove the core security shape: credentials authenticate before routing, roles
only narrow the existing policy boundary, storage effects remain authorized and no-follow, recovery
is distinct-destination and verify-before-effect, and local operation stays complete. Inspection
then found the less obvious process, crash, secret-alias, capacity, and denial-order gaps before
delivery. The mutation campaign was expensive but bounded to one broad inventory and exact
follow-ups, and the validation mirror preserved unrelated Rustal work while proving the exact
ScorchKit tree. The avoidable validation-environment leaks and late strict-Clippy failure keep the
rating at four; the six new rules make those failure modes directly preventable in later tickets.
