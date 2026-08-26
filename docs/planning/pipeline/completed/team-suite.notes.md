---
title: Add an authenticated multi-user deployment profile — notes
pipeline_id: d13e74eb-1bc8-44e0-be40-31a530d09fe6
---

# Add an authenticated multi-user deployment profile — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-attribution-not-authorization-001`,
  `PR-scorchkit-local-api-principal-boundary-001`,
  `PR-scorchkit-remote-session-principal-001`,
  `PR-scorchkit-remote-request-lifecycle-001`,
  `PR-scorchkit-durable-canonical-parity-001`,
  `PR-scorchkit-durable-worker-foreground-separation-001`,
  `PR-scorchkit-restore-integrity-before-effect-001`,
  `PR-scorchkit-authorize-validate-consume-one-handle-001`,
  `PR-scorchkit-credential-use-separate-grant-001`, and
  `PR-scorchkit-scoped-tool-artifacts-001`.
- Recon: current remote MCP authenticates before principal-specific routing but deliberately binds
  every principal to the one active engagement. The control API revalidates that engagement and
  canonical data but owns one bearer and one service. PostgreSQL jobs/webhooks are durable queues,
  while events are bounded per-service memory. Existing canonical tables are not tenant-keyed and
  jobs/findings have indirect project ownership, so row-level retrofitting would leave isolation
  dependent on every current and future query.
- Isolation decision: use one deployment cell per organization/project with a distinct database,
  control service, queues, journal, encrypted object root, key ring, quota, retention policy, and
  audit trail. Credentials select cells before request parsing and are never reusable across cells.
- Recovery direction: extend the release rule that verifies a snapshot immediately before and
  after restoring into a distinct database. Team manifests additionally bind cell identity,
  migrations, encrypted object inventory, and key identifiers; no in-place restore is added.
- Mutation direction: use one DIFF inventory. Preserve any survivors and rerun only their exact
  names after focused repairs; never launch a second broad inventory.
- Operator confirmation: the user's standing direction is to proceed through the next roadmap
  tickets, commit completed work locally, avoid pushes, and avoid unnecessary repeated broad
  mutation runs. That confirms SK-056 from the canonical ordered backlog and this bounded plan.

## Phase 2 — Design

- Architecture:
  - Add an optional root `team` feature over `control-api` and storage. A provider-neutral team
    contract in `scorchkit-control` describes the outer principal, role, object, audit, quota, and
    recovery envelopes; `scorchkit-config` owns serializable cells, bindings, key references,
    authorities, and bounds. The root package alone owns credential/key resolution, PostgreSQL,
    filesystem encryption, workers, and HTTP transport.
  - One prepared cell clones the safe application configuration but substitutes its exact enabled
    engagement, opens and migrates one environment-indirect PostgreSQL database, verifies that the
    database contains exactly the configured project, creates one `ControlService`, and owns one
    event journal, quota state, encrypted object root, key ring, and audit writer. Startup rejects
    equal live database identities or overlapping canonical roots across cells.
  - The listener remains loopback-only behind an explicitly trusted same-host TLS proxy. Exact Host
    and optional Origin, body, concurrency, event, and response bounds apply. A constant-time bearer
    digest lookup selects one binding containing subject, cell, role, and engagement before JSON,
    route identifiers, or client headers can influence authority; the authorization header is
    removed before downstream routing.
  - `POST /v1/team/control` wraps the existing v1 operation outcome in a team-principal envelope.
    Reader may query; analyst adds finding transitions/suppressions/correlation; operator adds
    target and job lifecycle commands; administrator adds object retention, key rotation, audit,
    and recovery inspection. Project create/delete is denied in the team transport because project
    identity is a deployment-cell invariant. Every allowed operation is subsequently processed by
    the unchanged `ControlService` engagement and canonical-data checks.
  - Before each operation, the gateway rechecks the cell identity singleton and exact project-row
    census. Start-job additionally proves the canonical target is registered to that project.
    Wrong-cell project, finding, job, target, event, object, cursor, or correlation identities are
    indistinguishable from absence because no cell can query another database or journal.
  - Each mutation first commits an append-only credential-safe intent audit. The terminal outcome
    is a second append; if terminal audit fails, the durable intent remains outcome-unknown and a
    recovery pass can close it without hiding the attempted effect. Database triggers reject audit
    update/delete. Reads and authentication denials are recorded after bounded admission when a
    cell is known; unknown credentials produce credential-safe host tracing only.
  - Team object PUT/GET/rotate/retention routes use exact lowercase SHA-256 object identities.
    Writes first require `LocalState` plus exact `Passive` authorization for the canonical cell
    root, then use a no-follow owned file path and Ring AEAD with a random nonce and cell/metadata
    AAD. PostgreSQL metadata, ciphertext header, plaintext digest, key identifier, kind, size, and
    expiry must agree. Key values are 32-byte environment inputs held in zeroizing buffers; config,
    errors, audits, manifests, and responses contain only key IDs.
  - A versioned backup manifest binds cell identity, source database identity, migration ledger,
    canonical identity probes, database snapshot digest, encrypted object inventory/digests, key
    IDs, and creation time. Verification is pure and bounded. The PostgreSQL recovery integration
    uses `pg_dump`/`pg_restore` only against disposable source and distinct destination databases,
    verifies before and after consumption, and proves corruption and same-destination refusal.
  - Local `AppConfig`, CLI/MCP/control/console startup, root database behavior, and default feature
    graph do not construct or require team state. The console remains a local client in this ticket;
    a proxy or later UI adapter may call the team API but receives no database, key, or bearer.
- File manifest:
  - Contracts/config: `crates/scorchkit-control/src/team.rs`,
    `crates/scorchkit-config/src/team.rs`, their `lib.rs`/feature manifests, root and CLI feature
    wiring, and exact workspace-direction assertions.
  - Runtime: `src/team/{mod,auth,service,object_store,transport,recovery}.rs`,
    `src/cli/team.rs`, CLI argument/runner wiring, and `migrations/014_team_service.sql`.
  - Verification: unit tests beside each contract/runtime module,
    `tests/team_service.rs`, `tests/team_recovery.rs`, focused configuration/control/CLI/workspace
    contracts, and gate 21 PostgreSQL wiring. Fixtures remain local, disposable, and loopback-only.
  - Operations/docs: `docs/architecture/team-service.md`, README, SECURITY, configuration/control/
    workspace architecture, changelog, roadmap, intake/ticket/spec/notes/AAR/index, and any exact
    backup helper required by the recovery rehearsal.
- Regression test plan:
  - Exact configuration edges for authorities, bindings, roles, cells, databases, roots, keys,
    quotas, retention, body/response/concurrency/subscriber limits, duplicate values, overlap, and
    secret-redacted Debug/parser errors.
  - Exhaustive role versus every v1 control operation and every team-only route, including project
    lifecycle denial and proof that denial precedes service, database, object, or worker effects.
  - Real two-cell PostgreSQL/HTTP fixture with concurrent same-cell users, wrong-cell UUIDs,
    spoofed subject/organization/project/role/engagement headers and bodies, token collision,
    expired/disabled engagement, corrupt cell identity, database alias collision, queue/quota
    exhaustion, event cursor isolation, cancellation/recovery, and anti-enumerating errors.
  - Object exact/over-limit round trips, nonces, ciphertext inequality, plaintext/ciphertext digest
    drift, AAD/header/metadata tampering, unknown/retired keys, rotation, idempotency, quota,
    retention, symlink/path replacement, partial write, cleanup, and key/error/audit redaction.
  - Audit intent/outcome parity, unknown terminal recovery, immutable trigger, sequence concurrency,
    bounded details, and absence of bearer/key/database credentials in durable rows or responses.
  - Disposable backup snapshot/manifest/restore across database and encrypted objects; changed
    snapshot, changed object, missing key ID, migration drift, identity drift, and same-destination
    negatives; restored project/job/finding/evidence/triage/audit/object identities must match.
  - Default/no-team config serialization, headless CLI/MCP/control behavior, optional Rustal console
    build, all feature states, root package direction, fast gate during development, one DIFF gate
    for validation, and exact survivor-only follow-up if needed. No FULL/no-mode gate or public/
    remote target is authorized.

## Phase 3 — Implement

- Files and behavior changed:
  - Added feature-scoped team contracts and configuration in `scorchkit-control` and
    `scorchkit-config`, including the exhaustive role matrix, server-bound principal and audit
    projections, trusted-proxy authorities, environment-indirect secrets, cell/key/root identity,
    and exact hard quota and retention validation.
  - Added `migrations/014_team_service.sql` for immutable cell identity, encrypted-object
    metadata, a durable retired-ciphertext deletion queue, durable request admission, and
    self-describing append-only audit events protected by database triggers.
  - Added `src/team/` composition, authentication, service, transport, encrypted object store, and
    recovery modules. Each cell preflights a distinct live PostgreSQL identity and canonical root,
    reuses an independently configured `ControlService`, authenticates by a full-table
    constant-time digest selection, narrows every operation through RBAC, rechecks canonical cell
    identity, serializes active-job admission, and audits mutations with intent plus terminal
    outcome.
  - Added immutable plaintext/ciphertext-digest object versions with AES-256-GCM metadata AAD,
    private no-follow I/O, hard count/byte/expiry budgets, tamper detection, transactional key
    publication, and restart-recoverable cleanup for rotation and retention.
  - Added versioned bounded recovery manifests over exact cell/database/migration/snapshot/object/
    key/timestamp inputs and a distinct-destination verifier; the PostgreSQL qualification invokes
    `pg_dump` and `pg_restore` only for disposable local databases and reverifies before and after
    consumption.
  - Added the loopback `team-api` CLI/HTTP adapter, exact Host/Origin and bearer pre-routing,
    claimed-identity header stripping, bounded bodies/responses/concurrency, empty-body rejection,
    and control/audit/object/rotation/retention routes. Local defaults remain feature-free and
    inert.
  - Added two-cell PostgreSQL/HTTP and recovery integration coverage plus contract, configuration,
    CLI, workspace-direction, migration-gate, architecture, security, README, and changelog updates.
- Design deviations:
  - No scope or authority deviation. Adversarial implementation review strengthened the locked
    design by making audit records self-describing and by replacing in-place ciphertext rotation
    with immutable versions plus a durable deletion queue, so database commit ambiguity cannot
    make the active metadata point at overwritten bytes.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Isolation | Audit rows relied on database locality and were not independently bound to cell, organization, project, and engagement. | medium | Fixed: columns, wire projection, append/recovery paths, read-time identity checks, and integration assertions now bind all four identities. |
| 2 | Crash consistency | In-place key rotation and file-first retention could leave PostgreSQL metadata and ciphertext irreconcilable after an error or ambiguous commit. | high | Fixed: immutable plaintext/ciphertext-digest versions plus transactional `team_object_deletions`; startup and retry cleanup are durable and tested across rotation, retention, and restart. |
| 3 | Concurrency | An idempotent put swept “untracked” versions after releasing the inventory lock and could delete a concurrently published rotation. | high | Fixed: untracked sweeping occurs only while metadata is absent under the write lock; published/retired versions are reconciled only by transactional metadata and deletion rows. |
| 4 | Secret lifecycle | Encryption/decryption plaintext copies and bearer verifier digests were not zeroized on every success/error/drop path. | medium | Fixed: AEAD working buffers and request digests use `Zeroizing`; prepared verifier digests have redacted `Debug` and zeroizing `Drop`; temporary secret-digest sets and decoded keys zeroize. |
| 5 | Filesystem race | Canonical/symlink checks did not require a private root, leaving write-parent replacement safety dependent on ambient permissions. | high | Fixed: startup and every object operation require a non-symlink canonical Unix-private root, shards are created `0700`, and permission drift is exercised. |
| 6 | Process isolation | Two service processes could attach to the same cell database and split in-memory journal, rate, and job-admission state. | high | Fixed: a database-scoped connection-lifetime advisory lease allows one live service per database; every operation pings the lease and duplicate startup is tested. |
| 7 | Key isolation | Unique environment names did not prove unique resolved key or credential values across cells. | medium | Fixed: startup rejects reuse of any resolved database/key/bearer secret value and requires canonical base64 keys; duplicate resolved key and bearer tests pass. |
| 8 | Recovery integrity | Manifest creation time was unchecked and placeholder ciphertext could satisfy an inventory digest without matching a team envelope. | medium | Fixed: exact timestamp is an input invariant; each bounded object parses and matches schema, cell, object, key, nonce, plaintext/ciphertext size, and expiry metadata before manifest acceptance. |
| 9 | Recovery authority | A cell administrator could invoke the pure verifier for a manifest belonging to another cell. | medium | Fixed: the lazy post-RBAC verifier first binds manifest cell/organization/project/engagement/database identity to the authenticated live cell. |
| 10 | Capacity | Concurrent start/resume requests could both observe available active-job capacity. | medium | Fixed: cell-local job-capacity admission is serialized through dispatch; the live database count remains the canonical bound. |
| 11 | Admission accounting | A duplicate request-ID rollback removed the first matching rate reservation instead of the newly appended reservation. | low | Fixed: rollback removes the last exact reservation; nil request IDs are rejected before rate or durable admission and constrained in PostgreSQL. |
| 12 | Denial order | `std::future::ready` evaluated recovery verification before administrator permission and admission. | medium | Fixed: an async block defers all recovery parsing/hashing until after admission, identity, and RBAC checks. |
| 13 | HTTP parsing | Authenticated GET routes and empty-body POST routes did not all consume and reject unexpected body bytes. | low | Fixed: description, audit, object read, rotation, and retention use the same zero-byte timed body boundary; live HTTP coverage asserts rejection. |
| 14 | Recovery cleanup | Crash-left root staging files could accumulate outside the database object quota. | medium | Fixed: startup recognizes only strict owned temporary names, validates regular canonical files, applies a hard recovery bound, and removes them; restart coverage proves cleanup. |
| 15 | Test reliability | Disposable database cleanup attempted to terminate PostgreSQL maintenance workers and could fail after otherwise successful qualification. | low | Fixed: cleanup terminates client backends only; the two test-only databases left by the observed failure were explicitly removed. |

- Inspection target check: `bash bin/mutants.sh --inspect` completed with 12,791 configured mutants
  across 333 workspace source files. This inspected targeting only; it did not compile or execute
  mutants.
- Focused inspection verification: team-feature Clippy passed with warnings denied; 7 root team
  tests, 4 team configuration tests, 3 team control-contract tests, 2 feature-gated CLI tests, the
  real two-cell PostgreSQL/HTTP test, and both recovery tests passed.

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - `DATABASE_URL=postgresql:///scorchkit_gate_ticket034 bash bin/gate.sh --fast`: GREEN, 14 passed,
    0 failed, and 8 delivery-only skips.
  - Focused team/config/control/HTTP/recovery suites and strict workspace all-feature Clippy passed
    before the DIFF campaign.
- Gate run and receipt:
  - The completed one-worker DIFF selected 732 mutations across nine files and 149 functions: 562
    caught, 94 missed, 76 unviable, and zero timeouts. The 656 viable outcomes scored 85.67%, below
    the unchanged 95% floor, so the gate remained red and wrote no receipt.
  - The raw completed result is preserved in
    `.git/scorchkit-mutants-focused-ticket-034/initial`. The owner approved all and only the 94
    survivors in 37 functions across six files for focused repair and exact-name recheck; no second
    broad campaign is authorized.
  - The first completed exact-name repair recheck caught 92/94 at 97.87% MSI. Its two residual
    misses identified independent regular-file-root and retention-route conjunction cases that the
    first repair tests had not named directly. The completed artifact remains preserved as
    `.git/scorchkit-mutants-recheck-ticket-034`; it is diagnostic history, not delivery evidence.
  - After adding those two direct assertions, the canonical completed exact-name recheck caught
    94/94 with zero misses, timeouts, or unviable mutants. The sealed focused bundle at
    `.git/scorchkit-mutants-focused-ticket-034` reconstructs 656/656 viable outcomes caught at 100%
    MSI, verifies mutation input
    `aa6426e9d1df0895a98c668712be84ad4035cd63caee6ce338b300bbe0e88d62`.
  - The first focused delivery attempt then found one strict-Clippy diagnostic in the object-store
    mutation guard test. The pre-repair file is preserved under `followup-001`; only the
    behavior-preserving `map` plus `unwrap_or_else` to `map_or_else` rewrite changed mutation
    inputs. The completed follow-up selected all 26 baseline survivors in the nine affected
    object-store functions and caught 26/26 with zero misses, timeouts, or unviable mutants. The
    resealed bundle verifies current mutation input
    `bbd8ac5ddc35f3429461a7df7fdb79caa52f6904495e89c055da5cc01201604b` and evidence digest
    `78af0fc19898b3041b3e7e7bb11c20f3af193ad6c408dcbc63890a7491375b2d`.
  - The same attempt found the shared `/srv/stacks/rustal` checkout on an unrelated dirty branch
    rather than ScorchKit's approved `8b741c4c0e4c87542dea575aea9be9acfa3bf728` dependency pin.
    Validation did not reset or edit that sibling. A disposable shared Git clone checked out the
    exact clean pin beside an exact disposable ScorchKit worktree mirror; the mirror and original
    gate-state fingerprints were required to match before execution, while
    `SCORCHKIT_PROJECT_ROOT` bound focused evidence and the receipt to the original worktree. The
    pinned `bash bin/console.sh check` passed formatting, strict Clippy, 13 unit tests, five real
    HTTP integration tests, and doc tests.
  - The first mirrored gate invocation exported `SCORCHKIT_PROJECT_ROOT` to every child process.
    Gates 1–8 and 10–14 passed, but gate 9's pre-commit selftest correctly rejected the inherited
    real active-pipeline state instead of observing its disposable fixture, so delivery lanes were
    skipped and no receipt was written. Keeping the same project-root binding shell-local and
    non-exported preserves original-tree receipt ownership without contaminating child fixtures;
    the isolated pre-commit selftest then passed before the receipt-producing rerun.
  - The corrected full focused-repair attempt passed 21/22 lanes: formatting, the strict Clippy
    feature matrix, all-feature tests, documentation, dependency/security/static checks, 85.82%
    region and 85.85% line coverage, sealed 656/656 focused mutation outcomes, render/CSS checks,
    2,246/2,246 nextest tests, PostgreSQL integration, and CLI/MCP contracts. Browser gate 17 alone
    failed before browser startup because the console's pinned Rustal build inherited ScorchKit's
    exported `DATABASE_URL` and SQLx tried that unrelated database as user `anonymous`. Rebuilding
    the console with only `DATABASE_URL` and `SCORCHKIT_DATABASE_URL` removed passed, followed by
    green conversation-workbench and Rustal-console browser interactions. The receipt-producing
    rerun therefore removes those variables only at the console Cargo boundary while retaining
    them for ScorchKit's database lanes.
  - The exact fingerprint-matched rerun with that package-scoped environment boundary passed all
    22 focused-repair lanes with zero failures or skips and wrote the delivery receipt for
    worktree fingerprint `35e9b95fe8518f7d879a87683c229cdbceae490a779f6b5d2f3d44519c7df21a`.
    Coverage reported 85.81% regions, 83.06% functions, and 85.85% lines; nextest passed
    2,246/2,246 executed tests with ten configured skips; the PostgreSQL lane passed 105 tests
    across MCP, storage, recovery, and two-cell isolation suites; CLI/MCP contracts passed 116
    tests. Focused evidence remained 656/656 viable outcomes caught at 100% MSI with the same
    mutation input and evidence digest recorded above.
- Documented skips with reasons:

## Phase 5 — Complete

- Docs updated: README, SECURITY, changelog, configuration/control/storage/workspace/team-service
  architecture, roadmap status/evidence/backlog, intake/ticket indexes, knowledge register/AAR,
  migration and release qualification, and the pipeline spec/notes describe the optional hard-cell
  team profile, unchanged local authority boundary, exact recovery contract, and sealed focused
  mutation evidence.
- AAR submitted: `docs/planning/knowledge/aar/AAR-034-team-suite.md` on 2026-08-26 with
  effectiveness 4/5 and six new reusable failure/prevention pairs.
- Archive: `bash bin/pipeline.sh pass complete` will close TICKET-034, remove it from the open
  queue, archive this spec/notes pair, and rewrite active/open cross-links. Post-archive delivery
  will rerun the same 22-lane focused-repair gate from the exact validation mirror; gate 16 will
  verify the sealed 656/656 viable evidence without launching cargo-mutants before commit and push.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Fast gate metadata lane rejected the new manifests. | New dependencies were not lexically sorted. | Sorted only the changed root/config manifests without retaining unrelated formatter churn. | Run the exact metadata lane before phase transition. |
| 2 | One recovery-test cleanup failed after qualification. | Cleanup included a PostgreSQL maintenance backend the test role could not terminate. | Restricted termination to client backends and removed the two resolved disposable databases. | Keep destructive fixture cleanup type-scoped and exact-name validated. |
| 3 | The DIFF gate's release-upgrade test rejected the new migration ledger. | Its exact current-ledger assertion still named migration 013 after this ticket added migration 014. | Advanced the expected migration count and latest version to 14. | Treat every added migration as requiring the release-boundary ledger assertion to advance in the same ticket. |
| 4 | The first survivor recheck left two misses despite clearing the 95% floor. | The repair assertions named neighboring compound guards instead of independently exercising a regular file as an object root and the exact retention method/path conjunction. | Added a direct regular-file-root rejection and the exact retention route guard contract, simulated both mutations locally, then completed the canonical 94-name recheck at 100% MSI. | Resolve mutation coordinates against the preserved baseline source and assert the immediate predicate truth table rather than inferring the targeted clause from the enclosing function. |
| 5 | The first focused delivery pass failed strict Clippy after the main mutation seal. | A mutation-oriented source-section helper used `map(...).unwrap_or_else(...)`, which the repository lint profile requires as one `map_or_else` expression. | Preserved the sealed object-store input, applied the behavior-preserving rewrite, passed the direct guard test and strict all-feature Clippy, and caught all 26 mutations in the nine affected functions before resealing. | Run strict all-target Clippy after the final mutation assertion edit and before sealing current-tree mutation evidence. |
| 6 | Console validation rejected the sibling Rustal checkout even though ScorchKit's pin had not changed. | The shared sibling was actively developing unrelated Rustal work at a different dirty revision, and ScorchKit correctly refuses to build that source. | Left the sibling untouched; ran validation from an exact fingerprint-matched disposable ScorchKit mirror beside a clean disposable Rustal clone at the approved pin, with the receipt still bound to the original tree. | Treat separately pinned sibling dependencies as immutable validation inputs and use an exact disposable checkout when the shared working copy is active. |
| 7 | The first exact-mirror gate failed only the pre-commit selftest and skipped delivery lanes. | Exporting the original project-root binding caused the selftest's child hook to inspect the real active pipeline instead of its disposable repository. | Kept the binding non-exported in the gate shell, proved the pre-commit selftest green in isolation, and retained the original worktree/evidence as the receipt target. | Scope validation-root overrides to the process that consumes them; do not leak fixture-control variables into nested selftests. |
| 8 | The corrected full gate failed only the console build at browser gate 17. | ScorchKit's delivery database variables reached the independently pinned Rustal dependency, so SQLx preferred that unrelated live database over Rustal's committed query metadata and peer-authenticated as `anonymous`. | Removed `DATABASE_URL` and `SCORCHKIT_DATABASE_URL` only from console Cargo invocations; the clean pinned build and both browser interactions then passed while ScorchKit retained its database context. | Keep database environment ownership at the package/test boundary when one validation process builds independently pinned database consumers. |
