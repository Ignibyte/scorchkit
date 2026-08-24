---
title: Durable finding validation and triage lifecycle — notes
pipeline_id: 8c4c93ca-e8f2-432f-a8fd-ff1b058d6851
---

# Durable finding validation and triage lifecycle — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-transition-audit-reconstruction-001` requires every state and
  evidence decision to be reconstructible; `PR-scorchkit-durable-canonical-parity-001` and
  `PR-scorchkit-projection-validate-canonical-001` require child/raw/duplicated-column validation
  before public reads; `PR-scorchkit-proof-evidence-own-provenance-001` prevents correlation from
  borrowing unrelated evidence; `PR-scorchkit-correlation-work-budget-001` requires independent
  input/detail/work/output bounds; `PR-scorchkit-attribution-not-authorization-001` and the SK-052
  model boundary keep model identity separate from authority; `PR-scorchkit-public-typed-canonical-redaction-001`
  requires consumer-side normalization; `PR-scorchkit-bounded-validator-mutation-table-001`
  requires exact enum/limit/compound predicate tests. These rules changed the plan from extending
  mutable `status` into a separate canonical append-only contract with exact projection parity.
- Recon: `tracked_findings.status/status_note` is updated in place; `VulnStatus` has seven legacy
  values but there is no history or authorization in storage. Canonical finding/evidence and agent
  analysis children already have strong durable validation. Attack paths provide the closest
  append-only transition/identity/storage pattern. `ControlService` is the provider-neutral command
  boundary used by HTTP, CLI, and MCP, and triage commands fit its existing `local_state` effect.
- Operator confirmation: the owner's overnight goal for the next roughly five dependency-ordered
  tickets confirms this plan and local commits. It does not authorize remote/public targets, live
  models, a push/PR, a FULL gate, or repeated broad mutation selection after survivor discovery.

## Phase 2 — Design

- Architecture: `scorchkit-core::triage` owns the closed seven-state vocabulary, actor kinds,
  canonical transition/correlation/suppression records, exact subject identities, normalization,
  matching, history reconstruction, legacy-state mapping, and independent ceilings. PostgreSQL
  stores canonical raw child documents plus duplicated identity/state/time/scope columns; the
  ordered child history is authoritative and `tracked_findings.triage_state` is validated as an
  indexed projection. `ControlService` derives the actor from its verified principal, authorizes
  the finding's canonical target as `local_state`/`active_safe`, and then invokes one transactional
  store operation. Public `FindingViewV1` attaches a complete `FindingTriageViewV1`; raw scanner
  JSON and evidence rows are never rewritten. Existing CLI/MCP status verbs call the same command
  through an explicit legacy mapping. Deterministic ingest compares material evidence independent
  of observation timestamps: a fixed rediscovery becomes `regressed`, while changed proof behind
  a prior disposition becomes `needs_context`.
- File manifest: add `crates/scorchkit-core/src/triage.rs`, `src/storage/triage.rs`,
  `migrations/013_finding_triage.sql`, `docs/architecture/finding-triage.md`, and
  `tests/finding_triage.rs`; update core/storage/control/CLI/MCP exports and contracts,
  `src/storage/findings.rs`, `src/control/service.rs`, CLI finding dispatch/rendering, MCP parameter/
  tool compatibility, terminal/HTML/PDF/SARIF triage projection helpers, external control fixture,
  release migration fixtures, README, SECURITY, control/evidence/model/report/storage architecture,
  roadmap, changelog, knowledge register, and pipeline artifacts. No new transport, scanner,
  provider, frontend, or direct database client is added.
- Durable design: migration 013 creates one canonical initial transition for every legacy finding,
  maps the seven old states into the new closed vocabulary, and adds append-only transition,
  correlation, and suppression tables. Transition writes lock the parent, rebuild and validate the
  complete history, verify every cited evidence/model-analysis identity belongs to that parent,
  append idempotently or reject identity conflicts, and update only the validated current-state
  projection. Correlation writes additionally lock and validate every contributing project finding.
  Suppression scope is one exact closed shape over safe derived subject identities, and its active
  verdict is computed at read time from match plus expiry/review.
- Compatibility design: `new` maps to `needs_context`; `acknowledged` to `validated`;
  `false_positive` to `false_positive`; `wont_fix` and `accepted_risk` to `accepted_risk`; and
  `remediated`/`verified` to `fixed`. The duplicated legacy status remains a safe adapter projection,
  not history authority. The MCP tool name and CLI `finding status` syntax remain stable, but both
  now require the configured engagement and reach `ControlCommandV1::TransitionFinding`.
- Regression test plan: direct state-transition and legacy-mapping tables; exact text/count/time
  boundaries; each suppression scope and independent mismatch; canonical redaction and identity
  mutation matrix; transition chain/order/duplicate/conflict checks; same-finding evidence and
  model-reference negatives; immutable raw finding/evidence bytes; fixed rediscovery and material-
  evidence change with concurrent/idempotent ingestion; PostgreSQL row/raw/parent/state/time/scope
  corruption; control missing-principal/grant/target denial before write; CLI/MCP/API/report parity;
  external schema snapshot; migration/upgrade; default/all-feature strict Clippy; fast development
  gate; one authenticated DIFF delivery gate followed only by exact survivor repair if needed.
- Operator confirmation: the owner's explicit overnight direction to proceed through SK-053 and
  later dependent tickets confirms this design and local delivery. It does not authorize remote
  effects, a live model call, push/PR, FULL mutation, or repeat broad mutation runs.

## Phase 3 — Implement

- Files and behavior changed: added the core seven-state triage, actor, transition, correlation,
  suppression, subject, legacy-mapping, material-evidence, identity, and bounded canonical
  validation contracts. Migration 013 maps every legacy status, seeds one canonical initial
  transition, adds append-only correlation/suppression children, and retains validated compatibility
  projections. Finding ingest now appends the initial state, serializes equivalent identities,
  emits one deterministic regression for concurrent fixed rediscovery, and returns dispositions to
  `needs_context` after material proof drift. Storage reconstructs all children with sentinel
  limits, duplicated-column/raw-document parity, exact evidence/contributor ownership, and
  same-finding analysis references.
- Files and behavior changed: the control contract adds transition, correlation, and suppression
  commands plus complete finding triage and project-report summaries. `ControlService` authorizes
  the canonical runtime/source/artifact/network/cloud finding target as `local_state`/
  `active_safe` before any write. Existing CLI and MCP status operations map legacy vocabulary into
  the same transition command; finding reads/resources and project reports consume the same
  fail-closed control projection. Tests cover immutable scanner/evidence bytes, cross-surface
  parity, exact suppression, foreign provenance, unauthorized no-write, corrupt children, cloud
  scope, concurrent rediscovery, migration seed parity, and legacy status compatibility.
- Files and behavior changed: added `docs/architecture/finding-triage.md`; updated evidence, model,
  control, storage, report, README, SECURITY, roadmap, changelog, release-upgrade, external-schema,
  and pipeline documentation. Strict all-feature Clippy and focused core/control/PostgreSQL tests
  are green.
- Implementation review tightened the public bounds and concurrency contract before inspection:
  transition and correlation histories now reject the first over-limit append; project suppression
  writes serialize in project-before-finding lock order and cannot create a projection that exceeds
  its bound; multi-finding correlations take sorted advisory locks before row locks; suppression
  reads validate origin ownership. Rediscovery uses the durable scan observation time, and retrying
  the same scan neither changes the disposition nor increments `seen_count`.
- Design deviations: scan-time terminal/JSON/HTML/PDF/SARIF render immutable `ScanResult` data and
  cannot truthfully project a durable lifecycle before persistence, so canonical durable triage
  reporting is implemented in `GetProjectReport` and documented explicitly rather than inventing
  state in scan-time reports. The implementation initially boxed every control command to reduce
  one future size; review restored the existing public Rust command shape and boxed only internal
  futures. Review also replaced the first HTTP-only mutation authorization draft with typed
  multi-target policy derivation.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Durable-parity critic | Selecting suppressions by duplicated scope columns let a corrupted selector remove its row from the validation query, so a malformed child could be hidden. | high | Fixed: writes now cap and serialize the whole project ledger; reads validate every project suppression, origin, raw document, and duplicate before filtering canonical scopes. A PostgreSQL raw/parent/state/time/scope corruption matrix proves complete-read failure. |
| 2 | Concurrency/bounds critic | Read sentinel limits did not prevent the first over-limit append, opposite-parent correlation writes could take row locks in conflicting order, and project suppressions needed a project-before-finding order. | high | Fixed: transactional write ceilings, sorted per-finding advisory locks, project serialization, exact-limit core/storage tests, and lock-order review. |
| 3 | Historical-integrity critic | Revalidating a correlation's scanner inventory against the latest mutable finding snapshot could make a valid append-only decision unreadable after cross-scanner rediscovery; identical evidence outside the contributor set could also create a false ownership failure. | medium | Fixed: read validation proves canonical contributors and cited evidence ownership, requires cited evidence scanners in the preserved decision inventory, ignores unrelated duplicate evidence, and no longer rewrites historical scanner truth from the latest snapshot. Cross-scanner rediscovery retains the decision. |
| 4 | Retry/determinism critic | Same-scan persistence retries could increment `seen_count` and regress a fixed finding, while system transition identity used wall-clock time instead of the durable scan observation. | high | Fixed: same-scan writes are idempotent for count/disposition, distinct scans drive reappearance, and stored scan time supplies the system transition timestamp. Concurrent two-scan tests prove exactly one state correction. |
| 5 | Boundary critic | Foreign caller references and malformed correlation shapes surfaced as canonical durable corruption; the control validator did not require the correlation parent among contributors. | medium | Fixed: caller-originated validation/ownership failures are typed invalid requests, the control contract requires the parent, and restored durable rows retain projection-mismatch classification. |
| 6 | Compatibility critic | The shared MCP finding resource correctly moved to `FindingViewV1`, but a direct JSON assertion remained at the old top level; missing findings inside an existing project could lose resource-not-found semantics, and CLI output echoed the requested legacy alias instead of the actual projection. | low | Fixed: MCP asserts `canonical.title` plus triage, existence is classified before canonical loading, the 77-test MCP suite is green, and CLI prints the returned compatibility projection. |

## Phase 4 — Validate

- Tests run (commands and outcomes): focused core, control-contract, control-service, storage, MCP,
  CLI dispatch, and real PostgreSQL finding-triage suites are green; strict all-feature workspace
  Clippy is green. `bash bin/mutants.sh --inspect` reports 12,014 configured mutants across 325
  workspace source files with the policy kernel included and composition binary excluded.
- Gate run and receipt: the completed `bash bin/gate.sh --diff` passed all 18 applicable
  non-mutation lanes and selected 598 mutations: 357 caught, 195 missed, 46 unviable, 64.67% viable
  MSI. The immutable raw result is preserved under
  `.git/scorchkit-mutants-focused-ticket-031/initial`. Per owner direction and the focused repair
  amendment, no second DIFF or FULL mutation run occurred.
- Exact survivor evidence: the first 195-name recheck caught 164 and isolated 31 residuals; the
  31-name recheck caught 28 and isolated three selector-guaranteed defensive checks; the final
  three-name recheck caught all three. The mechanically assembled cumulative recheck contains one
  successful baseline plus the raw latest outcome for every one of the original 195 survivor
  names. `bash bin/focused-mutation-evidence.sh --verify` reconstructs 552/552 viable caught, 46
  unviable, zero misses, 100% MSI, mutation-input hash
  `38c8435887939570c6cd533eb45766074eaa9e0d81f748772075023f7592dca2`, and evidence digest
  `b6f08ad14dc1d370d6fbd2c6941bf6d753eba035c7f71e7aae3c0eb43e6f1870`.
- Post-repair tests: strict all-target/all-feature workspace Clippy passed; focused core, MCP exact-
  page, outer correlation-bound, and nine storage unit tests passed, including authenticated
  PostgreSQL exact 1,000/1,001 child bounds, contributor guards, and independent duplicated-column
  replay checks. The authenticated pre-completion `bash bin/gate.sh --focused-repair` passed all 19
  applicable lanes with zero failures and three named web-only skips, recorded 85.55% line
  coverage, passed 2,189 strict Nextest cases with 10 reasoned skips, and passed PostgreSQL plus
  CLI/MCP contracts. Its mutation lane verified the sealed evidence without launching
  cargo-mutants; post-archive delivery will rerun the same mode for the exact archived tree.
- Documented skips with reasons: no remote/public scan target or live model/service is authorized.
  Browser, website-rendering, and built-CSS lanes remain named not-applicable skips because the
  repository ships no web UI or CSS asset pipeline. No FULL gate or repeated broad mutation
  selection is authorized.

## Phase 5 — Complete

- Docs updated: README, SECURITY, changelog, finding/evidence/model/control/storage/report
  architecture, external control fixture, release upgrade contract, roadmap, ticket index,
  knowledge register, and pipeline artifacts describe the shipped lifecycle and its validation.
- AAR submitted: `docs/planning/knowledge/aar/AAR-031-finding-triage.md` on 2026-08-24 with
  effectiveness 4/5.
- Archive: `bash bin/pipeline.sh pass complete` will close TICKET-031 and archive this spec/notes
  pair; the same approved focused-repair gate will then produce the exact post-archive delivery
  receipt before commit.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first fast gate reported the all-feature test lane red while an immediate identical isolated workspace suite passed. | A non-reproducible shared test-run condition; no failing case survived isolation. | Re-ran the exact all-feature workspace suite and continued only after green; the later fast gate remains required. | Treat a gate aggregate as authoritative for delivery but reproduce the named lane before changing source. |
| 2 | The release-upgrade assertion expected `acknowledged` legacy data to seed `needs_context`. | The new test expectation contradicted the locked explicit legacy map. | Pinned `acknowledged` to canonical `validated` and validated the complete raw seeded transition identity/schema/actor/time/column parity. | Derive upgrade expectations from the closed compatibility table, not a default-state assumption. |
| 3 | Initial triage authorization parsed every affected target as HTTP(S). | Existing control target helpers were web-specific while durable findings also carry source, artifact, network, and cloud locations. | Derive a typed policy target from the canonical finding location, with a bounded originating-scan fallback only when the location is not independently addressable; added cloud and classifier tests. | Every finding mutation must authorize the canonical typed target kind rather than reuse a presentation-specific helper. |
| 4 | Core validation accepted an initial `regressed` state and unbounded/control-bearing correlation facets. | The first transition and facet fields were reconstructed through individually valid types without enforcing those two compound invariants. | Reject initial regression and validate both normalized facet fields against the canonical identity bound and control-character rules. | Include impossible-initial-state and independent malformed-facet mutations in every closed transition/correlation table. |
| 5 | A first write beyond a durable history bound could poison later reads, and opposite-parent correlation writes could lock contributors in conflicting order. | Read-side sentinel bounds were present, but writes did not enforce the same ceiling; the parent row was locked before sorted contributor rows. | Enforce transition/correlation/project-suppression bounds transactionally, serialize project suppressions with project-before-finding row locks, and acquire sorted per-finding advisory locks before correlation row locks. | Review every bounded append-only child for both read and write ceilings plus a complete lock-order argument. |
| 6 | Retrying the same scan could increment observation count and regress a finding already marked fixed; system transitions used wall-clock time. | Rediscovery did not distinguish a new scan from an idempotent persistence retry and did not use durable scan time. | Preserve count/state on same-scan retries, validate the scan belongs to the project, and derive rediscovery transition time from the stored scan record. | Reappearance tests must include same-scan retry, distinct concurrent scans, exact count, and deterministic durable timestamps. |
| 7 | The fast gate's MCP resource test looked for `title` at the legacy top level after the resource was moved to the shared control projection. | The resource implementation correctly returned `FindingViewV1`, but one assertion still expected a raw storage row. | Assert `canonical.title` and the shared triage state; the complete 77-test MCP suite is green. | Whenever a public resource changes shape, update both schema fixtures and direct JSON-path assertions in the same patch. |
| 8 | Corrupting a duplicated suppression selector made the child disappear from the matching query and the public read succeeded. | Query relevance was decided from unvalidated duplicated columns, creating a fail-open ordering bug. | Validate the entire bounded project ledger and origin ownership first, then filter using the canonical raw scope. | Never use an unvalidated duplicate to decide whether its canonical row is subject to validation. |
| 9 | A valid correlation became vulnerable to future read failure when a contributor's latest scanner changed or identical evidence appeared on an unrelated finding. | Read validation tried to reconstruct historical scanner inventory from current snapshots and queried evidence outside the preserved contributor set. | Preserve the append-only scanner inventory, filter evidence reads to contributors, and prove cited evidence scanners are included without requiring equality to mutable current snapshots. | Historical decision validation must use append-preserved inputs, not mutable latest-state reconstruction. |
| 10 | Three defensive duplicated-column checks survived after every reachable database corruption case was covered. | Their current SQL selectors guarantee the same parent/identity values before the defensive projection check executes. | Added narrowly keyed test-only row injection so each fail-closed predicate is independently falsifiable without changing production query behavior. | Preserve direct test seams for defensive checks whose current selector makes their failure state unreachable. |
| 11 | The first final three-name mutation attempt stopped in its unmutated baseline before testing a mutant. | The disposable database owner authenticated and could migrate, but lacked the `CREATEDB` capability required by the release-upgrade test. | Recreated the exact disposable database under a dedicated local test role with `CREATEDB`; the repeated three-name allowlist then caught all three. | Preflight the complete database capability required by the selected test suite, not authentication alone, before an isolated mutation baseline. |
