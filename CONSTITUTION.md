# ScorchKit Constitution

Binding rules for changing ScorchKit. The repository-owned pipeline and quality gate implement
these rules; agent-specific adapters may guide them but may not redefine them.

## §0 — Quality gates

`bin/gate.sh` is the single delivery verdict. `--fast` runs static gates and never writes a delivery
receipt. `--diff` runs the delivery set with mutation testing scoped to changed and untracked Rust.
`--full` runs the full mutation inventory. `--focused-repair` is available only under the explicit
repair-campaign amendment in §19. It verifies sealed focused mutation outcomes and runs every other
delivery gate without executing cargo-mutants. A green DIFF, FULL, or amendment-qualified
FOCUSED-REPAIR run writes `.git/scorchkit-gate-receipt`, bound to the exact current worktree and its
declared evidence mode.

Static gates in every mode:

1. Rustfmt.
2. Clippy with warnings denied across every feature state derived by `bin/feature-states.sh`.
3. All-feature Rust tests.
4. Rustdoc with warnings denied, including warnings Cargo prints without a failing exit status.
5. Cargo Audit.
6. Cargo Deny.
7. Cargo Machete.
8. Gitleaks.
9. ShellCheck plus workflow, hook, gate, and feature-state self-tests.
10. No unjustified lint suppression, blanket lint-group suppression, or ignored test without a
    nonempty reason.
11. Source bans: unsafe code, transmute, and library process exits.
12. No actionable TODO/FIXME/XXX markers outside planning documents.
13. Cargo Sort, Taplo, and typos.
14. Semgrep.

Delivery gates:

15. LLVM line coverage at or above the baked floor.
16. Mutation testing at or above 95% MSI. In an amendment-qualified focused-repair run, verify raw
    completed outcomes for every repaired survivor at the same floor and bind them to the exact
    mutation-relevant inputs. A later repair must prove its old-to-new input transition and add raw
    outcomes limited to the newly repaired functions.
17. Browser end-to-end checks: not applicable until ScorchKit ships a web UI; always a named skip.
18. Website dogfood rendering: not applicable; always a named skip.
19. Built CSS sheet drift: not applicable; always a named skip.
20. Nextest strictness: no empty non-binary suites, no retries, and bounded per-test timeouts.
21. PostgreSQL integration against a migrated database; missing `DATABASE_URL` is a failure.
22. CLI and MCP contract suites.

Gate numbers are stable. New checks take the next number rather than renumbering existing checks.
Missing tools fail closed. Cargo commands run sequentially; cargo-mutants may use its own bounded
workers. Coverage and mutation floors may rise through environment overrides but never fall below
their baked values. Fix sources—do not buy green with baselines, broad exclusions, retries, silent
skips, or blanket suppressions.

## §3 — Ticket pipeline

The only normal delivery path is:

```text
intake (optional) → ticket/create → plan → design → implement → inspect
                  → validate → complete/archive → delivery gate → commit/PR
```

- Keep at most one spec/notes pair in `docs/planning/pipeline/active/`.
- Every active change has a canonical ticket under `docs/planning/tickets/open/`, an active spec and
  notes pair, and an open AAR.
- Ticket and spec requirements use EARS: one observable `shall` behavior and one verification method
  per row.
- Plan and design require explicit operator confirmation, expressed by invoking the phase transition.
- Implement follows the confirmed design. Inspect is a separate adversarial review checkpoint.
- Validate writes and runs tests and produces a green DIFF/FULL receipt, or a FOCUSED-REPAIR receipt
  when the active ticket satisfies the §19 amendment.
- Complete updates durable docs, submits the AAR, archives the pair, and closes the ticket.
- Delivery reruns the same approved receipt-producing gate after completion because archival changes
  the worktree. DIFF is the normal mode.

`bin/pipeline.sh` owns deterministic creation, transitions, validation, and archival. Planning files
are the source of truth; no sidecar ticket system is required.

## §7 — Testing

Every behavior change gets meaningful automated tests. Tests must actually run. Database tests may
skip during an ordinary direct test command, but delivery gates 21 and CI must fail when the database
lane is unavailable. External-service or hardware gaps require a narrow reason in the pipeline notes.
Pre-existing failures are recorded and kept separate from the ticket unless the operator expands
scope.

## §14 — Code conventions

- Keep domain, policy, findings, evidence, and execution independent of CLI, MCP, storage, and agent
  providers.
- Deny unsafe Rust. Return typed errors on malformed or operator-controlled inputs.
- Document public items and modules. Justify every source suppression and ignored test locally.
- Preserve scanner evidence; agent analysis is a separate labeled layer.
- Comments explain why. Reuse existing seams before creating parallel ones.

## §15 — anti-circumvention

Evidence outranks prose. A claimed test or gate result is valid only when produced by the real
command. Do not weaken a gate, delete a test, lower a floor, or broaden an exclusion to finish a
ticket. The Git pre-commit hook checks a versioned content receipt from a real green delivery gate.
The receipt records DIFF, FULL, or FOCUSED-REPAIR. A focused receipt also records and rechecks the
sealed evidence digest. Staging does not change the receipt, but any content edit does.

## §18 — inspect and knowledge recall

Before plan and implementation, search the local knowledge register, comparable completed pipeline
notes, and relevant architecture documents. After implementation, perform independent correctness,
security, data-integrity, and simplification review where the change warrants them. Record findings
and dispositions in the inspect ledger. New reusable lessons go in both the AAR and the knowledge
register.

## §19 — local knowledge

ScorchKit owns its workflow knowledge in this repository:

| Surface | Location |
|---|---|
| Tickets | `docs/planning/tickets/` |
| Pipeline narratives | `docs/planning/pipeline/{active,queued,completed}/` |
| Knowledge register | `docs/planning/knowledge/INDEX.md` |
| AARs | `docs/planning/knowledge/aar/` |
| Architecture decisions | `docs/architecture/` |
| Bulletins | `docs/planning/bulletins/INDEX.md` |

Amendments must state the affected section and rationale. Tightening is routine; loosening must be
explicit and may not be smuggled into an unrelated ticket.

### 2026-08-16 amendment — focused repair delivery evidence

This amendment affects §§0, 3, and 15 for an owner-approved mutation repair campaign. A completed
broad mutation run can provide the survivor inventory needed to direct repairs. Repeating that broad
run after every repair adds hours of work without improving the evidence for the repaired seams.

A FOCUSED-REPAIR receipt is valid only when all of these conditions hold:

- The active ticket records the owner's approval and the exact repair scope.
- A completed DIFF or FULL result remains preserved as the broad baseline.
- The focused evidence contains the raw initial inventory and outcomes, the complete survivor
  recheck inventory and outcomes, and a summary reconstructed by the verifier.
- The verifier proves the survivor set and recheck set are identical, the final viable score is at
  least 95%, and the mutation-relevant Rust, tests, manifests, configuration, examples, migrations,
  and rules match the hash sealed after the focused run.
- If a later delivery pass exposes another source defect, the evidence preserves an exact snapshot
  of every changed mutation-input file, proves that substituting those snapshots reconstructs the
  prior sealed input hash, and includes a completed current-tree mutation run limited to the newly
  repaired functions. The cumulative viable score remains at least 95%. Changes outside that
  explicit transition require a new DIFF or FULL result.
- `bin/gate.sh --focused-repair` passes gates 1–15 and 17–22 on the current worktree. Gate 16
  verifies the sealed evidence and does not launch cargo-mutants.
- The versioned receipt names FOCUSED-REPAIR and binds the evidence digest as well as the exact
  worktree. The pre-commit hook rechecks both.
- A new broad inventory remains scheduled work and incomplete broad output is never reported as a
  passing result.

TICKET-001 is the first approved use. Its main repaired scope is 42 selected functions across 14
files, with 171 selected mutations and an exact three-survivor recheck. Its post-archive teardown
repair changed one previously snapshotted source file and tested six mutations in two functions,
producing cumulative evidence of 167/167 viable mutations caught and 10 unviable.

TICKET-002 is the second owner-approved use and is limited to SK-028. The owner explicitly directed
that mutation work remain on the files changed for this ticket and that the next broad run happen
later. A Git DIFF cannot express that boundary because TICKET-002 began on the still-uncommitted
TICKET-001 tree; its nominal inventory contains 1,038 mutants across 135 files. The approved scope
is therefore exactly 68 mutations in 35 functions across the five executor/orchestrator files. The
sealed evidence must retain the green initial baseline and raw outcomes, count test timeouts as
caught only where cargo-mutants records them as such, prove the exact two-survivor recheck, compare
the current generated mutation inventory with the initial inventory, and bind both sides of the
two-file inline-test transition with source snapshots and mutation-input hashes. The final score is
35/35 viable caught with 33 unviable. This approval does not turn focused delivery into the default
for later feature tickets and does not satisfy or cancel the scheduled broad inventory.
