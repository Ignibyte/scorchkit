---
title: Source-to-runtime attack-path correlation and focused verification — notes
pipeline_id: fa239f34-f7e8-46b3-b770-59f982e3fdee
---

# Source-to-runtime attack-path correlation and focused verification — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-canonical-evidence-identity-001` and
    `PR-scorchkit-identity-schema-label-parity-001`: canonicalize unordered inputs, length-prefix
    identity parts, and version record and identity schemas separately.
  - `PR-scorchkit-finding-observation-transaction-001`: append distinct evidence/analysis while the
    canonical identity is transactionally locked.
  - `PR-scorchkit-untrusted-finding-channel-redaction-001`: normalize and redact every untrusted
    description, flow message, HTTP field, and diagnostic at construction and projection.
  - `PR-scorchkit-scan-coverage-projection-parity-001`: incomplete coverage must remain incomplete
    across storage and public projections.
  - `PR-scorchkit-operation-coverage-method-route-001`: runtime operation proof requires both method
    and normalized route, not URL coincidence.
  - `PR-scorchkit-adapter-terminal-state-authority-001`: canonical typed evidence, not adapter or
    host inference, owns terminal state.
  - `BF-scorchkit-correlation-delimiter-collision-001`: prior finding work proved delimiter-joined
    correlation identities can collide.
- Recon evidence:
  - The core has 14 heuristic rules and MCP has a separate six-rule engine; both match titles and
    module IDs, and neither owns a stable path/evidence/state contract.
  - Durable MCP correlation currently discards finding-v2 location, code-flow, provenance,
    correlation keys, and evidence before matching.
  - Finding v2, ZAP, Nuclei, Semgrep/SARIF, and PostgreSQL already provide the typed source/runtime
    inputs required by this ticket.
- Operator confirmation: the owner directed work to continue to the next roadmap item, authorized
  automatic commits for green tickets, and retained the prohibition on repeated broad mutation
  scans.

## Phase 2 — Design

- Architecture:
  - Added `docs/architecture/source-runtime-correlation.md` with the provider-neutral facet,
    identity, state-machine, selector, persistence, compatibility, and no-effect boundaries.
  - Correlation consumes immutable canonical finding-v2 records. A shared weakness creates a
    suspected candidate; a precise shared application facet establishes reachability; source flow,
    redacted HTTP proof, shared weakness/application identity, and comparable deployment provenance
    are all required for reproduced.
  - Verification attempts are ordered, idempotent, and append-only. Only a complete comparable
    negative can mitigate prior reproduction; later proof becomes regressed. Scanner confidence is
    never rewritten.
  - Focused selections contain exact static rules, runtime probes/templates, redacted request
    metadata, and explicit test IDs. They are inert and require normal engagement authorization in
    any later execution workflow.
- File manifest:
  - `crates/scorchkit-core/src/attack_path.rs` and `lib.rs`: schemas, normalized facets, bounded
    correlation, path/member/gap contracts, proof state, transitions, and minimal selectors.
  - `src/engine/attack_path.rs`, `src/engine/mod.rs`, `src/lib.rs`, and `src/prelude.rs`:
    compatibility and public re-exports without moving domain ownership out of the core package.
  - `migrations/011_attack_paths.sql`, `crates/scorchkit-storage/src/lib.rs`,
    `src/storage/{mod,attack_paths}.rs`: project-scoped current path plus append-only transitions in
    an advisory-lock transaction.
  - `src/mcp/{tools,prompts}.rs`, MCP schemas/fixtures, and tests: reconstruct canonical durable
    findings, expose typed paths and gaps, and retain title/module chains only as explicitly legacy
    unverified output.
  - `src/report/{mod,attack_path}.rs` and report tests: canonical JSON, terminal-safe text, and
    escaped Mermaid projections from one path contract.
  - `docs/architecture/{source-runtime-correlation,mcp,report,storage}.md`,
    `docs/guide/codex-plugin.md`, README, changelog, roadmap, ticket, notes, and AAR: operator and
    delivery records.
- Regression test plan:
  - Facet table: route, method, parameter, component, weakness, application, deployment, explicit
    key normalization; empty/oversized values; delimiter ambiguity; sorting and deduplication.
  - Correlation matrix: weakness-only suspected; precise reachable; complete reproduced; missing
    flow, HTTP proof, weakness, application facet, or revision; conflicting revisions; different
    targets; hostile titles; agent-only claims; input nonmutation; stable permutation identity;
    finding/path count ceilings.
  - Transition table: complete and incomplete negatives, failed attempts, stale timestamps,
    duplicate identities, mitigated reproduction, regression, evidence retention, and scanner
    confidence invariance.
  - Selection table: minimal static rules, runtime probes, method/route/parameter/persona, explicit
    tests, exact digest/config identity, redaction, no bodies/credentials, empty and duplicate inputs.
  - Storage table: migration, project/path uniqueness, concurrent upsert, append-only transition
    identity, update without evidence loss, list order, deletion cascade, and JSON/schema parity.
  - MCP/report table: valid and malformed durable findings, typed gaps, compatibility labeling,
    exact schema/state/selection parity, terminal control neutralization, and escaped Mermaid labels.
  - Validation uses focused unit, integration, PostgreSQL, MCP, and report tests, then the fast gate.
    Mutation is limited to changed or inspection-repaired functions; no broad inventory is allowed.

## Phase 3 — Implement

- Files and behavior changed:
  - Added `scorchkit-core::attack_path`: versioned facets, stable length-prefixed identities,
    bounded correlation, suspected/reachable/reproduced proof states, focused selectors, canonical
    boundary validation, and append-only mitigated/regressed verification transitions.
  - Runtime HTTP proof is bound to the target revision on its own evidence provenance. Historical
    proof from another revision becomes `runtime_proof_revision_unbound`, not reproduced.
  - Added migration 011 and `storage::attack_paths`: one identity-locked path snapshot per project,
    append-preserved child transitions, stale/conflicting-history rejection, canonical readback,
    and deletion cascade. Added one batched project-evidence read for correlation.
  - Reworked MCP `correlate_findings` to reconstruct finding-v2 records and durable evidence, expose
    the canonical correlation schema and typed gaps, and place old title/module rules only under
    `legacy_unverified_attack_chains`.
  - Added complete redacted JSON, terminal-safe, and escaped Mermaid projections plus architecture,
    storage, MCP, report, plugin, README, changelog, and roadmap guidance.
  - Focused tests cover the proof-condition matrix, input/permutation stability, title/agent
    negatives, hard resource ceilings, selector redaction, state transitions, tamper validation,
    PostgreSQL history/cascade, MCP parity/malformed rows, historical revision binding, and report
    injection safety.
- Design deviations:
  - Verification transitions now preserve outcome and comparable conditions directly, in addition
    to the attempt identity, coverage, evidence, and observation time. The first draft retained too
    little of the attempt to satisfy the append-only audit requirement.
  - Added explicit per-finding-detail and pair-evaluation ceilings after adversarial review showed
    that finding and path-count ceilings alone did not bound an all-nonmatching cross-product.
  - Duplicate logical paths are resolved deterministically to the strongest supported state before
    the path ceiling is charged; the initial vector/dedup draft was input-order-sensitive.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Proof provenance | Append-preserved HTTP evidence from an older revision could be combined with current finding provenance and promote a new deployment to reproduced. | high | Fixed: runtime proof keeps its own evidence revision and must match the shared deployment; historical proof now produces `runtime_proof_revision_unbound`. |
| 2 | Audit history | Verification transitions retained only the attempt identity, so outcome and comparable conditions could not be independently reconstructed. | high | Fixed: transitions append coverage, outcome, conditions, evidence, and time, and canonical validation rebuilds the attempt identity. |
| 3 | Negative verification | Complete-comparable negative attempts did not prove that every selected scanner configuration was exercised. | high | Fixed: complete attempts require the exact normalized configuration identity set from the focused selection. |
| 4 | State cleanup | A later complete reproduction removed `missing_runtime_http_proof` but left `runtime_proof_revision_unbound`, producing a reproduced path with a contradictory gap. | medium | Fixed: successful comparable reproduction removes both runtime-proof gaps. |
| 5 | Boundary integrity | Path, storage, and report boundaries could accept nested state, selection, or transition content without rebuilding every canonical identity. | high | Fixed: `AttackPath::validate` checks schemas, identities, ordering, member and selection normalization, transition continuity, attempt reconstruction, and final state. Storage and reports fail closed. |
| 6 | Initial history | A coherently rewritten initial transition could change its state, evidence set, or observation time while retaining a self-consistent transition identity. | high | Fixed: the initial transition is bound to the member evidence union, latest member observation, and proof-gap/state invariants. |
| 7 | Duplicate paths | Equivalent logical paths charged the path ceiling and selected content according to input order. | medium | Fixed: paths are keyed by stable identity before the ceiling is charged and ties resolve deterministically to the strongest supported record. |
| 8 | Work bounds | Finding and path count ceilings did not bound per-finding nested details or a nonmatching source/runtime cross-product. | high | Fixed: detail and pair-evaluation ceilings return typed incomplete coverage gaps. |
| 9 | Candidate quality | A shared HTTP method alone could create a suspected path across unrelated application surfaces. | medium | Fixed: method-only intersections are rejected; a regression test covers the false link. |
| 10 | Facet parity | Semantically equivalent namespaces such as `route` and `http-route` did not normalize to one facet. | medium | Fixed: known facet kinds use canonical namespaces before identity and comparison. |
| 11 | MCP inventory bounds | MCP loaded the complete finding and evidence inventory before core limits could reject it. | high | Fixed: it counts findings first, bounds the evidence query at ceiling plus one, and reports typed incomplete coverage. |
| 12 | Durable parity | MCP trusted decoded raw finding/evidence JSON without checking identity, schema, timestamp, correlation-key, and canonical JSON parity with durable columns. | high | Fixed: malformed or divergent records are excluded and surfaced as typed incomplete gaps. |
| 13 | Coverage projection | MCP reported every durable row as analyzed even when malformed rows were excluded from canonical correlation. | medium | Fixed: responses distinguish findings available from canonical findings analyzed. |
| 14 | Report integrity | Text, JSON, and Mermaid helpers could project a tampered nested path before verifying the canonical contract. | medium | Fixed: every projection validates correlation ordering/status and nested paths first, then uses terminal-safe and Mermaid-safe rendering. |
| 15 | Timestamp precision | PostgreSQL microsecond timestamps were compared to nanosecond Rust values, falsely classifying valid restored transitions as corrupt. | low | Fixed: durable parity compares the precision PostgreSQL preserves. |

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - Focused core, report, storage, and MCP unit/integration tests passed on the build host with
    PostgreSQL, including exact 4,096/4,097 finding and 16,384/16,385 evidence boundaries.
  - Strict workspace/all-target/all-feature Clippy passed after test-only cleanup.
  - The fast gate passed all 14 active lanes with eight documented skips before focused mutation.
  - The owner-approved mutation inventory selected 216 mutations in 14 repaired functions across
    four production files. The initial run caught 135 and exposed 81 test-observability gaps. The
    exact survivor recheck caught 80; one equal-timestamp history boundary required one additional
    assertion, and its one-name follow-up was caught.
  - Sealed evidence `.git/scorchkit-mutants-focused-ticket-015` verifies 216/216 viable mutations,
    100% MSI, input hash `3a3f523eb470f6862c9a572a4f4d1fe42226cfe62ddc9f8f35a12a91a9b65bd5`,
    and evidence digest `9950f952367df94ce7ff87641381f416cd90d7e629f2a0fc63f341b62038d1ec`.
- Gate run and receipt:
  - `bash bin/gate.sh --focused-repair` passed 19 lanes, failed none, and issued a matching
    focused-repair receipt for the pre-completion tree. The same mode must be rerun after archive.
- Documented skips with reasons:
  - Browser E2E is not applicable until ScorchKit ships a web UI.
  - Website dogfood rendering is not applicable to the terminal security engine.
  - Built CSS sheets are not applicable because there is no web asset pipeline.

## Phase 5 — Complete

- Docs updated:
  - Added the source/runtime correlation architecture and updated MCP, storage, report, Codex plugin,
    README, changelog, roadmap, intake, and ticket guidance.
  - Added six reusable prevention rules and six failure patterns to the knowledge register.
- AAR submitted:
  - `AAR-015-source-runtime-correlation` submitted on 2026-08-21 with effectiveness 5/5.
- Archive:
  - Completion artifacts are ready for the repository pipeline's atomic archive transition; the
    post-archive tree requires the same focused-repair receipt before commit.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first fast gate rejected an unjustified `too_many_arguments` suppression. | A transition builder accumulated audit fields without a typed input object. | Replaced the long parameter list with `TransitionInput` and removed the suppression. | Keep transition audit fields grouped in one typed boundary and let the justified-suppression lane fail closed. |
| 2 | Strict Clippy rejected a redundant clone and an oversized boundary test added during mutation repair. | The first test draft optimized for rapid clause coverage rather than final test structure. | Consumed the last value directly and split finding/evidence ceiling coverage into separate tests. | Run strict all-target Clippy before sealing mutation inputs. |
| 3 | The initial focused mutation run left 81 surviving compound-guard and exact-boundary mutations. | Broad positive tests did not independently falsify every schema, parity, ordering, resource, and alias clause. | Added direct clause-by-clause unit and PostgreSQL boundary tests, then reran exactly the survivor inventory. | Treat every fail-closed conjunct and exact ceiling as an independent observable contract. |
| 4 | The exact survivor selector initially matched zero names. | The generated regular expression retained escaped line endings. | Regenerated it from stripped lines and proved the inventory was exactly 81/81 before execution. | Always compare the selected mutation-name set to the sealed survivor list before running. |
| 5 | One history-order mutation survived the 81-name recheck. | The equal-time test asserted append success but did not validate the resulting canonical path. | Added `AttackPath::validate()` to the equal-time regression and reran only that one mutation. | Boundary tests must exercise both the mutator API and the canonical read/validation boundary. |
