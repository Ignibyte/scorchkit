---
title: Provider-neutral model analysis roles and evaluations — notes
pipeline_id: 1f4acf58-8c38-4c6b-a3a9-17c8db2e3d8d
---

# Provider-neutral model analysis roles and evaluations — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-provider-consumption-validation-001` requires response
  revalidation where the workflow consumes an external adapter; `PR-scorchkit-attribution-not-authorization-001`
  and `PR-scorchkit-model-access-claim-boundary-001` keep model identity and access claims separate
  from grants and evidence; `PR-scorchkit-public-evidence-revalidation-001`,
  `PR-scorchkit-durable-canonical-parity-001`, and
  `PR-scorchkit-projection-validate-canonical-001` require normalization, child-row parity, and
  validation before public projection; `PR-scorchkit-proof-evidence-own-provenance-001` requires
  each analysis to bind its own exact input identities; `PR-scorchkit-bounded-validator-mutation-table-001`
  requires direct tests for every enum/default/limit/compound branch; and
  `PR-scorchkit-workflow-gap-no-broad-substitution-001` requires an unavailable exact role to remain
  a gap rather than trigger broader work. The SK-030 AAR additionally shows that public provider
  envelopes must be rechecked outside built-in adapters. These rules changed the plan by requiring
  exact eligibility keys, a closed readiness truth table, durable analysis-child parity, and no
  fallback search.
- Recon: existing `scorchkit.ai/v1` owns four task-specific Codex/Claude CLI calls and only optional
  model/cost metadata. `AgentAnalysisRecord` already lives separately from scanner evidence and is
  persisted as a child row, while canonical finding projections already carry its raw JSON through
  control/MCP/SARIF. The child row is not independently revalidated on a canonical finding read.
  The current config has no role binding, execution location, service data policy, readiness, or
  evaluation contract. The shared `policy_http::build_service_client` and `ToolExecutor` already
  provide the required network/process ownership seams.
- Plan: add closed core contracts and corpus/evaluator first; add disabled-by-default explicit role
  configuration; compose exact readiness plus three bounded adapters in the root; convert only
  validated analysis responses into provenance-rich analysis records; validate durable child rows;
  expose readiness through the control contract and provenance through existing canonical
  finding/MCP/report paths; preserve the legacy `[ai]` surface.
- Operator confirmation: the owner directed ScorchKit to finish the exact mutation survivors,
  commit, and move to the next ticket, then explicitly authorized commits. That confirms TICKET-030
  planning and local delivery. It does not authorize model enrollment, remote/public model calls,
  a push/PR, a FULL gate, or repeating a broad mutation run after survivor discovery.

## Phase 2 — Design

- Architecture: `scorchkit-core::model_analysis` owns the six closed roles, three execution
  locations, v1 analysis/evaluation envelope, bounded redacted inputs, exact response validation,
  provenance, readiness states, five-class built-in corpus, evaluation outcome, and eligibility
  key. `scorchkit-config::model_analysis` owns disabled-by-default role bindings and adapter/data
  policy. Root `model_analysis` composes an exact binding with a process or service transport,
  rechecks provider/model/role/contract/kind, authorizes the supplied source target before a
  process, authorizes the service endpoint and credential separately before a no-redirect request,
  publishes an audit decision before send, and converts only valid analysis into the existing
  child analysis layer. Evaluation invokes the same adapter against every built-in case but does
  not require prior eligibility; production analysis does. Control readiness is a safe pure
  projection and existing canonical finding projections carry the complete analysis record.
- Authority and data design: host/local processes require `ExternalTool` with `passive` against the
  explicitly supplied code/web target. Service requests require `ExternalTool`/`active-safe` and,
  when a bearer reference is configured, `CredentialUse`/`passive` against the exact service URL.
  The endpoint is credential-free HTTP(S), redirects are disabled, body sizes and wall time are
  hard bounded, request strings are redacted before serialization, the credential is resolved only
  for the authorized send, and v1 accepts only `redaction = required` plus `retention = none`.
  Provider output has no grant, evidence, storage, finding-transition, or scanner-execution field.
- Identity and compatibility design: legacy `AgentAnalysisRecord::new` remains
  `scorchkit.agent-analysis/v1` with its unchanged identity inputs. New model records use
  `scorchkit.model-analysis/v1`, retain a complete optional provenance object, and compute identity
  from the canonical provenance plus redacted summary. Canonical finding normalization validates
  and sorts both forms. PostgreSQL rechecks every declared analysis child against its duplicated
  identity/schema/time and raw JSON. No migration is needed because migration 009 already stores
  versioned raw child documents. Existing `[ai]`, `AiProvider`, CLI, MCP, and autonomous behavior
  remains unchanged when `[model_analysis]` is absent.
- File manifest: add `crates/scorchkit-core/src/model_analysis.rs`,
  `crates/scorchkit-config/src/model_analysis.rs`, `src/model_analysis.rs`,
  `tests/model_analysis.rs`, and `docs/architecture/model-analysis.md`; update core/config/root
  module exports, `AppConfig`, `AgentAnalysisRecord`, canonical finding normalization,
  `src/storage/findings.rs`, control contract/resource/schema/service exports, HTML/terminal/PDF
  report labels, `SECURITY.md`, AI/control architecture docs, roadmap, changelog, and pipeline
  artifacts. Update exact workspace architecture/source-contract tests only if the new module
  boundary requires it. Do not add a migration, new scanner module, model vendor to core, or direct
  storage handle.
- Regression test plan: direct tables for all six roles, three locations, six readiness states,
  binding duplicates, identifiers, digests, confidence, input/count/byte/time boundaries, safe
  endpoint and environment reference clauses, retention/redaction requirements, exact eligibility
  key dimensions, complete/duplicate/missing/wrong corpus answers, and response schema/provider/
  model/role/kind mismatch. Add recording process tests for host/local invocation and authorization
  denial before executor; loopback service tests for endpoint/DNS authorization, credential-use,
  audit-before-send, redaction, bearer transport without serialization, no redirects, timeout, and
  first-byte-over-output-limit rejection. Add finding identity/evidence/status invariance,
  PostgreSQL child-row tamper/round-trip, control readiness schema, MCP canonical finding, and
  HTML/terminal/PDF/SARIF provenance assertions. Run focused tests and `bash bin/gate.sh --fast`
  during development, both default and all-feature strict Clippy before mutation sealing, then one
  `DATABASE_URL=... bash bin/gate.sh --diff`; preserve the completed raw result and use only exact
  survivor follow-ups if needed.
- Operator confirmation: the owner's direction to move immediately into the next ticket and commit
  each completed ticket confirms this design and local delivery. The design deliberately excludes
  any live remote model call, entitlement claim, automatic model choice, push/PR, FULL mutation, or
  repeat broad mutation sweep.

## Phase 3 — Implement

- Files and behavior changed: added provider-neutral roles, execution locations, typed
  analysis/evaluation envelopes, exact response validation, provenance, readiness, the immutable
  five-class corpus, deterministic all-pass evaluation, and exact eligibility keys in
  `scorchkit-core`; added disabled-by-default exact bindings and closed host/service/local data
  policy in `scorchkit-config`; composed readiness and bounded policy-owned process/service
  adapters in the root service. Every adapter consumes the same contract, rechecks provider/model/
  role/kind, and publishes an awaited decision before execution. Production use requires ready
  exact-key evaluation; the evaluation path intentionally permits an enabled, valid, available
  binding to produce its first result.
- Analysis boundary: extended `AgentAnalysisRecord` backward-compatibly with optional complete
  model provenance and a distinct `scorchkit.model-analysis/v1` identity. Model inputs,
  instructions, responses, durable summaries, and public projections reapply canonical redaction;
  manually constructed unredacted typed values fail validation. Finding identity, scanner
  evidence, policy, and lifecycle remain unchanged. HTML, terminal, PDF, SARIF, control canonical
  findings, and the MCP compatibility projection preserve provider/model/role/location labels.
- Durable boundary: canonical finding writes now reject invalid model provenance. Canonical reads
  independently load at most 1,000 append-preserved analysis children, revalidate raw JSON,
  identity, schema, parent, and timestamp, verify every declared child exists, and reattach all
  validated children before control/MCP projection. No migration was needed because migration 009
  already owns the versioned raw child table.
- Control and compatibility: added the side-effect-free `GetModelReadiness` query, a credential-safe
  six-role DTO, generated schema, and updated external compatibility fixture. Existing `[ai]`,
  Codex/Claude task adapters, deterministic fallbacks, CLI, MCP, and autonomous paths remain
  unchanged when `[model_analysis]` is absent.
- Documentation: added `docs/architecture/model-analysis.md` and updated README, getting started,
  AI/config/control architecture, `SECURITY.md`, and `CHANGELOG.md` with the disabled default,
  exact readiness/evaluation rules, service controls, provenance, and support boundary.
- Development evidence: focused core/config/control/service/report/MCP/storage tests passed,
  including authenticated loopback PostgreSQL corruption cases. Default and all-feature strict
  Clippy passed. The final `DATABASE_URL=... bash bin/gate.sh --fast` passed 14 applicable lanes,
  failed none, and skipped only the eight lanes that fast mode intentionally does not run.
- Design deviations: response/input canonical redaction and built-in evaluation prompt pinning were
  strengthened at consumer validation after review showed public typed structs could otherwise be
  constructed without their safe constructors. Storage write validation was added in addition to
  the planned read parity so malformed provenance cannot first become durable. No scope or
  authority was broadened.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Security | Public request/input/response structs could bypass safe constructors and retain secret-shaped input, instruction, summary, provider, model, or workflow values. | high | Fixed: consumer validation now requires canonical redaction for all untrusted text and identities; direct-construction negatives cover each boundary. |
| 2 | Correctness | An evaluation request could retain a valid case ID while changing its workflow, class, or prompt. | high | Fixed: request validation now matches the complete built-in case tuple and corpus version. |
| 3 | Correctness | The exported corpus validator accepted altered expected verdict/refusal metadata even though eligibility used the immutable built-in corpus. | medium | Fixed: validation now requires exact equality with the complete built-in corpus; altered-corpus evidence is rejected. |
| 4 | Resource bounds | Aggregate content could fit the nominal request ceiling while JSON envelope overhead made the process request exceed it. | medium | Fixed: request validation now enforces the ceiling over the complete serialized envelope, with a boundary regression. |
| 5 | Data integrity | Invalid model provenance could survive normalization fallback and reach a durable write or public child read. | high | Fixed: canonical writes and every durable child read independently validate the complete record before projection. |
| 6 | Data integrity | Analysis children loaded by timestamp did not match canonical finding identity ordering, allowing deterministic round-trip order drift. | medium | Fixed: the bounded validated query orders by unique analysis identity, matching `Finding::canonical_appsec`. |
| 7 | Audit | The process adapter originally authorized execution without publishing an awaited decision event. | medium | Fixed: host/local decisions publish before execution; the recording executor asserts audit ordering. |
| 8 | Authorization | Separate service credential-use enforcement was implemented but lacked a direct negative regression. | medium | Fixed: a loopback-unused test grants external-tool/active-safe but withholds credential-use and proves policy denial before transport. |
| 9 | Secret handling | The environment-backed bearer header was not marked sensitive for downstream debug formatting. | medium | Fixed: constructed authorization headers set the sensitive flag; a direct regression verifies it. |
| 10 | Projection | Invalid configuration readiness and legacy report labels could expose secret-shaped provider/model labels. | high | Fixed: invalid readiness omits binding labels, identities require canonical redaction, and report labels re-redact legacy values. |
| 11 | Tooling | A loopback test's fake bearer used a secret-shaped name/literal and triggered Semgrep. | low | Fixed: fixtures are generated at runtime and assertions still prove no body exposure. |
| 12 | Mechanical | One assertion retained the prior fixture variable after the secret-fixture rename. | low | Fixed: corrected the reference and reran focused tests plus the complete fast gate. |

- Inspection methods: contract/branch review, authorization and audit ordering trace, redaction and
  public-projection trace, durable canonical parity review, resource-bound review, compatibility
  diff review, strict default/all-feature Clippy, focused core/service/report/PostgreSQL tests, and
  a complete fast gate. Subagent variance review was not used because repository instructions for
  this run prohibit delegation.
- Residual scope: host-managed execution deliberately inherits the trusted host environment;
  local execution clears it. Service v1 deliberately permits exact HTTP(S) endpoints as locked by
  REQ-005, while authorization, DNS, redirects, credentials, redaction, retention, time, and byte
  limits remain enforced by the shared policy-owned client and this adapter.

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - `cargo test -p scorchkit-core model_analysis --no-default-features`: PASS; seven direct role,
    redaction, response-binding, serialized-envelope, immutable-corpus, eligibility, provenance,
    and finding-invariance tests.
  - `cargo test -p scorchkit-config model_analysis --no-default-features`: PASS; six default,
    duplicate, endpoint, identity, service-bound, serde, and failed-evaluation tests.
  - `cargo test --lib model_analysis::tests --all-features` plus the separately added credential-
    denial regression: PASS; all host/service/local readiness, policy, audit, redaction, timeout,
    output, environment, substitution, evaluation, sensitive-header, and credential-use paths.
  - `cargo test --lib report:: --all-features`: PASS; 45 report tests including complete model
    provenance and secret-safe human labels.
  - Authenticated PostgreSQL `canonical_control_reads_fail_closed_for_independent_projection_corruption`:
    PASS; raw analysis, identity, schema, timestamp, ordering, and public round-trip checks.
  - `cargo clippy --workspace --all-targets -- -D warnings` and the corresponding
    `--all-features` command: PASS.
  - Post-inspection authenticated `bash bin/gate.sh --fast`: GREEN; 14 passed, 0 failed, eight
    intentional fast-mode skips, and no mutation invocation.
  - Authenticated `bash bin/pipeline.sh doctor`: PASS, including the exact PostgreSQL URL.
    `bash bin/mutants.sh --inspect`: PASS; 11,452 configured mutants across 323 workspace source
    files, with no mutant compiled or executed.
- Gate run and receipt:
  - The one authenticated `bash bin/gate.sh --diff` passed every non-mutation lane, including
    85.03% line coverage, 2,128 strict Nextest cases, 101 PostgreSQL tests, and the CLI/MCP contract
    suites. Its mutation lane completed 287 selected mutations: 182 caught, 71 missed, and 34
    unviable, for 71.93% initial viable MSI. Raw evidence is preserved under
    `.git/scorchkit-mutants-focused-ticket-030/initial`; no second DIFF or FULL run occurred.
  - Added exact constants, max/one-over ceilings, independent compound-guard operands, canonical
    order, evaluation mismatch, response/provenance count, authorization-audit, serialized input,
    bounded response, and exact 1,000/1,001 durable-child tests. Focused core/config/control/root
    and authenticated PostgreSQL tests passed; default and all-feature strict Clippy passed.
  - `bash bin/mutants.sh --recheck` selected exactly the 71 preserved survivor names and caught 70.
    The one residual config guard used padded/control fixtures that also exceeded the byte limit;
    after separating those operands, an exact one-name follow-up caught the residual. The sealed
    evidence verifier reconstructs 253/253 viable caught with 34 unviable, zero misses, 100% MSI,
    mutation-input hash `02dc6d1794f482419f779956404b73cc8d50f92596c3aca2549e24f45aa8110a`,
    and evidence digest `456cf548388a36ad9924dbb28d30b7e562b6d0616c7d239e7b3d8e9d2d92657a`.
  - Pre-completion validation now runs authenticated `bash bin/gate.sh --focused-repair`; its
    mutation lane verified the sealed evidence and launched no cargo-mutants. The gate passed 19
    applicable lanes, failed none, retained the three named web-only skips, passed 2,140 strict
    Nextest cases with 10 reasoned skips, and passed all PostgreSQL and CLI/MCP contract lanes.
    Post-archive delivery will rerun that same non-mutation receipt-producing mode.
- Documented skips with reasons: no remote/public model or scan target is authorized; service tests
  use loopback only. Browser, website-rendering, and built-CSS lanes remain the repository's named
  not-applicable skips because ScorchKit ships no web UI or CSS asset pipeline. No FULL gate or
  repeated broad mutation selection is authorized.

## Phase 5 — Complete

- Docs updated: README, getting-started guide, security policy, AI/config/control and new model-
  analysis architecture, changelog, knowledge register, ticket index, and roadmap now describe the
  shipped provider-neutral role, readiness, evaluation, provenance, adapter, and authority
  boundaries plus their final validation evidence.
- AAR submitted: `docs/planning/knowledge/aar/AAR-030-model-analysis.md` on 2026-08-24 with
  effectiveness 4/5.
- Archive: `bash bin/pipeline.sh pass complete` will close TICKET-030 and archive this spec/notes
  pair; the same approved focused-repair gate will then produce the exact post-archive delivery
  receipt before commit.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first fast gate reported a Semgrep hardcoded-secret finding in a loopback test. | A fake fixture used a secret-shaped variable name and literal. | Generated a non-secret repeated-character bearer fixture and retained the body/non-exposure assertions. | Keep credential fixtures runtime-generated and visibly non-secret. |
| 2 | The first rerun failed to compile after the fixture rename. | One assertion still referenced the old local name. | Updated the remaining reference and reran the focused model tests plus the complete fast gate. | Run the focused compile immediately after mechanical fixture renames. |
| 3 | The completed DIFF mutation lane found 71 survivors after every functional lane passed. | Representative contract tests did not independently pin every exact ceiling, guard operand, canonical order, thin dispatch, and constant. | Added direct truth tables and rechecked only the exact 71 names from the preserved result. | Write exact max/one-over and one-invalid-condition-at-a-time matrices before mutation validation. |
| 4 | One compound-guard mutation survived the first exact recheck. | The padded and control fixtures also exceeded their one-byte maximum, so an earlier operand rejected them even when the target `||` became `&&`. | Gave each fixture enough byte headroom to violate only its intended condition; the exact one-name follow-up caught it. | Ensure each compound-predicate fixture makes exactly one operand true and assert the complementary valid boundary. |
