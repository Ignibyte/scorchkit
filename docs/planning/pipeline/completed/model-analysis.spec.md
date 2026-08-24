---
title: Provider-neutral model analysis roles and evaluations
pipeline_id: 1f4acf58-8c38-4c6b-a3a9-17c8db2e3d8d
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-030
ticket_doc: docs/planning/tickets/closed/TICKET-030-model-analysis.md
aar: docs/planning/knowledge/aar/AAR-030-model-analysis.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-030
created: 2026-08-24
---

# Provider-neutral model analysis roles and evaluations — spec

## Intent

Ship an exact, provider-neutral readiness and execution boundary for model-assisted AppSec roles.
Configured host, service, and local adapters share one versioned contract and can become ready only
after their exact provider/model/role combination passes the versioned evaluation corpus. Successful
output becomes deterministic labeled provenance in the existing analysis layer and never gains
scanner-evidence, lifecycle, storage, or authorization authority.

## Scope

- In: six closed roles; typed request/response/provenance/readiness/evaluation contracts; explicit
  role binding configuration; host/local process and service HTTP adapters; exact eligibility;
  storage parity and public/report projections; compatibility and negative tests; docs.
- Out: model access or enrollment, operator model selection, OAuth/OIDC, provider-specific domain
  types, arbitrary endpoints/headers, service retention modes other than none, direct database
  handles, finding-state decisions, scanner-evidence creation, remote target/provider tests,
  legacy AI replacement, FULL mutation, push, or PR.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a workflow requests planning, finding validation, correlation, attack-path reasoning, remediation, or verification, ScorchKit shall resolve only the one explicitly configured compatible provider and exact model for that role and shall return a typed unavailable state instead of substituting another model or broadening scanner work. | Exhaustive role/readiness matrix, duplicate-binding negatives, and exact-provider/model response tests. |
| REQ-002 | When ScorchKit reports model readiness, it shall distinguish disabled, unconfigured, invalid, unavailable, evaluation-required, and ready states without executing the model or exposing credentials. | Core and control-projection truth tables plus credential-safe serialization tests. |
| REQ-003 | When a host-managed, service-managed, or local adapter returns analysis, ScorchKit shall validate the exact provider, model, role, contract version, and response kind and shall record input evidence digests, workflow version, timestamp, confidence, and execution location in deterministic labeled provenance. | Adapter envelope rejection tests and provenance identity/serde fixtures through storage, control/MCP canonical results, HTML, terminal, PDF, and SARIF. |
| REQ-004 | When model analysis references a finding or attack path, ScorchKit shall keep it in the append-only agent-analysis layer and shall not allow it to create scanner evidence, change engagement grants, or transition finding lifecycle state. | Finding identity/evidence/status invariance tests and durable child-record parity checks. |
| REQ-005 | When a service-managed adapter is configured or invoked, ScorchKit shall require a credential-free exact HTTP(S) endpoint, environment-indirect credential, mandatory redaction and no-retention policy, bounded input/output/time, engagement authorization, credential-use authorization, and an audit decision before the no-redirect request. | Configuration boundary table and authorized/denied loopback service tests for endpoint, credential, redaction, audit order, timeout, and byte ceilings. |
| REQ-006 | When a provider/model/role is proposed for use, ScorchKit shall evaluate its typed answers against the complete versioned AppSec corpus for valid findings, false positives, missing context, attack paths, and unsafe tool proposals and shall mark only an exact all-pass result eligible. | Corpus completeness contract, duplicate/missing/wrong-answer tests, exact eligibility-key tests, and adapter-driven evaluation fixture. |
| REQ-007 | When existing `scorchkit.ai/v1` planning and analysis configuration is used without the new model-role configuration, ScorchKit shall preserve its current Codex-first/Claude-compatible behavior and deterministic fallbacks. | Existing AI provider, CLI, MCP, autonomous-runner, and configuration compatibility suites. |
| REQ-008 | When mutation validation repairs TICKET-030, ScorchKit shall preserve the completed 287-mutant DIFF baseline and recheck all and only its 71 named survivors in 17 verifier-distinct functions across six files. | Sealed initial outcomes, six pre-repair snapshots, exact-name survivor evidence, one residual-name follow-up, reconstructed MSI, and focused-repair receipt. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Define roles, readiness, provenance, evaluation, and eligibility in `scorchkit-core`; keep transport configuration in `scorchkit-config` and runtime adapters in the root composition package. | Domain contracts remain independent of Codex, Claude, CLI, MCP, storage, and HTTP implementations. |
| 2 | Bind exactly one configured provider/model to each role and fail duplicate, absent, incompatible, unavailable, or unevaluated bindings visibly. | A preference list or provider default would make substitution ambiguous. |
| 3 | Use one `scorchkit.model-analysis/v1` envelope for analysis and evaluation requests/responses and revalidate it at adapter consumption. | Typed Rust values returned by external adapters are still untrusted at the consumer boundary. |
| 4 | Extend `AgentAnalysisRecord` backward-compatibly with optional model provenance and use a distinct model-analysis schema/identity for new records. | Existing v1 fixtures keep their bytes and identity while new provenance is complete and independently labeled. |
| 5 | Treat service HTTP as `ExternalTool`/`active-safe` plus `CredentialUse`/`passive`, use the shared policy-owned no-redirect client, environment-only bearer resolution, and publish the decision before send. | Model service access is a separately authorized external effect and credential use. |
| 6 | Require every one of the five closed corpus classes to pass for an exact eligibility key; no weighted threshold, partial pass, or other-model result is accepted. | Eligibility must be deterministic, auditable, and resistant to a good aggregate hiding an unsafe-tool failure. |
| 7 | Leave legacy `[ai]` behavior intact and introduce disabled-by-default `[model_analysis]`. | SK-052 adds the durable role contract without breaking the existing compatibility adapter. |
| 8 | Run one normal DIFF gate, preserve its raw result, and limit any follow-up to exact survivors. | The owner explicitly stopped repeated broad mutation campaigns because they add hours without improving survivor repair evidence. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-030-model-analysis.md`
- AAR: `docs/planning/knowledge/aar/AAR-030-model-analysis.md`
- Architecture:
  `docs/architecture/model-analysis.md`, `docs/architecture/ai.md`,
  `docs/architecture/control-api.md`, and `SECURITY.md`.

## Phase plan

| Phase | Deliverable | Exit evidence |
|---|---|---|
| 1 Plan | ticket, AAR, spec, notes, recalled knowledge | operator confirmation |
| 2 Design | architecture, file manifest, regression plan | operator confirmation |
| 3 Implement | code per design | self-review |
| 3.5 Inspect | adversarial ledger with dispositions | lead review |
| 4 Validate | tests run and delivery gate green | matching receipt |
| 5 Complete | docs, submitted AAR, archive, closed ticket | archive complete |
| Delivery | gate rerun after archive, commit/PR | matching receipt |
