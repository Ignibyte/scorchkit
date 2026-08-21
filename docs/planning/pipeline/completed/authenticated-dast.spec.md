---
title: Authenticated schema-driven application DAST
pipeline_id: 16be5e3f-af1f-441c-b5e1-378cbce1640b
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-013
ticket_doc: docs/planning/tickets/closed/TICKET-013-authenticated-dast.md
aar: docs/planning/knowledge/aar/AAR-013-authenticated-dast.md
created: 2026-08-20
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-013-delivery-final-2
---

# Authenticated schema-driven application DAST — spec

## Intent

Deliver a policy-sealed application DAST service that turns explicit target, schema, profile, and
persona selections into isolated OWASP ZAP Automation Framework executions. Preserve the plan,
route, operation, authentication, scanner, and redacted HTTP evidence needed for later static-to-
runtime correlation without making the engine depend on Codex or another agent provider.

## Scope

- In: the complete TICKET-013 scope and public surfaces listed in the linked ticket.
- Out: target deployment/reset, remote schemas, third-party authentication origins, arbitrary ZAP
  scripts/plans, scan-time add-on updates, public targets, business-logic exploits, access-control
  attack automation, general HAR import, remote MCP, and a repository-wide mutation campaign.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an application DAST request is accepted, ScorchKit shall authorize the exact HTTP target, requested scan effect, external ZAP process, each selected persona's credential use, and every local schema file before reading credentials, copying schemas, creating the run workspace, or launching ZAP. | Exact-grant matrix, denial-before-secret-resolution, denial-before-filesystem, and recording-executor tests. |
| REQ-002 | When a persona is selected, ScorchKit shall resolve credentials only from named environment references after authorization, place only variable placeholders in the Automation Framework plan, pass secrets through a clean redacted process environment, and fail closed when a required secret or verification rule is absent. | Config round-trip, redacted `Debug`, plan snapshot, missing-variable, process-environment, and public-output secret-canary tests. |
| REQ-003 | When an OpenAPI or GraphQL schema is supplied, ScorchKit shall canonicalize one owned bounded read, verify its declared SHA-256 and supported shape, reject remote references and out-of-scope endpoints, copy the accepted bytes into the run workspace, and preserve route, method, operation, and schema identities. | Symlink, size, digest, remote-reference, cross-origin, route/operation, and single-read fixtures. |
| REQ-004 | When a persona plan is compiled, ScorchKit shall generate one deterministic ZAP Automation Framework plan whose ordered jobs and limits match the selected profile, whose context is strict and in scope, and whose active scan appears only under an intrusive grant. | Exact YAML golden tests for anonymous, header, and browser personas across passive, standard, and active profiles. |
| REQ-005 | When an authenticated plan runs, ScorchKit shall verify authenticated state before discovery, retain ZAP authentication statistics, and report failed or lost authentication as a typed coverage gap rather than a clean authenticated assessment. | Successful-login, invalid-login, expired-session, missing-statistic, and anonymous-control fixtures. |
| REQ-006 | When ZAP runs, ScorchKit shall require the pinned ZAP 2.17.0 runtime, accept only documented Automation Framework exits, use an owner-only per-persona workspace and home, enforce wall-time, output, file-count, and artifact-byte limits, and terminate the owned process tree on cancellation or limit failure. | Version, invocation, permissions, exact-exit, artifact-budget, timeout, cancellation, and descendant-cleanup tests. |
| REQ-007 | When ZAP emits results, ScorchKit shall distinguish valid empty output, valid alerts, plan warnings, plan errors, authentication failure, missing artifacts, and malformed output, and shall never convert an incomplete outcome into a successful clean result. | Traditional JSON Plus, auth-report, URL-export, warning/error, truncation, missing-file, and malformed golden fixtures. |
| REQ-008 | When a ZAP alert is accepted, ScorchKit shall preserve its alert/plugin identity, CWE, confidence, persona, normalized route, schema operation identity when available, plan digest, scanner version, and redacted bounded HTTP request and response evidence. | Evidence-v2, provenance, identity, correlation, secret-redaction, and report/SARIF round-trip tests. |
| REQ-009 | When one request selects anonymous or multiple named personas, ScorchKit shall execute isolated persona plans in stable order, retain per-persona route and phase coverage, and expose findings and coverage through agent-neutral facade, CLI, MCP, JSON, SARIF, reports, storage, and durable-job compatible results. | Multi-persona isolation, role-route difference, public contract, storage, and process-level CLI/MCP tests. |
| REQ-010 | When TICKET-013 is delivered, the build host shall have the checksum-verified official ZAP 2.17.0 Linux runtime, doctor and operator documentation shall enforce that exact contract, tests shall target only loopback fixtures, and mutation validation shall not repeat a completed broad inventory. | Build-host checksum/version evidence, doctor tests, documentation inspection, loopback integration, one DIFF inventory, and narrow survivor rechecks only if needed. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Use the official checksum-pinned native ZAP 2.17.0 Linux distribution. | The build host already has Java 21; native execution avoids mutable images and Docker-socket authority. |
| 2 | Compile ScorchKit-owned plans rather than accept arbitrary YAML. | The plan is an effect contract and must not smuggle new URLs, scripts, add-ons, or scan phases. |
| 3 | Use local digest-pinned schemas only and override their runtime target to the authorized URL. | Schema URLs, references, and server blocks are otherwise independent network authorities. |
| 4 | Resolve persona secrets from named environment references after authorization and inject them only into a clean child environment. | Request, config, plan, argv, logs, and durable evidence must not carry credential values. |
| 5 | Run each persona in an isolated sequential process. | Header authentication is process-global in ZAP, while separate homes and reports prevent cross-role session and evidence contamination. |
| 6 | Treat passive, standard, and active DAST as explicit phase profiles. | Active scanning attacks the application and must never appear under a passive or active-safe authorization. |
| 7 | Use URL export, method-bearing traffic HAR, authentication JSON, and Traditional JSON Plus as required bounded artifacts. | Alerts and URLs alone cannot prove operation methods or authenticated state; all four are needed for a defensible result. |
| 8 | Extend the shared invocation contract with an owned artifact budget and redacted debugging. | ZAP writes files outside stdout/stderr and receives secrets in environment values; the process boundary must own both risks. |
| 9 | Project typed per-persona coverage through existing `ScanResult` outcomes and evidence-v2. | A clean finding list is not proof that schema import, auth, crawl, passive scan, or active scan completed. |
| 10 | Establish one normal DIFF inventory, then repair and recheck only named survivors. | This satisfies delivery evidence without repeating the expensive broad scan the owner stopped. |
| 11 | Treat the owner's direction to keep driving as Plan and Design confirmation within this locked scope. | The pipeline may proceed without another pause, while all target and delivery authority remains unchanged. |
| 12 | Apply the repository's focused-repair receipt path to the exact 229-survivor inventory in 72 functions across 15 files. | The completed 564-mutant DIFF run is the sole broad inventory; the owner has repeatedly directed ScorchKit to recheck only repaired survivors. |
| 13 | Seal the final current-tree mutation evidence over the 11 repaired functions after simplifying one equivalent redaction guard and extracting deterministic artifact-race predicates. | The 229-survivor pass and 72-mutation repair pass remain preserved as raw evidence; the final 71-mutation scope is the smallest current inventory that proves every repaired seam without inventing behavior for an equivalent mutant. |
| 14 | Reseal the delivery tree over the 11 repaired functions plus the three functions directly exercised by the final redaction and ZAP-doctor validation corrections. | Moving the test environment lock to every test build and renaming a secret-like fixture variable changed mutation inputs after the 71-mutation seal. The exact 83-mutation delivery scope preserves that earlier proof and adds only the affected redaction and doctor seams; it does not repeat the broad inventory. |
| 15 | Seal one final current-tree follow-up over only `get_tool_version` after synchronizing its environment-reading test through a private current-thread runtime. | The 83-mutation delivery evidence and first five-case follow-up remain preserved. The later test-only race and strict-lint repair affects one production seam, so its exact-tree proof stays narrow and does not repeat any prior inventory. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-013-authenticated-dast.md`
- AAR: `docs/planning/knowledge/aar/AAR-013-authenticated-dast.md`
- Architecture:
  `docs/architecture/application-dast.md`, `docs/architecture/application-security-evidence.md`,
  `docs/architecture/runner.md`, `docs/architecture/tools.md`, `docs/architecture/config.md`,
  `docs/architecture/cli.md`, `docs/architecture/mcp.md`

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
