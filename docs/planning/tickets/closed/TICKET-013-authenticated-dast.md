---
title: TICKET-013-authenticated-dast
status: done
ticket_number: 013
type: feature
created: 2026-08-20
closed: 2026-08-20
intake: docs/planning/intake/INTAKE-authenticated-dast.md
pipeline_spec: docs/planning/pipeline/completed/authenticated-dast.spec.md
focused_repair: approved
---

# Authenticated schema-driven application DAST

## Summary

Replace the legacy `zap-cli quick-scan` wrapper with a policy-sealed application DAST service that
builds and runs deterministic OWASP ZAP Automation Framework plans for anonymous and named
personas. The service accepts only owned, bounded OpenAPI or GraphQL schema files, separates crawl,
passive, and active phases, verifies authentication coverage, and projects redacted request and
response evidence through the existing finding and scan-result contracts.

## Why

SK-034 narrowed the scanner catalog, SK-035 established durable evidence, SK-036 added deep source
analysis, and SK-037 added application supply-chain evidence. Runtime correlation now needs a DAST
producer that can prove which routes, operations, persona, authentication state, phases, and ZAP
configuration produced an observation. The current wrapper launches an obsolete ambient
`zap-cli`, silently converts malformed output into no findings, and cannot make any of those claims.

## EARS Requirements

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

## Scope

- In: ZAP Automation Framework plans; anonymous, header-token, and browser/login personas; local
  OpenAPI 2/3 and GraphQL schema files; strict contexts; traditional and client crawling; passive
  and active phases; URL, authentication, alert, request, and response evidence; per-persona
  coverage; facade, CLI, MCP, reports, SARIF, storage, durable result compatibility, doctor, tool
  installation, architecture, and Codex-host guidance.
- Out: deploying or resetting target applications; remote schema URLs; SSO or third-party resource
  origins; arbitrary ZAP plans or scripts; add-on updates during a scan; public or unregistered
  targets; access-control exploit automation; business-logic abuse; general HAR ingestion; remote
  MCP; and a repository-wide mutation campaign.

## Locked decisions

- ZAP execution uses the official 2.17.0 Linux distribution with SHA-256
  `efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a`; mutable stable or weekly
  images and runtime add-on updates are not accepted.
- One request may select anonymous and multiple named personas, but each persona receives an
  independent sequential ZAP process, home, plan, report set, and evidence namespace.
- Persona configuration supports pre-issued header tokens and browser-based username/password
  login with explicit verification. Secret values are environment references, never plan or
  request fields.
- Schemas are local files with required SHA-256 values. ScorchKit rejects remote `$ref` or schema
  imports, overrides OpenAPI servers to the authorized target, and requires a same-origin GraphQL
  endpoint.
- Passive and standard plans never contain `activeScan`. The active profile is intrusive and
  requires an exact intrusive DAST and external-tool grant. Any named persona additionally requires
  exact credential-test and credential-use grants.
- Automation Framework exit 0 is complete, exit 2 is degraded pending parsed warnings, and every
  other exit is failure. Missing or malformed required artifacts are never clean.
- Final coverage evidence includes both the URL export and a bounded traffic HAR. A schema operation
  is observed only when its route template and HTTP method match the traffic history.
- The owner's standing direction authorizes a local commit after a green exact-tree delivery
  receipt. It does not authorize a push, pull request, or scan of a non-loopback target.
- Validation may establish one ticket DIFF mutation inventory. If it exposes survivors, only the
  repaired named functions may be rechecked; the broad inventory is not repeated.
- The completed ticket inventory selected 564 mutations and produced 229 exact survivors in 72
  functions across 15 files. Focused-repair evidence is limited to those named outcomes; the raw
  broad result is preserved under `.git/scorchkit-mutants-broad-ticket-013`.
- The final current-tree repair scope selected 71 mutations in 11 functions across 6 files. Its
  sealed result caught 68/68 viable mutations at 100% MSI with 3 unviable and no misses; the exact
  input and raw outcomes are preserved under `.git/scorchkit-mutants-focused-ticket-013`.
- Two later validation-only corrections changed mutation inputs: the shared test environment lock
  now exists in default test builds, and a redaction fixture no longer uses a secret-like binding.
  The delivery reseal therefore selected the existing 11 repaired functions plus only the two
  redaction deserializers and ZAP doctor function affected by those corrections. Its 83 mutations
  produced 77 caught, 2 timeouts, 4 unviable, and no misses: 79/79 viable caught at 100% MSI. The
  exact current-tree proof is preserved under
  `.git/scorchkit-mutants-focused-ticket-013-delivery`; no broad inventory was repeated.
- A later staged-tree gate exposed one process-wide `PATH` race in the version-probe test. After the
  reader joined the shared environment lock through a synchronous test and private current-thread
  runtime, the final exact-tree follow-up selected only five `get_tool_version` mutants and caught
  all 5 with no misses. The current proof is preserved under
  `.git/scorchkit-mutants-focused-ticket-013-delivery-final-2`; every earlier result remains
  preserved and no broader scope was rerun.

## Recon

- `src/tools/zap.rs` is a 116-line `zap-cli quick-scan` wrapper with two permissive parser tests. It
  has no phase, authentication, schema, artifact, or provenance contract.
- The build host has OpenJDK 21, Docker 29.7.2, 1.5 TiB free on `/mnt/fast`, and no `zap.sh` or
  `zap-cli`. A native pinned installation avoids a mutable image and Docker-socket authority.
- ZAP Automation Framework runs jobs in document order, uses exit 0/1/2 for success/error/warning,
  supports environment-variable credentials, local OpenAPI and GraphQL jobs, authenticated spider
  and active-scan jobs, passive-scan barriers, URL exports, authentication reports, and Traditional
  JSON Plus request/response reports.
- `ScanContext` already owns exact authorization decisions and an injectable bounded executor, but
  it needs an owned-invocation seam for clean environment, working directory, exact exits, and
  artifact budgets.
- `HttpEvidence` already carries a redacted persona label and `FindingRecordV2` already carries
  scanner/config provenance. `ScanResult` module outcomes and coverage projections can represent
  incomplete DAST without inventing positive findings.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/authenticated-dast.spec.md`

## Log

- 2026-08-20: opened.
- 2026-08-20: promoted from SK-038 after TICKET-012 reached a clean committed boundary and the
  owner directed continuous execution.
- 2026-08-20: completed the sole 564-mutation broad inventory, repaired its 229 named survivors,
  and sealed a zero-miss 71-mutation current-tree scope without repeating the broad run.
- 2026-08-20: corrected the final default-feature test lock and redaction fixture, then resealed only
  the affected 83-mutation delivery scope with 79/79 viable caught and zero misses.
- 2026-08-20: fixed staged-deletion receipt invariance and the version-probe environment race, then
  sealed the five affected `get_tool_version` mutations with 5/5 caught and zero misses.
