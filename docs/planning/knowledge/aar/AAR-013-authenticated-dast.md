---
aar: AAR-013-authenticated-dast
ticket: TICKET-013
pipeline: authenticated-dast
status: submitted
opened: 2026-08-20
submitted: 2026-08-20
effectiveness: 5 - highly effective
---

# AAR-013 — Authenticated schema-driven application DAST

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `CONSTITUTION.md` §§0, 3, 7, 14, 15, 18, 19 | Required the repository pipeline, evidence boundary, tests, inspection, and mutation limits. | Yes — fixes phase order and prevents a repeated broad mutation run. |
| `SECURITY.md` | Defines exact target, credential, subprocess, filesystem, cancellation, redaction, and scope invariants. | Yes — makes the generated plan an untrusted effect description, not authority. |
| `PR-scorchkit-policy-before-effects-001` | ZAP needs network, filesystem, credential, and subprocess effects. | Yes — all grants precede secret resolution and workspace creation. |
| `PR-scorchkit-credential-use-separate-grant-001` | A named persona supplies credentials to an already-authorized scanner. | Yes — external-tool authority alone cannot unlock persona secrets. |
| `PR-scorchkit-executor-contract-001` and `PR-scorchkit-adapter-execution-descriptor-parity-001` | The legacy wrapper has no owned plan/report invocation contract. | Yes — drives the exact recording-executor and descriptor matrix. |
| `PR-scorchkit-parser-outcome-integrity-001` and `PR-scorchkit-scan-coverage-projection-parity-001` | ZAP has independent plan, auth, crawl, passive, active, and report outcomes. | Yes — any missing or failed required phase becomes incomplete coverage. |
| `PR-scorchkit-scoped-tool-artifacts-001` | ZAP writes a home, session data, logs, exports, and reports. | Yes — every persona needs an owned budgeted workspace. |
| `PR-scorchkit-public-evidence-revalidation-001` and `PR-scorchkit-untrusted-finding-channel-redaction-001` | ZAP reports may contain tokens, cookies, passwords, and untrusted diagnostics. | Yes — all public and durable projections re-redact parsed material. |
| `PR-scorchkit-cancellation-whole-lifecycle-001` | Process execution and artifact monitoring form one effect lifecycle. | Yes — cancellation or limit failure must terminate the whole process tree. |
| TICKET-010 through TICKET-012 completed notes | Provide persona evidence, typed coverage, pinned tool, and verified artifact precedents. | Yes — avoids parallel DAST-only contracts. |
| Official ZAP 2.17.0 and Automation Framework documentation | Defines exact jobs, auth variables, exit codes, reports, and release checksum. | Yes — replaces the obsolete `zap-cli` assumptions with the reviewed upstream contract. |

## What happened

- ScorchKit replaced the ambient `zap-cli quick-scan` wrapper with an agent-neutral application
  DAST service that compiles deterministic OWASP ZAP Automation Framework plans for anonymous,
  header-token, and browser-login personas. Every plan is tied to an exact target, profile, local
  schema digest, persona, tool version, and policy decision set.
- The service authorizes the complete target, process, credential, and schema-file effect set before
  it resolves a secret, reads a schema, creates a workspace, or launches ZAP. Each persona receives
  a private home and report set, a clean child environment, bounded artifacts, and whole-process
  cancellation.
- OpenAPI and GraphQL inputs use one canonical bounded read. Remote references, cross-origin
  endpoints, unsafe routes, symlinks, digest mismatches, and oversized operation sets fail before
  execution. Accepted bytes are copied into the owned run workspace and correlated to observed
  method-plus-route traffic.
- Authentication proof combines a pre-discovery traffic record with final ZAP statistics. Missing,
  malformed, failed, or lost authentication remains a typed coverage gap. Findings and coverage
  retain persona, phase, route, operation, plan, scanner, and redacted HTTP evidence through CLI,
  MCP, reports, SARIF, storage, and durable scan results.
- Adversarial inspection repaired nine security, data-integrity, correctness, resource-safety, and
  simplification findings. Validation exercised the pinned ZAP 2.17.0 runtime and ChromeDriver only
  against loopback targets. One broad changed-code mutation inventory was preserved, then repair
  work and rechecks were limited to its exact 229 survivors. After two final validation-only
  corrections, the exact delivery scope caught 79/79 viable mutations at 100% MSI with no misses.
  A final environment-race repair then caught all 5 `get_tool_version` mutants in its one-function
  current-tree scope; the broad inventory and earlier delivery scope were not repeated.

## Novel findings

| ID | Finding | Consequence |
|---|---|---|
| `BF-scorchkit-zap-port-zero-001` | ZAP treats port zero as its default proxy port instead of requesting an operating-system-assigned port. | Parallel or unattended runs can collide on a shared fixed port. |
| `BF-scorchkit-version-probe-secret-leak-001` | The first version probe reused the persona environment before the executable proved it was the pinned ZAP runtime. | Credentials could reach an untrusted or wrong executable during a nominal readiness check. |
| `BF-scorchkit-url-only-operation-coverage-001` | A URL export has no HTTP method, so it could mark a POST schema operation observed after only a GET reached the same path. | Runtime coverage could claim an operation was exercised when it was not. |
| `BF-scorchkit-graphql-import-variant-001` | The first GraphQL import guard recognized only an exact lowercase `#import` prefix. | Whitespace, case, or BOM variants could bypass the local-schema boundary. |
| `BF-scorchkit-artifact-entry-undercount-001` | The first recursive artifact budget counted regular files and symlinks but not directories, sockets, or FIFOs. | A child could exceed the intended entry ceiling without exceeding its regular-file count. |

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-zap-port-zero-001` | The first loopback plan reached ZAP's default proxy port instead of a newly allocated one. | Pinned-runtime OpenAPI integration. |
| `BF-scorchkit-version-probe-secret-leak-001` | Version and scan modes shared one environment map. | Security inspection of the external process boundary. |
| `BF-scorchkit-url-only-operation-coverage-001` | Route coverage consumed URL export data without method-bearing traffic. | Data-integrity inspection and method-mismatch fixture. |
| `BF-scorchkit-graphql-import-variant-001` | Import rejection matched one lexical spelling rather than the normalized directive. | Security inspection and BOM/case/whitespace fixtures. |
| `BF-scorchkit-artifact-entry-undercount-001` | The artifact walker incremented its entry count only for selected filesystem types. | Resource-safety inspection and Unix-socket fixture. |
| Validation process | The first DIFF delivery attempt used an obsolete TCP database URL after the build-host upgrade. | PostgreSQL-backed delivery lanes before mutation. |
| Validation process | The first focused delivery gate found a test environment lock hidden behind the `infra` feature and a redaction fixture binding that matched the hardcoded-secret rule. | Default-feature compilation and Semgrep. |
| Validation process | The first commit attempt made the exact receipt stale by staging the removed legacy ZAP file. | Pre-commit verification exposed that both path inventories omitted already-staged deletions despite the documented staging-invariance contract. |
| Validation process | A staged-tree gate intermittently failed the version-probe test, while the exact focused rerun passed. | The test read `PATH` concurrently with ZAP doctor fixtures that temporarily replaced it; the reader had not joined the shared environment lock. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-generated-dast-plan-001` | Compile external scanner plans only from already-authorized targets, local verified inputs, personas, phases, and bounded limits. Do not accept arbitrary scanner plans as authority. | A plan can introduce network, credential, filesystem, browser, and subprocess effects beyond the request that selected it. |
| `PR-scorchkit-secretless-tool-version-probe-001` | Prove the executable and required version through a structurally secret-free environment before injecting credentials or scan-specific settings. | A version probe runs code and is part of the trust boundary, not a harmless metadata read. |
| `PR-scorchkit-authenticated-dast-two-stage-proof-001` | Prove authenticated state before discovery and again from final scanner evidence; report a typed gap when either proof is absent or authentication is lost. | A successful login request does not prove later crawl and attack traffic remained authenticated. |
| `PR-scorchkit-operation-coverage-method-route-001` | Claim schema-operation coverage only from bounded traffic that matches both the HTTP method and normalized route template. | URL-only evidence conflates distinct operations on the same path. |
| `PR-scorchkit-artifact-entry-all-types-001` | Count every non-root filesystem entry against a recursive artifact ceiling, follow only real directories, and sum bytes only for regular files. | Sockets, FIFOs, directories, and symlinks consume namespace and traversal resources even when they add no regular-file bytes. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5 - highly effective. Recalled policy-before-effect, credential, executor, artifact, parser,
redaction, and focused-mutation rules materially changed the design before delivery: arbitrary ZAP
plans never became an authority surface, secrets remain outside plans and probes, schemas receive
one verified local read, and incomplete phases cannot project as clean. Inspection repaired nine
security and integrity findings. Three pinned-runtime loopback cases, 81.26% line coverage, 1,744
strict cases, PostgreSQL and public-contract lanes, sealed 79/79 viable delivery evidence, and the
final 5/5 current-tree follow-up provide independent executable proof without repeating the broad
mutation inventory.
