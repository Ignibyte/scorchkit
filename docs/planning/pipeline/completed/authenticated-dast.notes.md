---
title: Authenticated schema-driven application DAST — notes
pipeline_id: 16be5e3f-af1f-441c-b5e1-378cbce1640b
---

# Authenticated schema-driven application DAST — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001` and
  `PR-scorchkit-credential-use-separate-grant-001` require exact scan, subprocess, credential, and
  schema-file grants before secret or filesystem effects; `PR-scorchkit-executor-contract-001`,
  `PR-scorchkit-adapter-execution-descriptor-parity-001`, and
  `PR-scorchkit-scoped-tool-artifacts-001` require one observable bounded invocation whose metadata
  matches its actual files; `PR-scorchkit-parser-outcome-integrity-001` and
  `PR-scorchkit-scan-coverage-projection-parity-001` forbid malformed, failed, or missing DAST
  phases from looking clean; `PR-scorchkit-public-evidence-revalidation-001` and
  `PR-scorchkit-untrusted-finding-channel-redaction-001` require redaction at plan-output, finding,
  report, MCP, and storage boundaries; `PR-scorchkit-cancellation-whole-lifecycle-001` requires ZAP
  and artifact monitoring to stop as one lifecycle; and `PR-scorchkit-focused-mutation-repair-001`
  forbids repeating a completed broad inventory.
- Comparable work: TICKET-008 established the application adapter registry and exact effects;
  TICKET-010 added persona labels, stable evidence identity, and durable redaction; TICKET-011 made
  analyzer failures typed coverage gaps; TICKET-012 added ordered producers, clean environments,
  pinned tools, verified single-read artifacts, and public coverage projection. The new DAST service
  reuses those contracts instead of extending the legacy quick-scan wrapper in place.
- Official contract review: ZAP 2.17.0 Automation Framework executes jobs in YAML order and exits
  0/1/2 for success/error/warning. Official jobs cover browser authentication with environment
  variables, OpenAPI/GraphQL local imports, traditional and client crawling, passive-scan waits,
  intrusive active scan, URL export, authentication JSON, and Traditional JSON Plus evidence.
- Build-host recon: OpenJDK 21 and Docker 29.7.2 are installed; `zap.sh` and `zap-cli` are absent;
  `/mnt/fast` has roughly 1.5 TiB free. The official ZAP 2.17.0 Linux archive is 243,895,361 bytes
  with SHA-256 `efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a`.
- Operator confirmation: on 2026-08-20 the owner directed Codex to keep driving into the next work
  after TICKET-012 was committed. This confirms Plan and Design within the locked TICKET-013 scope,
  standing green local commits, no pushes, and no non-loopback target scans.

## Phase 2 — Design

- Architecture: add a provider-neutral DAST assessment to `scorchkit-core`; add reference-only
  persona and limit configuration to `scorchkit-config`; add a typed root `application_dast`
  service for request validation, schemas, plans, workspaces, execution, parsing, and result
  assembly; remove the legacy quick-scan module from implicit registry execution; expose one facade,
  CLI, and MCP request; and project the assessment through the existing result/report/storage
  boundaries. `docs/architecture/application-dast.md` records the full trust and sequence contract.
- Authorization: every request requires exact `DastScan/Intrusive` and
  `ExternalTool/Intrusive` grants. A named persona additionally requires
  `ExternalTool/CredentialTest` and `CredentialUse/CredentialTest`; each canonical schema file
  requires `LocalState/Passive`. The service obtains the complete decision set before resolving
  secret environment references, reading schema bytes, creating its workspace, or starting ZAP.
- Process and secret boundary: the shared `ToolInvocation` gains a recursive owned-artifact budget
  and a custom redacted `Debug`. ZAP receives only a clean environment, owner-only home/workspace,
  plan-variable secrets, exact 0/2 exit policy, fixed output/artifact/time limits, and process-group
  cleanup. One selected persona equals one sequential process and evidence namespace.
- Data model: `ApplicationDastAssessment` owns target/profile/schema, persona, auth, phase, route,
  gap, plan-digest, warning, and version evidence. `ScanResult` gains an optional assessment and
  includes it when deriving complete/incomplete/degraded status. Alert findings reuse
  `FindingRecordV2`, `ScannerProvenance`, `ObservationLocation::Runtime`, correlation keys, and
  redacted `HttpEvidence`.
- File manifest: create `crates/scorchkit-core/src/application_dast.rs` and
  `src/application_dast/{mod,request,schema,plan,workspace,parser,orchestrator}.rs`; modify core
  exports/result/error, config types, shared tool invocation/executor, root exports/facade, adapter
  registry and ZAP registration, CLI arguments/runner/doctor, MCP types/tools, report renderers,
  storage execution projection tests, module census/contracts, manifests/lockfile, configuration,
  CLI/MCP/tools/runner/evidence architecture, README, tool checklist, roadmap, changelog, ticket,
  notes, AAR, and knowledge register. Add loopback schemas/reports only under test fixtures.
- Regression test plan: core assessment serde/status/merge/redaction; config secret-reference and
  `Debug`; complete grant matrix and denial-before-effect ordering; schema canonicalization,
  one-read/digest/size/reference/origin/operation validation; exact deterministic plans for three
  profiles and persona kinds; clean environment, exact exits, version, permission, file/byte
  budget, timeout, cancellation, and descendant cleanup; strict URL/auth/report parsing; empty,
  alert, warning, error, auth loss, missing, oversize, changed-artifact, and malformed outcomes;
  operation correlation and HTTP redaction; sequential persona isolation; exact facade/CLI/MCP
  schemas and built-process output; report/SARIF/storage round trips; registry and doctor updates;
  loopback header/browser/schema execution against the pinned ZAP runtime; fast gate during repair;
  one final DIFF inventory and narrow survivor rechecks only when needed.
- Design risk review: ZAP is an external network client and does not use ScorchKit's native resolver.
  The service therefore accepts only one authorized same-origin context, local schemas, strict
  Client Spider scope, no third-party resources or remote references, and no arbitrary plans. This
  does not authorize public or third-party targets. Browser authentication that requires an SSO
  origin remains out of scope until the engine can model and authorize that additional origin.
- Operator confirmation: the owner's 2026-08-20 direction to keep driving confirms this design
  within the locked ticket. No remote target, push, or pull-request authority is inferred.

## Phase 3 — Implement

- Files and behavior changed: added the provider-neutral application DAST assessment and coverage
  types; added the request, schema, plan, workspace, orchestrator, and strict report parser service;
  extended the shared process invocation with clean environments, redacted debugging, exact exit
  sets, recursive owned-artifact budgets, and whole-process cleanup; replaced the legacy implicit
  `zap-cli` module with explicit facade, CLI, and MCP entry points; added config, doctor, terminal,
  HTML, PDF, SARIF, storage, and durable-result projections; and installed the checksum-pinned ZAP
  2.17.0 and matching ChromeDriver runtime on build-host scratch storage.
- Authorization and evidence behavior: the complete web, process, credential, and canonical schema
  decision set precedes secret resolution, schema reads, workspace creation, and process launch.
  Schemas receive one bounded digest-verified read; persona processes use isolated private homes;
  authentication is proven from a bounded pre-discovery HAR and final ZAP statistics; and missing,
  malformed, warning, authentication-loss, or execution outcomes remain typed coverage gaps.
- Design deviations: ZAP treats port zero as its default proxy port, so execution now reserves and
  supplies a nonzero ephemeral loopback port. The Automation Framework requestor job does not
  support the originally drafted context/test fields, so ScorchKit instead exports the immediately
  following history as a bounded HAR and performs the exact URL/status/body/credential proof itself.
  Browser execution resolves an operator-pinned WebDriver and supplies its absolute path through a
  Java property because the ZAP-bundled driver can lag the installed browser. Artifact monitoring
  tolerates only descendants that disappear during browser cleanup; a missing artifact root still
  fails closed. Inspection also added a final bounded traffic HAR because the URL export alone
  cannot prove the HTTP method for a schema operation.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Security | The ZAP version probe inherited persona credentials and the browser-driver property before the executable proved its required version. | high | Fixed: version mode now has a structurally credential-free clean environment; exact environment regression is green. |
| 2 | Data integrity | URL-only route coverage could claim a schema operation ran when only a different HTTP method reached the same path. | high | Fixed: final bounded traffic HAR is mandatory and operation coverage matches method plus route template. |
| 3 | Data integrity | A process or artifact failure after plan compilation discarded the plan digest. | medium | Fixed: persona failures carry optional compiled-plan identity, while genuinely pre-plan failures remain explicitly empty. |
| 4 | Security | Header personas could configure `Host`, framing, proxy, or connection-control headers. | high | Fixed: authority and framing headers are rejected before credentials are resolved. |
| 5 | Security | A credential environment value containing CR/LF could become a header-splitting value inside ZAP. | high | Fixed: resolved header secrets must pass strict HTTP header-value validation without entering the diagnostic. |
| 6 | Security | GraphQL import rejection recognized `#import` but not whitespace, case, or BOM variants. | medium | Fixed: import comment detection normalizes those lexical variants and tests all three. |
| 7 | Correctness | Authentication statistics selected the first suffix match, so a lower unrelated counter could hide a larger logged-out count. | medium | Fixed: all compatible counters are aggregated conservatively by maximum. |
| 8 | Resource safety | The recursive artifact entry ceiling did not count sockets, FIFOs, or directories. | medium | Fixed: every non-root filesystem entry counts, only real directories are traversed, and only regular-file bytes are summed. |
| 9 | Simplification | The new service could have coexisted with the legacy implicit quick-scan wrapper and created two behavioral owners. | medium | Fixed in implementation: the legacy wrapper is removed and all public hosts route through the single agent-neutral service. |

## Phase 4 — Validate

- Tests run (commands and outcomes): strict all-feature lint passed for the root and affected
  packages; the direct workspace all-feature suite passed with 1,204 root cases, 4 reasoned root
  ignores, and every package, integration, and doc-test suite green; the 32 root and 3 core
  application-DAST cases passed; the two artifact-budget cases passed; exact module-list,
  adapter-census, process-backed-wrapper, and task-abort ownership contracts passed; and Semgrep
  reported no findings.
- Pinned-runtime proof: three individually selected loopback-only integrations passed against ZAP
  2.17.0 on build-host scratch storage: OpenAPI import and operation coverage, header persona
  authentication without public secrets, and browser/session authentication through the pinned
  ChromeDriver 151.0.7922.137 executable.
- Gate run and receipt: `bash bin/gate.sh --fast` passed all 14 applicable lanes with zero failures.
  The non-mutation delivery lanes then passed with 81.65% line coverage, 1,701/1,701 strict Nextest
  cases, and green PostgreSQL plus CLI/MCP contracts after replacing an obsolete TCP database URL
  with the build host's peer-authenticated local connection.
- Mutation evidence: the sole broad DIFF inventory completed all 564 candidates in two hours: 255
  caught, 3 timed out and counted as caught, 229 missed, and 77 unviable, for 52.97% viable MSI.
  The 229 unique survivors reduce to 72 functions across 15 files. Raw artifacts are preserved at
  `.git/scorchkit-mutants-broad-ticket-013` with summary, outcomes, and inventory SHA-256 values
  `56131ba24af291eee81d4663bc8b0d1c3c7ea15f1935d4bb198d3d9f0d96664f`,
  `6b3a4c002e8ad3e1dc591146a3e8dfc62eac2d66fbd6133cf017767cae2b4bbc`, and
  `53886bf543a91e6d0031e144a1e74d5477db342efefad2839822aab7aed2ccd5`.
  Per the owner's standing direction and REQ-010, it will not be repeated; repairs and mutation
  rechecks are limited to those exact named survivors.
- Focused repair: the first exact 229-survivor pass caught 220 and exposed nine residual seams. The
  next current-tree pass covered 72 mutations in the repaired functions and produced 63 caught, 2
  timeouts, 3 unviable, and 4 misses. Those misses led to key-based persona sorting, a wrong-method
  correlation fixture, and deterministic injected filesystem-race readers. One output-equivalent
  percent-encoding guard was simplified instead of adding artificial test behavior. The final
  current-tree scope selected 71 mutations in 11 repaired functions across 6 files: 67 caught, 1
  timeout counted as caught, 3 unviable, and 0 missed. Sealed evidence verifies 68/68 viable caught,
  100% MSI, mutation-input SHA-256
  `36cb0529a18379c152cfb1c6abfccb0396f2fa128f4cd582e8e8eb3231d93a04`, and evidence digest
  `d506d1ad908daa3d1876b0198cca28baf8afa1fe447ae3c3ff88b9414775129f` under
  `.git/scorchkit-mutants-focused-ticket-013`. The two prior focused passes remain preserved beside
  it for audit.
- Delivery reseal: the first focused gate exposed two validation-only defects after the 71-mutation
  seal: the shared test environment lock was restricted to the `infra` feature even though ZAP
  doctor tests use it in default builds, and a redaction fixture variable triggered the hardcoded-
  secret rule. The lock now exists in every test build and the fixture passes its literal directly
  to the redactor. The exact current-tree follow-up added only the two deserializers and ZAP doctor
  function exercised by those corrections to the 11 repaired functions. All 83 selected mutations
  completed: 77 caught, 2 timeouts counted as caught, 4 unviable, and 0 missed. Sealed evidence at
  `.git/scorchkit-mutants-focused-ticket-013-delivery` verifies 79/79 viable caught, 100% MSI,
  mutation-input SHA-256 `e143adf9e9040fe0e610f0d9702a4e5249cbf6f0a5992f09bb965bed9aebb976`,
  and evidence digest `cabf1b2a389bd03b3eccaace31b5db1b3fa058deb0fb0b70cafad6d9388b2a38`.
  The sole broad inventory and every preceding focused pass remain preserved; none was rerun.
- Final staged-tree follow-up: synchronizing the version-probe test with process-wide `PATH`
  fixtures first caught all five `get_tool_version` mutants. Strict lint then rejected holding the
  synchronous environment guard across `.await`, so the test now runs the async probe through a
  private current-thread runtime while the outer synchronous scope owns the guard. The same exact
  five-mutant scope was rechecked once on that final tree: all 5 were caught with no timeouts,
  unviable cases, or misses. Sealed evidence at
  `.git/scorchkit-mutants-focused-ticket-013-delivery-final-2` verifies 5/5 viable caught, 100% MSI,
  mutation-input SHA-256 `d3c56d3e8f9932a85187be7bbd28f227879f19e75fbf2da8bffbaef6585c1b94`,
  and evidence digest `7b4c16749ebd3b894a592bf0b37bed4abca4f1905bd89e045f37aac862fe76cb`.
  The first five-case seal and earlier 83-mutation delivery seal remain preserved; neither was
  broadened or rerun.
- Documented skips with reasons: the three pinned-runtime tests remain ignored in the ordinary
  suite because they require the separately checksum-verified build-host ZAP/browser runtime; they
  were executed explicitly above. Fast mode intentionally skipped coverage, mutation, Nextest,
  PostgreSQL, and built CLI/MCP lanes; the final DIFF gate owns those lanes. Web UI lanes remain not
  applicable because ScorchKit ships no web UI. The approved focused-repair gate owns the final
  non-mutation delivery lanes and verifies the sealed current-tree scope without compiling another
  mutant.

## Phase 5 — Complete

- Docs updated: the changelog, README, application DAST architecture, application-security catalog,
  CLI, configuration, MCP, module, runner, storage, report, tool, operator-checklist, ticket,
  pipeline, roadmap, and knowledge pages describe the shipped authenticated schema-driven DAST
  service, exact runtime pins, policy and credential boundaries, typed coverage, and unsupported
  targets. The roadmap closes SK-038 and promotes SK-039 to the head of the remaining queue.
- AAR submitted: `AAR-013-authenticated-dast` records the nine inspection findings, five novel
  defects, five reusable prevention rules, validation corrections, exact focused mutation proof,
  and a 5/5 effectiveness assessment.
- Archive: this notes/spec pair and TICKET-013 are ready for pipeline-controlled archival. The
  archive invalidates the pre-completion receipt, so delivery reruns the same focused-repair gate
  against `.git/scorchkit-mutants-focused-ticket-013-delivery-final-2` without launching
  cargo-mutants.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | ZAP plan execution tried the default proxy port instead of an ephemeral port. | ZAP interprets `-port 0` as its default rather than an operating-system allocation request. | Reserve a nonzero loopback port and pass it explicitly. | Retain the nonzero-port unit assertion and exact loopback integrations. |
| 2 | The first Automation Framework plan rejected requestor fields. | The requestor job does not accept context or inline test fields. | Removed unsupported fields and added a bounded pre-discovery HAR proof owned by ScorchKit. | Keep deterministic plan assertions and pinned-runtime loopback cases. |
| 3 | Header authentication was reported unknown even though protected requests succeeded. | The auth report has no positive login statistics for manual header authentication. | Combine exact HAR transport/status/body proof with the bounded final authentication report. | Require both artifacts and retain the header-secret canary test. |
| 4 | Browser startup failed after the host browser upgraded. | ZAP's bundled ChromeDriver major no longer matched installed Chrome. | Installed checksum-pinned ChromeDriver 151.0.7922.137 on scratch storage and added explicit driver configuration. | Document and doctor the pinned add-ons; require operator maintenance when the browser major changes. |
| 5 | Artifact accounting raced transient Chrome profile deletion. | Browser descendants remove temporary files while the recursive budget walk is in progress. | Stop the owned process tree before final accounting and ignore only vanished descendant entries, never the root. | Retain the executor artifact test and browser loopback integration. |
| 6 | The first browser fixture logged in but never authenticated later requests. | Its JSON token response had no browser behavior that stored and replayed the token. | Model a normal protected application with a scoped HTTP-only session cookie and redirect. | Keep fixture behavior representative of browser-managed sessions. |
| 7 | The version probe received persona credentials before the executable proved its version. | The scan and probe reused one environment map. | Give version mode a structurally credential-free clean environment; inject persona and driver variables only into the validated plan run. | Retain the exact probe-environment regression test. |
| 8 | URL-only coverage could mark a POST schema operation observed after only a GET to the same route. | The URL export has no request method. | Require a bounded final traffic HAR and match both method and route template. | Retain method-mismatch and out-of-scope HAR tests. |
| 9 | Process and artifact failures discarded an already-compiled plan digest. | The error path accepted only `ScorchError` and always wrote an empty digest. | Carry optional compiled-plan identity with persona failures. | Assert both pre-plan empty and post-plan retained digest cases. |
| 10 | Header personas could override request authority/framing or inject a second header line. | Validation accepted every syntactically named header and did not validate the resolved value as an HTTP header value. | Reject authority/framing names and CR/LF-bearing resolved values before process launch. | Retain name and canary-safe value tests. |
| 11 | GraphQL import variants bypassed the first lexical check. | The check matched only the exact `#import` prefix. | Normalize BOM, whitespace, and keyword case before recognizing import comments. | Retain variant fixtures. |
| 12 | Non-regular artifacts and directories did not consume the entry count. | The walker incremented only symlinks and regular files. | Count every child entry while following only real directories and summing only regular-file bytes. | Retain Unix-socket budget proof and live browser integration. |
| 13 | Fast validation initially failed strict lint in newly added DAST routines and integration helpers. | Default-feature focused checks did not exercise every all-feature/all-target lint path. | Split plan, parser, alert, and process-output work into smaller helpers and made test setup return typed results. | Run the repository feature-matrix lint before the first fast-gate handoff for feature-gated additions. |
| 14 | Legacy ZAP removal left four catalog expectations stale. | Template, CLI, executor-contract, and adapter-census assertions encoded the old module owner independently. | Updated every exact catalog boundary and removed the obsolete adapter descriptor. | Treat module removal as a registry, template, CLI, descriptor, and process-count transaction. |
| 15 | The ownership-drop test timed out under the parallel gate. | It polled indirectly for a full scan run to reach ownership through a fixed wall-clock budget. | Extracted the production ownership acquisition seam and synchronized the abort test with an exact one-shot handoff. | Async lifecycle tests wait on the asserted production transition, not elapsed time or unrelated network setup. |
| 16 | The first DIFF delivery attempt stopped before mutation. | Its saved TCP database URL no longer authenticated after the build-host upgrade. | Used the same named database through the host's healthy peer-authenticated local role; coverage, Nextest, PostgreSQL, and CLI/MCP lanes passed. | Record both host and authentication boundary with reusable validation URLs. |
| 17 | The completed changed-code inventory measured 52.97% MSI. | High-level happy-path tests exercised the feature but did not pin every validation operator, alternate ZAP shape, enum mapping, and exact output helper. | Preserved the 564-outcome baseline and reduced its 229 misses to 72 exact functions for table-driven focused repair. | Each security boundary and parser representation gets an exact observable contract; never repeat the broad inventory during repair. |
| 18 | The first commit attempt was blocked after staging the legacy ZAP deletion. | The gate and mutation-input inventories read cached and untracked paths but omitted paths whose deletion had already been staged, contradicting the receipt contract that staging does not change the tree fingerprint. | Include staged deletions as explicit missing paths in both inventories and add a real staged-deletion hook selftest. | Receipt and evidence hashing must preserve the same path set before and after staging additions, modifications, and deletions. |
| 19 | A staged-tree gate intermittently failed the tool-version probe while its focused rerun passed. | The test resolved `printf` while concurrent ZAP doctor fixtures temporarily replaced process-wide `PATH`; those fixtures held the environment lock but the version-probe test did not. | Acquire the shared environment lock in a synchronous test and run the async probe through a private current-thread runtime, then seal only the affected `get_tool_version` scope. | Every test that reads or writes process-wide environment state participates in the same synchronization boundary without holding a synchronous lock across an await point. |
