---
title: INTAKE-security-suite-architecture
status: candidate
created: 2026-08-23
ticket:
pipeline_spec:
---

# Layer ScorchKit into a full application-security suite

## Problem or opportunity

ScorchKit already has deep SAST, supply-chain, DAST, correlation, and narrow application-pentest
capabilities, but they are presented primarily as scanner families and individual workflows. The
next product step is to make them one coherent application-security suite with explicit suite
boundaries, a resumable assessment process, machine-readable technique packs, shared coverage, and
focused source-to-runtime feedback.

Strix is a useful reference for the missing workflow. Its root coordinator decomposes an assessment,
specialists perform discovery and validation, findings pass through a reporting boundary, the agent
graph can resume, and quick/standard/deep modes change the methodology. Its strongest operational
ideas are the shared HTTP workbench, browser sessions, source-aware testing sequence, technique
playbooks, explicit lifecycle tools, closeout budget reserve, and live task graph.

ScorchKit should implement those ideas as typed engine behavior. It must not copy Strix's generic
shell, prompt-enforced authorization, rolling offensive workstation, or model-authored evidence
boundary. ScorchKit remains the tool: hosts and models may propose and explain work, but ScorchKit
owns authorization, execution, coverage, evidence, lifecycle, and durable state.

## Research basis

The reference review used Strix `1.5.3` at commit
[`1c499c5b2d788c553f0d276b389b2b424e483304`](https://github.com/usestrix/strix/commit/1c499c5b2d788c553f0d276b389b2b424e483304).
The repository was inspected locally rather than inferred from its feature list.

### Strix execution process

1. Inputs normalize repositories, local source, URLs, IPs, API specifications, instructions, mode,
   budgets, and resume state into one scan configuration.
2. The runner starts or restores one sandbox, one shared proxy/traffic workspace, an agent graph,
   per-agent SQLite histories, notes, todos, reports, and model-budget state.
3. A root coordinator reads scope and decomposes the assessment. Its intended role is orchestration,
   coverage tracking, and final synthesis rather than hands-on testing.
4. Reconnaissance and source mapping create the initial target and attack-surface map.
5. Focused specialists investigate one component or technique. Work is added reactively as routes,
   technologies, hypotheses, and findings appear.
6. A candidate finding receives an independent validation/PoC task. A validated finding receives a
   reporting task, with a source fix proposal when source is available.
7. The root reviews filed findings for duplication, chaining, uncovered surfaces, and closeout.
8. Explicit lifecycle tools settle children and write Markdown, JSON, CSV, SARIF, and run-state
   artifacts. Interrupted runs can restore the graph and model sessions.

Relevant reference seams:

- [top-level runner and resume](https://github.com/usestrix/strix/blob/1c499c5b2d788c553f0d276b389b2b424e483304/strix/core/runner.py#L112-L487);
- [root coordinator methodology](https://github.com/usestrix/strix/blob/1c499c5b2d788c553f0d276b389b2b424e483304/strix/skills/coordination/root_agent.md);
- [source-aware white-box sequence](https://github.com/usestrix/strix/blob/1c499c5b2d788c553f0d276b389b2b424e483304/strix/skills/coordination/source_aware_whitebox.md);
- [agent graph tools](https://github.com/usestrix/strix/blob/1c499c5b2d788c553f0d276b389b2b424e483304/strix/tools/agents_graph/tools.py);
- [agent coordinator state](https://github.com/usestrix/strix/blob/1c499c5b2d788c553f0d276b389b2b424e483304/strix/core/agents.py);
- [HTTP workbench operations](https://github.com/usestrix/strix/blob/1c499c5b2d788c553f0d276b389b2b424e483304/strix/tools/proxy/tools.py);
- [bounded output spill](https://github.com/usestrix/strix/blob/1c499c5b2d788c553f0d276b389b2b424e483304/strix/tools/output_store.py);
- [structured reporting gateway](https://github.com/usestrix/strix/blob/1c499c5b2d788c553f0d276b389b2b424e483304/strix/tools/reporting/tool.py).

### What the reference does not provide

- Most scanners are not typed Strix tools. Nuclei, Semgrep, SQLMap, Nmap, ffuf, Python scripts, the
  browser, and other binaries are invoked through a generic agent shell.
- The root/specialist role split and discovery-validation-reporting chain are primarily prompt
  instructions. All agents receive much of the same tool surface.
- Quick, standard, and deep are methodology skills rather than deterministic capability, effect,
  coverage, and budget contracts.
- Proxy scope rules filter the proxy view; they are not equivalent to ScorchKit engagement and
  effect enforcement.
- Report fields are structured, but model-authored PoC and evidence text is not automatically
  equivalent to immutable scanner evidence.

These limitations define the adaptation: borrow the process vocabulary, then make it enforceable in
ScorchKit's engine.

## Proposed outcome

ScorchKit becomes a layered application-security suite with:

- coherent recon, SAST, supply-chain, DAST, pentest, workflow, and triage domains;
- one durable work graph for discovery, detection, validation, correlation, reporting, remediation,
  and regression verification;
- versioned assessment packs for frameworks, protocols, technologies, vulnerability techniques,
  and workflow profiles;
- structural source maps that guide runtime testing;
- a policy-owned HTTP traffic/query/replay ledger and isolated browser executor;
- stateful, script-free application-pentest scenarios with captures, assertions, persona changes,
  concurrency, cleanup, and negative controls;
- coverage reconciled by asset, route, parameter, persona, technique, phase, and evidence class;
- bounded previews backed by immutable, redacted, digest-bound full artifacts;
- the same complete behavior through the library, CLI, MCP, control API, CI, and optional frontends.

General Active Directory, password spraying, persistence, lateral movement, broad infrastructure
exploitation, and cloud-account exploitation remain explicit compatibility or optional-extension
families. Making them default suites requires a separate product-boundary decision.

## ScorchKit-native assessment workflow

```text
engagement + registered assets + source/artifacts/personas
                         |
                         v
       suite profile and assessment-pack compilation
                         |
                         v
 typed work graph: objectives, dependencies, effects, budgets,
 selectors, coverage obligations, cleanup, and evidence classes
                         |
             +-----------+-----------+
             |                       |
             v                       v
 structural/source/SCA work     runtime/recon work
             |                       |
             +-----------+-----------+
                         v
            deterministic candidate hypotheses
                         |
                         v
          independent focused validation / PoC
                         |
              +----------+----------+
              |                     |
              v                     v
       rejected candidate      validated finding
                                    |
                                    v
                correlation, attack path, and triage
                                    |
                                    v
              remediation proposal and regression case
                                    |
                                    v
              comparable verification and final coverage
```

Every graph node carries a stable objective kind, suite, target and selectors, dependencies,
required capability/effect pairs, executor or module selection, resource and closeout budgets,
cleanup contract, expected evidence classes, coverage obligation, proposal provenance, and terminal
state. Initial states should distinguish `planned`, `ready`, and `blocked`; terminal outcomes must
distinguish `complete`, `no_finding`, `incomplete`, `degraded`, `failed`, and `cancelled`.

Discovered routes, components, schemas, findings, and attack paths may produce typed follow-up
proposals. The engine validates, deduplicates, budgets, and reauthorizes each proposal before it can
become runnable work. An agent message or playbook sentence never adds an effect.

## Candidate crate architecture

Crates represent coherent domains, not individual tools.

```text
Kernel and shared contracts
  scorchkit-policy       engagement, scope, capabilities, effects, decisions
  scorchkit-core         universal targets, findings, evidence, observations, events
  scorchkit-config       safe configuration and credential references
  scorchkit-executor     jobs, scheduling, cancellation, budgets, ownership
  scorchkit-tools        bounded process and artifact execution
  scorchkit-storage      persistence record contracts
  scorchkit-control      provider-neutral application-service contract

Security suites
  scorchkit-recon        application attack-surface inventory and discovery coverage
  scorchkit-sast         source map, source findings, code flows, secrets, coverage
  scorchkit-supply-chain dependency graph, SBOM, advisories, artifacts, reachability
  scorchkit-dast         authenticated discovery, traffic, browser, probes, replay
  scorchkit-pentest      scenarios, invariants, validation, cleanup, attack chaining
  scorchkit-triage       validation, disagreement, risk, fix, regression lifecycle

Cross-suite composition
  scorchkit-workflow     work graph, assessment packs, profiles, budgets, coverage

Interfaces and composition
  scorchkit-cli / scorchkit-mcp / scorchkit-agent / future frontends
  scorchkit              root effectful composition and compatibility facade
```

### Migration rules

- Do not perform rename-only churn. `scorchkit-code` and `scorchkit-web` already own SAST and
  DAST/recon vocabulary. They can remain compatibility packages while `scorchkit-sast` and
  `scorchkit-dast` product contracts are introduced, or evolve behind explicit re-exports.
- Move inert contracts before concrete behavior. Policy-sealed contexts and concrete modules remain
  in the root composition until they can move without exposing constructible authorization state.
- Suite crates do not depend directly on each other. They exchange core artifacts and inert work
  proposals. `scorchkit-workflow` composes them; the root performs effects.
- Universal finding, evidence, observation, target, event, and attack-path identities remain in
  `scorchkit-core`.
- Good first extraction candidates from core/root are the application DAST, application pentest,
  and supply-chain domain contracts. Preserve root import paths and exact wire identities.
- Workspace gates, documentation, mutation inventory, feature states, dependency checks, and
  external consumer tests expand in the same ticket as any package extraction.

## Assessment-pack contract

Strix's 70 Markdown playbooks are useful organization, but ScorchKit packs need an executable,
machine-readable layer. A `scorchkit.assessment-pack/v1` pack should declare:

- suite, role, supported target kinds, languages, frameworks, technologies, and protocols;
- required source-map, schema, route, persona, artifact, traffic, or finding inputs;
- exact module and scenario selectors;
- required capabilities and effect classes;
- required external tools, versions, configuration identities, and readiness probes;
- ordered phases and typed follow-up rules;
- per-profile time, request, concurrency, output, artifact, and model-analysis budgets;
- expected evidence classes, negative controls, cleanup obligations, and completion criteria;
- pack identity, version, digest, provenance, compatibility, and review status;
- optional human/model guidance stored separately from the enforceable metadata.

Initial packs should focus on capabilities where coordinated testing adds value:

- OAuth/OIDC and GraphQL;
- Django, FastAPI, NestJS, and Next.js;
- BOLA/IDOR and BFLA;
- business logic, workflow abuse, race conditions, and idempotency;
- insecure deserialization, argument injection, and semantic confusion;
- browser trust boundaries;
- LLM/RAG/agent applications;
- Electron applications;
- infrastructure lifecycle and abandoned application dependencies.

Installed tools do not make a pack ready. Readiness requires exact compatible executables,
configuration/rule identities, supported target inputs, and all policy grants. Unavailable work is a
typed gap and never disappears from coverage.

## Tool and capability decisions

Strix's image is an inventory source, not a distribution model. ScorchKit already has direct
adapters or stronger native services for most high-value Strix tools.

| Capability seen in Strix | ScorchKit disposition |
|---|---|
| Semgrep, Bandit, ESLint, Gitleaks, TruffleHog | Retain existing bounded SAST adapters. |
| Nuclei | Retain the signed, pinned, HTTP-only ScorchKit runtime. |
| SQLMap, Wapiti, ffuf, Arjun, wafw00f | Retain existing bounded DAST adapters. |
| Nmap, Naabu, Subfinder, httpx, Katana | Retain application-recon or explicit compatibility placement. |
| Interactsh | Retain ScorchKit's owned callback lifecycle. |
| Trivy | Retain the offline, digest-bound shared-SBOM consumer. |
| ZAP | Retain the authenticated Automation Framework service; Strix does not install ZAP in its current image. |
| Dirsearch, GoSpider | Defer; existing native crawler, Katana, ffuf, Feroxbuster, and Gobuster substantially overlap. |
| Vulnx/CVEMap | Avoid an ad hoc remote lookup path; retain policy-owned provider snapshots. |
| jwt_tool | Extend native JWT scenarios when a measured technique gap exists. |
| JS-Snooper, jsniper | Borrow endpoint/bundle analysis ideas; do not adopt unpinned shell scripts. |
| Arbitrary Python, shell, and tool installation | Keep outside the core execution model. |
| ast-grep and Tree-sitter | Add pinned providers behind one structural source-map contract. |
| `govulncheck` | Add a narrow typed adapter for symbol-level Go dependency reachability. |
| `agent-browser` | Borrow the interaction pattern; implement a typed policy-owned browser executor. |
| Caido | Borrow request query/sitemap/replay operations; do not make Caido a core dependency. |
| Hurl | Consider an exact pinned backend generated from a restricted typed scenario; do not run arbitrary caller files. |
| Hypothesis/property testing | Defer to an isolated local-validation extension after the effect and fixture model exists. |

### Structural source map

Add one provider-neutral artifact describing routes and handlers, parameters and schemas,
authentication/authorization guards, sources and sinks, serializers/parsers, filesystem/command/
template/outbound-request operations, framework/language provenance, and parser coverage gaps.
Initial providers may use pinned Tree-sitter grammars and ast-grep query packs. The artifact feeds
SAST selection, DAST schema and route coverage, pentest planning, supply-chain reachability, and
source/runtime correlation.

### HTTP traffic and replay workbench

Start over ScorchKit's existing ZAP, HAR, HTTP-exchange, and finding-evidence records. Add typed
operations equivalent to:

- request query and bounded preview;
- full digest-bound request/evidence lookup;
- attack-surface route tree;
- inert replay planning;
- authorized replay with exact modifications and negative controls;
- capture visibility that never substitutes for engagement policy.

Every replay rechecks the engagement, target, DNS answer, redirect, persona, capability, effect,
request budget, response budget, and artifact limits. A later TLS-intercepting proxy is a separate
effectful increment, not a prerequisite for the ledger.

### Focused browser executor

Use a typed `open -> accessibility snapshot -> act on expiring reference -> resnapshot` contract.
Sessions bind one persona and initial authorized origin and isolate cookies, local storage, tabs,
downloads, and screenshots. Initial actions should be bounded navigation, click, fill, select,
submit, wait, and JavaScript-free extraction. Each navigation, redirect, download, upload, and
network destination is policy checked. DOM, accessibility, screenshot, and network evidence are
bounded artifacts. Script evaluation is omitted initially or receives a distinct stronger effect.

### Stateful application-pentest scenarios

Extend the current single-operation compiler with a script-free workflow graph:

- ordered HTTP and browser steps;
- typed values captured from prior responses;
- assertions and negative controls at each transition;
- persona changes without credential values in the plan;
- expected allow/deny and state invariants;
- bounded concurrent branches for race, replay, and idempotency checks;
- explicit cleanup steps and residual-state verification;
- paired vulnerable/fixed regression executions.

The compiler owns the allowed operations. A Hurl-like file, browser script, Python program, or model
message is never direct authority or an unreviewed payload program.

## Recommended roadmap splice after SK-049

SK-049 is already active. SK-050 through SK-057 are candidates, so the next dedicated roadmap
ticket should reorder the unpromoted work rather than append the security suite after frontends and
team deployment.

| Order | Candidate batch | Outcome | Existing work absorbed or shifted |
|---:|---|---|---|
| 1 | Suite architecture and compatibility extraction | Add suite identities, module roles, shared coverage obligations, new suite contract packages, and compatibility re-exports without changing scanner behavior. | New; establishes the crate model before further extension work. |
| 2 | Capability-declared extension runtime | Add isolated first/third-party modules whose manifests name suite, role, pack, inputs, outputs, effects, and budgets. | Current SK-050 candidate, shifted after suite contracts. |
| 3 | Typed assessment work graph and pack compiler | Evolve events/hooks into durable intake, plan, authorize, execute, normalize, correlate, validate, reconcile, report, and notify nodes with closeout reserves. | Expands current SK-051 typed-run-pipeline candidate. |
| 4 | Structural source intelligence and SAST depth | Add source-map schema, Tree-sitter/ast-grep providers, framework/route/guard extraction, and source-ranked follow-up proposals. | New suite work; builds on SK-036 and source/runtime correlation. |
| 5 | Supply-chain reachability and deployed artifacts | Add `govulncheck`, import/symbol/call-path evidence, deployed JavaScript inventory, and stronger source-to-artifact linkage. | Deepens SK-037 instead of adding duplicate CVE scanners. |
| 6 | Application recon, traffic, and browser DAST | Add attack-surface inventory, HTTP ledger/query/replay, focused browser sessions, persona-aware coverage, and captured evidence. | Deepens SK-038, SK-039, and SK-041. |
| 7 | Stateful pentest scenarios and chaining | Add workflow/state invariants, race/idempotency scenarios, cleanup proof, evidence-driven follow-ups, and bounded attack-path iteration. | Deepens SK-041. |
| 8 | Cross-suite profiles, coverage, and evaluations | Compile change, quick, standard, deep, staging, and release profiles into exact graphs and benchmark tool/pack additions on validated coverage and cost. | Makes current profile/workflow concepts suite-complete. |
| 9 | Provider-neutral model roles | Let optional planners, specialists, validators, reporters, and remediation advisers consume and propose graph work without execution authority. | Current SK-052 candidate moves after the engine-owned workflow exists. |
| 10 | Finding triage and validated remediation | Add append-only candidate, validation, disagreement, risk, fix, and regression states plus exact suggested-patch artifacts. | Current SK-053 candidate, expanded by validation-chain research. |
| 11 | Conversation and local-console views | Present the same graph, traffic, evidence, findings, coverage, and triage through optional clients. | Current SK-054 and SK-055 candidates. |
| 12 | Team deployment and signed catalog | Add tenant isolation, then signed extension and assessment-pack distribution, revocation, and conformance. | Current SK-056 and SK-057 candidates. |

The roadmap ticket should assign final SK identifiers, update each affected intake link, and preserve
one canonical order. It must not present candidate crates, tools, packs, browser execution, proxy
capture, or workflow behavior as shipped.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When ScorchKit describes its application-security inventory, it shall identify each module, scenario, work role, coverage obligation, and artifact as belonging to exactly one suite while preserving one shared finding and evidence contract. | Exact suite/module census, uniqueness checks, and cross-suite finding/evidence type-identity tests. |
| REQ-002 | When a suite contract moves into a package, ScorchKit shall preserve public root paths, wire identities, feature behavior, policy-sealed construction, and the exact allowed workspace dependency direction. | External consumer fixtures, negative visibility tests, schema snapshots, feature matrix, and workspace architecture tests. |
| REQ-003 | When an assessment profile or pack is compiled, ScorchKit shall produce a deterministic bounded work graph containing exact dependencies, selectors, capability/effect requirements, budgets, cleanup, expected evidence, and coverage obligations without executing an effect. | Canonicalization/permutation tests, exact graph fixtures, and no-client/no-file/no-process planning tests. |
| REQ-004 | When a finding, route, component, schema, or attack path proposes follow-up work, ScorchKit shall validate, deduplicate, budget, and reauthorize the proposal before it becomes runnable and shall retain rejected or unsupported work as a typed gap. | Proposal widening, duplicate, unsupported-selector, missing-grant, budget, and accepted-follow-up matrices. |
| REQ-005 | When work reaches a terminal state, ScorchKit shall distinguish clean negative coverage from incomplete, degraded, failed, and cancelled work and shall reconcile the result across asset, operation, persona, technique, pack, phase, and evidence class. | Complete cross-product coverage fixtures and CLI/MCP/API/report projection parity. |
| REQ-006 | When a requested assessment pack depends on a tool, grammar, query pack, persona, schema, or artifact, ScorchKit shall verify the exact compatible dependency before execution and shall report unavailable or mismatched dependencies as coverage gaps. | Missing, wrong-version, wrong-digest, incompatible-target, and exact-ready tests. |
| REQ-007 | When structural source mapping runs, ScorchKit shall emit bounded typed routes, handlers, parameters, guards, sources, sinks, operations, provenance, and parser coverage without treating unsupported languages or parse failures as clean coverage. | Multi-language fixtures, malformed/unsupported inputs, provider parity, and source-to-runtime selector tests. |
| REQ-008 | When HTTP traffic is queried or replayed, ScorchKit shall use redacted digest-bound evidence, compile exact modifications, and reauthorize the target, addresses, redirects, persona, capability, effect, and budgets before a request. | Existing-evidence query fixtures plus loopback replay allow/deny, redirect, DNS, persona, mutation, and ceiling tests. |
| REQ-009 | When a browser workflow executes, ScorchKit shall isolate the named persona and browser state, authorize each navigation and network effect, permit only typed bounded actions, retain bounded evidence, and tear down the complete session on every terminal path. | Multi-persona loopback application, cross-origin/redirect denial, expiring reference, artifact ceiling, cancellation, and descendant cleanup tests. |
| REQ-010 | When a stateful pentest scenario executes, ScorchKit shall bind captured values, assertions, persona transitions, concurrency, negative controls, cleanup, and residual-state checks to one approved typed plan and shall reject arbitrary scripts or uncompiled workflow files. | State-machine, race/idempotency, cleanup success/failure, plan-mismatch, script/file injection, and comparable regression tests. |
| REQ-011 | When a candidate vulnerability advances, ScorchKit shall append independent validation, rejection, reporting, remediation proposal, fix, and regression evidence without mutating the original scanner observation or converting model text into scanner evidence. | Transition truth table, disagreement preservation, provenance, immutable-original, and model-output separation tests. |
| REQ-012 | When an assessment is interrupted or a subscriber lags, ScorchKit shall restore the durable work graph, budgets, artifacts, coverage, and terminal outcomes without replaying committed effects or relying on model conversation history. | Crash/recovery, stale lease, event replay, exact-once commit identity, and no-model resume tests. |
| REQ-013 | When tool output exceeds a projection limit, ScorchKit shall return a bounded redacted preview and immutable artifact identity while retaining the complete bounded artifact under engine ownership. | Boundary, redaction, digest, storage/readback, authorization, and cleanup tests. |
| REQ-014 | When a new scanner or backend is proposed, ScorchKit shall require evidence of unique or improved coverage, reproducible exact-version execution, parser integrity, policy integration, and bounded resource behavior before adding it to a default suite. | Benchmark dossier and adapter conformance gate against an overlapping existing capability. |

## Scope notes

- In:
  - full application-security suite taxonomy and crate layering;
  - behavior-preserving contract extraction and compatibility strategy;
  - engine-owned assessment work graph, playbook compiler, budgets, lifecycle, and coverage;
  - structural source maps and source-informed runtime selection;
  - policy-owned HTTP evidence query/replay and focused browser operation;
  - stateful application workflows, business invariants, race/idempotency, cleanup, and regression;
  - specific, benchmark-backed tool gaps rather than inventory parity;
  - optional model and frontend clients over the same typed engine workflow.
- Out:
  - embedding or invoking Strix as a ScorchKit dependency or sidecar;
  - adopting a rolling Kali image, generic shell, arbitrary Python, or scan-time tool installation;
  - treating prompts, packs, agent roles, manifests, proxy visibility, or plan identity as authority;
  - copying Strix report text or skill prose into scanner evidence;
  - adding overlapping scanner wrappers without measured coverage benefit;
  - making general network, enterprise identity, cloud-account exploitation, persistence, privilege,
    or lateral movement part of default application-security profiles;
  - implementing the proposed suites, renumbering current candidates, or editing the active SK-049
    roadmap within this intake.

## Promotion notes

- Complete active TICKET-027/SK-049 before opening a roadmap or suite-architecture ticket.
- Promote this intake first as a documentation/architecture ticket that assigns final batch IDs,
  updates the canonical roadmap, and creates one scoped intake per new product batch.
- Preserve the current roadmap and active control-API diff until that ticket is delivered.
- Use pattern-level reimplementation by default. Any direct Strix code or prose reuse requires an
  explicit Apache-2.0 attribution and compatibility review; third-party tools retain their own
  licenses independently of Strix.
- Benchmark candidate tools and packs against local disposable applications with identical targets,
  personas, time, request, and resource budgets. Record validated unique findings, false positives,
  negative coverage, evidence reproducibility, scope denials, cleanup, runtime, and cost.
