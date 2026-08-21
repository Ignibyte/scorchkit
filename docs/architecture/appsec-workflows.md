# Application-security workflow profiles

TICKET-017 presents ScorchKit's existing application-security capabilities as a versioned,
provider-neutral workflow without creating a second execution engine. Codex is the preferred host:
its plugin coordinates semantic review and ScorchKit MCP tools, while ScorchKit remains the only
authority for deterministic effects, scanner evidence, policy decisions, and durable state.

## Boundary

```text
Codex plugin / another agent host
        |
        | application_context + plan_appsec_workflow (read-only)
        v
versioned context and inert ordered plan
        |                              |
        | labeled host analysis        | existing ScorchKit MCP tools
        v                              v
Codex Security / equivalent host       policy-gated source, SCA, artifact,
semantic review                        runtime, correlation, and pentest work
        |                              |
        +-------------+----------------+
                      v
          separate analysis and scanner-evidence layers
```

The workflow plan is not authorization, execution, evidence, target registration, or a scan result.
It contains exact requirements for later operations, including which steps are broad, which require
a project or registered target, and which target/capability/effect tuples remain subject to the
existing execution boundary. A prompt, profile, context identity, project, or plan identity cannot
supply a missing grant.

## Application context

`ApplicationSecurityContext` is assembled only after the existing `CodeScan`/`Passive` check for
the canonical local root. Its identity binds:

- the canonical code root, bounded detected languages, and root-relative manifests;
- one optional immutable Git change set containing distinct hexadecimal base/head revisions and a
  bounded canonical set of root-relative changed paths;
- host-declared root-relative artifacts and normalized application routes, each explicitly labeled
  as declared context rather than detected scanner evidence;
- configured persona labels without environment-variable names or values;
- project-registered HTTP(S) targets normalized without URL userinfo, fragment, or query values;
- the configured engagement capability and exact effect labels, which are inventory only; and
- typed gaps for missing or engine-unverified inputs.

The code adapter discovers languages and manifests through the existing bounded, no-symlink walk.
Routes and built artifacts are not guessed from arbitrary source text in this ticket. A host may
declare them, but their provenance remains visible. Project target membership is durable inventory,
not permission to contact the target.

## Profiles and monotonic expansion

Workflow profiles are separate from the existing quick/standard/thorough/pentest scan depths.
Every plan is a closed ordered list with stable step identities and one stable plan identity.

| Profile | Ordered coverage | Broad steps |
|---|---|---|
| `commit` | one host semantic change review covering the declared changed source, secret, and dependency surfaces | none |
| `pull_request` | commit coverage, then a full-root fast ScorchKit application code/SCA scan when explicitly executed | full-root code/SCA |
| `staging` | pull-request coverage, then registered-target application DAST | inherited full-root code/SCA and runtime target effects |
| `release` | staging coverage, then standard host repository review, full-root deep code/SCA, declared local artifact analysis, and project correlation | full-root repository/source/SCA, artifacts, runtime |
| `deep` | release coverage, then repeated complete independent host repository review | every inherited broad step plus repeated repository semantic review |

Commit plans fail when no exact change set is declared. Pull-request plans use the same boundary for
host semantic review, but clearly mark the deterministic root scan as broad. A deep profile never
runs automatically after a mutation. It is an explicit operator-selected workflow and still cannot
add credential, exploit, external-tool, filesystem, or runtime permission.

The Codex coordinator maps commit and pull-request semantic steps to
`$codex-security:security-diff-scan`, release repository review to
`$codex-security:security-scan` when selected, and deep repository review to
`$codex-security:deep-security-scan`. Those outputs remain labeled host analysis. Other hosts can
substitute an equivalent semantic-review capability without changing the plan schema or ScorchKit.

## Step model

Each `ApplicationSecurityWorkflowStep` records:

- a closed kind and owner (`host_analysis` or `scorchkit_engine`);
- exact scope (`change_set`, `code_root`, `artifact`, `registered_target`, `project`, or
  `focused_selection`);
- a ScorchKit MCP tool name or provider-neutral host capability name;
- whether the work is broad;
- required project, registered target, artifacts, routes, or focused selection;
- required capability and exact effect labels where an engine effect is possible; and
- `ready`, `blocked`, or `unsupported` state plus typed gaps.

The planner never calls the named operation. Execution uses the existing MCP schema and repeats its
normal validation and policy checks. An absent project, artifact, target, route, change set, or
enforceable selector remains a gap; the planner does not drop the step or claim clean coverage.

## Focused remediation

An optional `FocusedVerificationSelection` from attack-path correlation is identity-validated and
preserved as the preferred verification scope. The workflow creates only exact selector steps that
the current public tool contract can enforce. Unsupported rule, template, request, persona, or test
selectors remain typed gaps. The Codex skill must report those gaps and stop; it must not replace
them with a module-wide, profile-wide, repository-wide, or mutation-wide scan.

A broader fallback is a new explicit profile selection. It cannot be inferred from the fact that a
repair was made, a focused selector is unsupported, or a previous broad scan exists.

## MCP and plugin contract

`application_context` and `plan_appsec_workflow` are read-only MCP tools. Both may perform the same
bounded, policy-authorized local context discovery; neither contacts a target, launches an external
tool, writes project state, or runs a scanner. Their structured results use the existing MCP output
envelope and exact tool inventory.

The plugin adds `run-application-security-workflow` as the coordinator. It:

1. requests the typed context and inert plan;
2. checks every gap and asks no effectful tool to compensate for unsupported scope;
3. invokes the appropriate Codex Security skill only for the labeled semantic step;
4. invokes ScorchKit MCP only for ready engine steps explicitly covered by the user's request;
5. treats the engine's policy denial as final; and
6. reports host analysis, scanner evidence, coverage, gaps, and execution identities separately.

The skill contains no terminal fallback and does not install or force-load another plugin. Codex
Security is a preferred host capability. If it is unavailable, the semantic step remains
unavailable; ScorchKit does not impersonate it or broaden deterministic execution.

## Compatibility and security invariants

- No core type or MCP input names an agent vendor.
- Compatibility network, enterprise, and cloud-account scanners are absent from every profile.
- Context inputs are bounded, canonicalized, sorted, deduplicated, and control-character free.
- URL credentials and query values are never accepted into the workflow context.
- Host analysis never becomes scanner evidence or a finding lifecycle transition.
- Profile selection never authorizes a target or effect.
- Planning never refreshes providers, resolves persona credentials, launches a process, or sends
  network traffic.
- Missing and unsupported work remains visible in every projection.
- Mutation validation for this ticket is diff-scoped only; no full or repository-wide mutation
  inventory is part of the workflow.
