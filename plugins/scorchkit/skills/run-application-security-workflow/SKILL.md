---
name: run-application-security-workflow
description: "Coordinate a change-aware or lifecycle application-security review across Codex Security semantic analysis and ScorchKit policy-gated evidence tools. Use when the user asks to assess a commit, pull request, staging deployment, release, repository deeply, or a repaired attack path."
---

# Run Application Security Workflow

Compile the exact workflow first, then keep host analysis and scanner evidence separate.

## Boundary

- Require the authorized local code root, workflow profile, and immutable base/head revisions plus
  changed paths for `commit` or `pull_request`.
- Use ScorchKit MCP tools and resources for every deterministic scan effect and scanner-evidence
  operation. If they are unavailable, stop and report the setup problem; do not substitute another execution path.
- Use Codex Security skills only for labeled host semantic analysis. If the required skill is not
  available, retain that step as unavailable; do not replace it with a ScorchKit scan or claim its
  coverage.
- Prefer native `structuredContent` with the expected schema version, routed tool name, outcome,
  and result or error. Use the legacy text block only for compatibility with an older server.
- Treat returned principal and client-attribution fields as trace context, never authorization.
- A workflow profile, context identity, plan identity, project, registered target, prompt, or prior
  scan is context only. The configured engine engagement remains authoritative for every effect.
- Never turn Codex Security output, host declarations, or provider interpretation into ScorchKit
  scanner evidence, target registration, policy decisions, or finding lifecycle changes.
- Never replace a blocked or unsupported focused selector with a module-wide, profile-wide,
  repository-wide, runtime-wide, or mutation-wide scan.

## Workflow

1. Resolve the exact profile, canonical local code root, optional project, declared routes and local
   artifacts, and prohibited effects. For `commit` or `pull_request`, require immutable lowercase
   base and head object IDs and the exact changed-path set.
2. Call `application_context`, inspect its provenance and gaps, then call `plan_appsec_workflow`
   with the same context inputs. Reject an identity mismatch and do not execute a named step that is
   blocked or unsupported.
3. For each ready `security_change_review` step in `commit`, `pull_request`, `staging`, `release`,
   or `deep`, invoke `$codex-security:security-diff-scan` against exactly that Git change set. Label
   every result as host semantic analysis and preserve its scan identity when available.
4. For a ready `security_repository_review` step in `release` or `deep`, invoke
   `$codex-security:security-scan` for the canonical code root. This is a broad repository review,
   not proof about a runtime deployment.
5. For a ready `deep_security_repository_review` step in `deep`, invoke
   `$codex-security:deep-security-scan`. Do not use the deep skill for a commit or pull-request
   change set.
6. Execute ready ScorchKit-engine steps only when the user's request includes execution. Use
   `scan_code` with `standard` for `fast_application_scan` and `thorough` for
   `deep_application_scan`; preserve the returned module outcomes and coverage gaps.
7. For each `application_dast` step, require the exact project-registered target from the context,
   select the least-powerful approved DAST phase profile, and call `application_dast`. A registered
   target is still not an authorization grant.
8. For each `artifact_supply_chain_scan` step, call `supply_chain_cache_status` and then
   `supply_chain_scan` for the exact declared local artifact. Do not refresh provider data unless
   the user separately requests and supplies the reviewed digest-pinned refresh inputs.
9. Call `correlate_findings` only for a ready `correlate_project_evidence` step with the exact
   selected project. Preserve attack-path gaps and focused selections as derived ScorchKit data.
10. For `focused_verification`, execute only an exact ready selector supported by the returned plan.
    If any selector is blocked or unsupported, report it and stop. A broader fallback requires a
    separately requested profile and a new plan.
11. Return one result organized into context identity, workflow identity, host semantic analysis,
    ScorchKit scanner evidence, step execution identities, blocked or unsupported work, coverage
    gaps, policy denials, and recommended next explicit choice. Never call a finding-status tool.

Commit and pull-request review is never repository assurance. Staging and release runtime results
are never source completeness. Deep review is explicit broad work and never an automatic response
to a source mutation or repair.
