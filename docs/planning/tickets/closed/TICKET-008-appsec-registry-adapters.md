---
title: TICKET-008-appsec-registry-adapters
status: done
ticket_number: 008
type: refactor
created: 2026-08-17
closed: 2026-08-17
intake:
pipeline_spec: docs/planning/pipeline/completed/appsec-registry-adapters.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-008
---

# Application-security registry and scanner adapter foundation

## Summary

Refocus ScorchKit's production-facing registry on application security and replace the current flat
scanner catalog with a versioned adapter foundation. Codex-facing defaults will expose tools that
inspect application source, dependencies, deployment artifacts, web/API behavior, or application
attack paths. Existing network, enterprise, and cloud-posture adapters remain available only
through an explicit compatibility surface during this refactor.

## Why

ScorchKit already contains more than one hundred modules, but many are unrelated to securing an
application codebase and the external-tool wrappers duplicate invocation, parsing, provenance, and
finding-mapping behavior. Adding deeper SAST and DAST integrations before establishing a narrow
catalog and common adapter contract would multiply that duplication and give Codex an ambiguous
tool-selection surface.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a caller requests the default security catalog, ScorchKit shall return only modules classified as application source, application dependency, application artifact, application runtime, or application attack-path capabilities. | Exact registry and public CLI/MCP catalog tests. |
| REQ-002 | When a caller explicitly requests the compatibility catalog, ScorchKit shall preserve access to existing non-application adapters without allowing them into an implicit application profile. | Compatibility registry census and profile-selection tests. |
| REQ-003 | When an external scanner is registered, ScorchKit shall expose one versioned descriptor containing its target kinds, lifecycle stage, strongest effect class, output contract, provenance strategy, and application-security classification. | Descriptor schema tests and exhaustive registry validation. |
| REQ-004 | When an adapter constructs a tool invocation, ScorchKit shall use the shared bounded invocation contract for executable identity, arguments, timeout, output limits, environment, and temporary artifacts. | Executor fixture tests across representative DAST and SAST adapters. |
| REQ-005 | When a migrated adapter uses the v1 parser contract, ScorchKit shall distinguish no findings, parse failure, execution failure, and successful findings; Nuclei and Semgrep shall prove the contract in this ticket. | Parser contract and asymmetric Nuclei/Semgrep fixture tests. |
| REQ-006 | When CLI, MCP, agent, or report code consumes scanner metadata, ScorchKit shall derive it from the canonical adapter descriptor rather than a second scanner inventory. | Exact cross-surface inventory tests. |
| REQ-007 | When an unknown or incompatible profile requests a module, ScorchKit shall fail closed before creating a process or network effect. | Negative profile and executor non-invocation tests. |
| REQ-008 | When the refactor is delivered, ScorchKit shall preserve existing explicit module identifiers and serialized findings unless a separately versioned contract states otherwise. | Compatibility fixtures, public example builds, and DIFF gate. |

## Scope

- In: application-security taxonomy; default and compatibility registries; versioned adapter
  descriptors; shared invocation, parser-result, evidence, and temporary-artifact seams; CLI, MCP,
  agent, and documentation alignment; behavior-preserving migration of representative adapters.
- Out: new scanner binaries; evidence-schema v2; authenticated ZAP; Nuclei template governance;
  CodeQL, Psalm, or Syft support; removal of compatibility adapters; remote MCP; webhooks; cloud
  provider restoration; application exploitation.

## Locked decisions

- ScorchKit remains agent-neutral and Codex remains the preferred host.
- The core product is application SAST, SCA, secrets, artifact security, DAST, and code-informed
  application testing—not general network, cloud-account, or enterprise post-exploitation.
- This ticket quarantines rather than deletes existing out-of-bound adapters.
- Behavior-preserving extraction precedes scanner behavior changes.
- Scanner evidence remains distinct from agent-generated interpretation.
- Parser migration is incremental: this ticket owns the shared v1 outcome plus Nuclei and Semgrep;
  later adapter work must migrate to that contract rather than invent another result type.
- Mutation execution is limited to the functions repaired during inspection. The broad inventory is
  deferred under the owner's standing direction not to repeat broad mutation campaigns.

## Recon

- The production registries currently expose 91 DAST/recon modules, 22 SAST modules, four registered
  infrastructure modules, and five cloud tool adapters.
- Semgrep, Gitleaks, OSV-Scanner, Grype, PHPStan, Trivy, ZAP, and Nuclei are already present.
- ZAP currently uses one `zap-cli quick-scan`; Nuclei uses a default JSONL invocation; Semgrep uses
  `--config auto`. Their deeper behavior belongs to later tickets after this adapter foundation.
- The current `Finding` and `HttpEvidence` types cannot represent full source-flow and runtime proof;
  the queued evidence-v2 intake owns that change.
- Relevant prior work: WORK-085, WORK-087, WORK-093, WORK-096, WORK-116, and TICKET-007.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/appsec-registry-adapters.spec.md`
- Backlog: fourteen candidate intakes under `docs/planning/intake/`.

## Log

- 2026-08-17: opened.
- 2026-08-17: scoped as the first application-security roadmap ticket; no implementation or phase
  transition authorized yet.
- 2026-08-17: owner authorized completing the active ticket within its existing scope.
- 2026-08-17: Design reconnaissance narrowed parser migration to the new shared contract plus Nuclei
  and Semgrep so catalog enforcement is not combined with a 67-adapter behavior rewrite.
- 2026-08-17: the DIFF gate passed all non-mutation lanes and failed mutation preflight before
  cargo-mutants ran because the two-worker scratch floor exceeded available local space. Per the
  owner's earlier direction, validation is narrowed to 76 mutations in the 23 inspection-repaired
  functions; a broad campaign remains scheduled for later.
- 2026-08-17: focused evidence caught all 48 viable mutations with 28 unviable and no misses or
  timeouts. The focused-repair gate passed 19 applicable lanes with no failures, three named
  web-only skips, 79.11% line coverage, and 1,469 strict Nextest cases.
