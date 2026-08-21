---
title: TICKET-015-source-runtime-correlation
status: done
ticket_number: 015
type: feature
created: 2026-08-21
closed: 2026-08-21
intake: docs/planning/intake/INTAKE-source-runtime-correlation.md
pipeline_spec: docs/planning/pipeline/completed/source-runtime-correlation.spec.md
focused_repair: approved
---

# Source-to-runtime attack-path correlation and focused verification

## Summary

Add a provider-neutral, versioned attack-path model that correlates immutable source and runtime
observations through typed identities, preserves evidence lineage and verification history, derives
inert focused verification selections, and exposes the same result through storage, MCP, and reports.

## Why

ScorchKit now has deep source flows, schema-aware DAST, trusted Nuclei probes, typed coverage, and
durable finding-v2 evidence. Its two legacy correlators still use module names and title substrings,
cannot prove that findings describe the same application surface, and use language such as
"confirmed" without a versioned proof or coverage contract. SK-040 converts those separate signals
into a defensible bridge for the application-only pentest work in SK-041.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When source and runtime observations share a normalized route, parameter, component, application, deployment, or weakness identity, ScorchKit shall produce a deterministic correlation candidate without modifying either finding or its scanner confidence. | Cross-product facet matrix, ordering, identity, and input-nonmutation tests. |
| REQ-002 | When a runtime observation claims to reproduce a static hypothesis, ScorchKit shall require source-flow evidence, redacted HTTP proof, a matching weakness plus precise application facet, and compatible revision/deployment provenance before assigning the reproduced state. | Positive and one-missing-condition table tests plus a loopback-style fixture. |
| REQ-003 | When verification does not reproduce a path, ScorchKit shall preserve the attempted conditions and shall move a reproduced path to mitigated only when comparable coverage is complete. | Complete, incomplete, failed, stale, and duplicate-attempt state-machine tests. |
| REQ-004 | When a mitigated path is reproduced by later comparable evidence, ScorchKit shall append a regressed transition without replacing earlier evidence or scanner confidence. | Ordered transition and serialization round trips. |
| REQ-005 | When a path has source and runtime provenance, ScorchKit shall derive the smallest deterministic set of exact rule, template, request, and test selectors needed for focused verification, without executing it or carrying credential values. | Selection-minimization, redaction, stable-identity, and empty-selector tests. |
| REQ-006 | When attack paths are stored or returned through MCP and reports, ScorchKit shall preserve schema, identity, state, facets, finding/evidence references, coverage gaps, transitions, and focused selection with the same ordering. | PostgreSQL migration/round trip, MCP contract, JSON/text/Mermaid report tests. |
| REQ-007 | When legacy heuristic chains are shown for compatibility, ScorchKit shall label them separately and shall not allow their title/module matches or agent analysis to promote canonical attack-path state. | Compatibility and hostile-title/agent-analysis negatives. |
| REQ-008 | When TICKET-015 is validated, ScorchKit shall mutate only functions changed or repaired by this ticket and shall not launch a repository-wide mutation scan. | Sealed focused evidence and exact-tree focused-repair receipt. |

## Scope

- In: typed correlation facets, deterministic path identity, proof/state model, comparable coverage,
  append-only transitions, focused selectors, PostgreSQL storage, MCP output, reports, and
  compatibility labeling.
- Out: automatic exploitation, automatic verification execution, agent claims as scanner proof,
  mutation of original findings/confidence, cross-project correlation, credential values, broad
  network/cloud chains, and repository-wide mutation testing.

## Locked decisions

- Canonical path state comes only from typed scanner evidence and coverage; agent analysis is
  interpretation only.
- Weakness-only matches remain suspected. Reproduced requires a precise shared application facet,
  source flow, HTTP proof, and comparable deployment/revision identity.
- A negative result is not mitigation unless coverage is complete and comparable to the prior
  reproduced proof.
- Focused selections are inert data. TICKET-015 never executes a probe or test from correlation.
- The provider-neutral core owns contracts and state transitions; MCP, storage, and reports are
  adapters.
- Legacy title/module heuristics remain compatibility output only and are explicitly unverified.
- Validation uses owner-approved focused mutation repair only.

## Recon

- `crates/scorchkit-core/src/correlation.rs` contains 14 title/module heuristic rules with no stable
  chain identity, finding/evidence IDs, coverage, or state history.
- `src/mcp/prompts.rs` contains a second six-rule heuristic engine; `correlate_findings` reduces each
  durable finding to ID, module, title, and severity before invoking it.
- Finding v2 already preserves typed source/runtime/package/artifact locations, source-to-sink
  flows, scanner provenance, explicit correlation keys, HTTP/structured evidence, and separate
  agent analysis.
- PostgreSQL stores lossless `raw_finding` JSON and append-preserved evidence, but has no attack-path
  or path-transition table.
- ZAP and trusted Nuclei already produce bounded runtime locations and HTTP evidence; Semgrep,
  CodeQL, and Psalm produce source paths and code flows. The missing layer is correlation and
  comparable verification, not another scanner.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/source-runtime-correlation.spec.md`

## Log

- 2026-08-21: opened.
- 2026-08-21: promoted from `INTAKE-source-runtime-correlation`; plan locks canonical state to typed
  evidence, keeps legacy heuristics explicitly unverified, and retains the owner's no-broad-mutation
  constraint.
- 2026-08-21: implemented the provider-neutral path/state/selection contract, identity-locked
  PostgreSQL history, canonical MCP projection, and JSON/text/Mermaid reports. Focused development
  tests and strict all-feature Clippy are green; adversarial inspection and delivery validation
  remain.
- 2026-08-21: completed adversarial inspection with 15 repaired findings. Focused mutation evidence
  verifies 216/216 viable mutations caught at 100% MSI, and the focused-repair gate passed all 19
  applicable lanes with no failures. Pipeline completion and post-archive delivery proof remain.
