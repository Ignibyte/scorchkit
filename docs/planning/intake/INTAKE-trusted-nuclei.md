---
title: INTAKE-trusted-nuclei
status: promoted
created: 2026-08-17
ticket: docs/planning/tickets/closed/TICKET-014-trusted-nuclei.md
pipeline_spec: docs/planning/pipeline/completed/trusted-nuclei.spec.md
---

# Trusted Nuclei templates and application-specific runtime probes

## Problem or opportunity

The Nuclei wrapper does not pin its template collection, verify a ScorchKit trust policy, or expose
template effects before execution. This makes results hard to reproduce and makes custom templates
too powerful for unattended agent selection.

## Proposed outcome

Nuclei will run only an approved, versioned template set whose digest, signature trust, target kind,
and strongest effect are known before execution. Repository-owned application probes can be added
through reviewable signed templates.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a Nuclei profile resolves templates, ScorchKit shall select an exact approved template inventory and record its collection digest. | Inventory and reproducibility tests. |
| REQ-002 | When a template is unsigned, modified after approval, or signed by an untrusted identity, ScorchKit shall reject it before starting Nuclei. | Signature and tamper fixtures. |
| REQ-003 | When a template uses HTTP, headless, file, network, code, or other protocols, ScorchKit shall require the descriptor's strongest effect and resource grants before execution. | Exhaustive protocol/effect matrix tests. |
| REQ-004 | When Codex proposes an application-specific template, ScorchKit shall store it as an unapproved artifact until a trusted signing and review step completes. | Proposal, approval, and execution-state tests. |
| REQ-005 | When a template produces a result, ScorchKit shall preserve the exact template identity, matcher, extracted evidence, request target, and redaction status. | JSONL parser and evidence-v2 fixtures. |

## Scope notes

- In: template inventory, pinning, trust and signing, effect classification, repository-owned app
  probes, provenance.
- Out: arbitrary community template execution, unsigned agent-generated code templates, broad
  internet discovery.
