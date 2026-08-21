---
title: TICKET-019-daybreak-codex-website
status: done
ticket_number: 019
type: docs
created: 2026-08-21
closed: 2026-08-21
intake:
pipeline_spec: docs/planning/pipeline/completed/daybreak-codex-website.spec.md
---

# Position the website around Codex and Daybreak Blue

## Summary

Make the ScorchKit website state the product boundary at first glance: ScorchKit is an
agent-neutral application-security engine, Codex is the preferred host, and approved users can pair
Codex with Daybreak Blue for defensive semantic review while ScorchKit retains authorization,
deterministic scanner execution, and evidence.

## Why

The rebuilt site already removed the old Claude-first presentation, but Codex and its optional
Daybreak model appear only in a small lower-page block. The current hierarchy undersells the
intended product: Codex reasons across ScorchKit's SAST, supply-chain, DAST, and application-pentest
evidence, and Daybreak Blue can strengthen that defensive reasoning when OpenAI has separately
approved and provisioned the user. The site must make that relationship prominent without implying
that ScorchKit bundles, grants, automatically selects, or receives scanner evidence from a model.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a visitor opens the home page, the site shall identify ScorchKit as agent-neutral, Codex-preferred, and able to work with Daybreak Blue for approved defensive users. | Content contract, rendered preview, and metadata inspection. |
| REQ-002 | When the Codex section is read, the site shall distinguish Codex orchestration, optional Daybreak Blue reasoning, and ScorchKit-owned authorization, execution, and evidence. | Content contract and rendered desktop/mobile inspection. |
| REQ-003 | When Daybreak availability is described, the site shall state that access is separately approved and provisioned and link to official OpenAI model and Trusted Access documentation. | Exact URL and qualification assertions in the website content check. |
| REQ-004 | When another agent host is considered, the public copy shall preserve agent neutrality and shall not present Claude Code or any vendor as owning ScorchKit's core workflow state or evidence. | Negative content search plus engine documentation review. |
| REQ-005 | When search or social metadata is rendered, the title and descriptions shall present Codex-preferred application security and optional Daybreak use without claiming automatic model selection. | Static metadata assertions. |
| REQ-006 | When the source is delivered, the exact website tree shall pass its content check, TypeScript check, production build, and local preview, and the engine tree shall pass the required repository gate. | Website scripts and ScorchKit DIFF receipt. |

## Scope

- In: `/Volumes/srv/stacks/scorchkit_home` hero, Codex/Daybreak section, navigation, metadata,
  source-backed content constants, contributor guidance, and a dependency-free public-copy check.
- In: ScorchKit public README, Codex plugin guide, workflow architecture, changelog, and pipeline
  evidence needed to source the website claims.
- Out: model provisioning, Codex account configuration, a core dependency on OpenAI, automatic model
  selection, scanner behavior, target access, hosted deployment, repository push, and a full or deep
  security scan.

## Locked decisions

- ScorchKit remains agent-neutral and Codex remains the preferred host.
- Daybreak Blue is optional host reasoning for separately approved users. It is not bundled access,
  authorization, a scanner, or ScorchKit evidence.
- Public model claims use official OpenAI documentation and do not promise availability on every
  identity, workspace, API project, or product surface.
- The website will explain the three boundaries visually and in plain text rather than adding a
  second execution path.
- Delivery remains source-only because no website hosting identity or deployment target is known.

## Recon

- Official OpenAI Docs identify Daybreak Blue as a frontier-model alias with safeguards calibrated
  for defensive cybersecurity and require separate approval and provisioning.
- TICKET-018 already rebuilt the site from Claude-first to agent-neutral and Codex-first; this ticket
  changes prominence and adds the missing Daybreak relationship instead of redesigning the site.
- The existing ScorchKit architecture already separates Codex Security host analysis from
  policy-gated scanner evidence, so the website can describe Daybreak without a core code change.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/daybreak-codex-website.spec.md`

## Log

- 2026-08-21: opened.
- 2026-08-21: owner directed a Codex-preferred, Daybreak-capable website position.
