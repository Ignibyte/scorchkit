---
title: TICKET-014-trusted-nuclei
status: done
ticket_number: 014
type: feature
created: 2026-08-20
closed: 2026-08-21
intake: docs/planning/intake/INTAKE-trusted-nuclei.md
pipeline_spec: docs/planning/pipeline/completed/trusted-nuclei.spec.md
focused_repair: approved
---

# Trusted Nuclei templates and application-specific runtime probes

## Summary

Replace the ambient Nuclei wrapper with an approved local collection resolver that verifies exact
template bytes, signer identity, application-only protocols, effect declarations, engagement grants,
and result provenance before and after isolated execution.

## Why

The current wrapper runs Nuclei without naming templates. Nuclei therefore selects its mutable local
community collection and may update it automatically, while ScorchKit records no collection identity
and authorizes only a generic intrusive tool effect. This is neither reproducible nor safe for
unattended Codex selection. TICKET-013 established the application DAST execution and evidence
contracts that this adapter can now use.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a Nuclei profile resolves templates, ScorchKit shall select one explicit versioned local manifest, verify its schema, and compute a deterministic collection identity from the ordered approved inventory. | Manifest fixtures prove ordering, duplicate rejection, bounded counts, and reproducible identities. |
| REQ-002 | Before Nuclei is started, ScorchKit shall read each approved template through a bounded regular-file path, reject escapes or substitutions, verify its exact digest and declared template ID, and require a trusted native Nuclei signature whose signer identity matches the manifest. | Tamper, symlink, digest, ID, unsigned, wrong-signer, and executor non-invocation tests. |
| REQ-003 | When an inventory describes a Nuclei protocol or behavior, ScorchKit shall derive its minimum effect and resource requirements, reject an understated declaration, and deny every protocol outside the application HTTP allowlist before execution. | Exhaustive protocol and behavior classification table tests. |
| REQ-004 | When an approved application template is selected, ScorchKit shall require exact DAST, external-tool, credential-use when applicable, and strongest-effect grants for the canonical target before creating a workspace or subprocess. | Denial-before-effects and exact-grant acceptance tests. |
| REQ-005 | When Nuclei runs, ScorchKit shall pass only explicit verified template paths and bounded settings through a private workspace and clean environment while disabling updates, remote interactions, redirects, ambient configuration, and unsigned templates. | Invocation and loopback integration tests. |
| REQ-006 | When a template result is parsed, ScorchKit shall preserve verified collection, template, signer, matcher, target, evidence, redaction, tool version, and coverage state. | Parser and public-projection round trips. |
| REQ-007 | When an agent proposes an application-specific template, ScorchKit shall keep it non-executable until exact signed bytes and review metadata appear in the trusted inventory. | Proposal and promotion fixtures. |
| REQ-008 | When TICKET-014 is validated, ScorchKit shall use focused mutation evidence for changed functions and shall not launch a repository-wide mutation scan. | Sealed focused evidence and exact-tree gate receipt. |

## Scope

- In: trusted local inventory, native signatures, protocol/effect classification, proposal state,
  isolated execution, provenance, public projections, documentation, and build-host installation.
- Out: ambient collections, automatic updates, remote templates, AI templates, workflows,
  non-application protocols, signing private keys, public-target scans, and broad mutation scans.

## Locked decisions

- The manifest, not Nuclei's installed directory, owns selection.
- Exact digest and trusted native signature are both mandatory.
- Runtime support is HTTP-only; all other protocols fail closed after classification.
- Proposals cannot authorize or sign themselves.
- TICKET-014 uses focused mutation verification only.

## Recon

- `src/tools/nuclei.rs` currently invokes Nuclei without `-t`, `-duc`, `-dut`, `-ni`, or an isolated home/config.
- Nuclei's official runtime documentation says default execution selects most installed community templates and automatically checks for template updates; it also exposes explicit local template selection, update-disable, unsigned-template-disable, and interaction-disable flags.
- Official Nuclei flags identify code, JavaScript, file, headless, TCP, workflow, SSL, WebSocket, WHOIS, and DAST/fuzz behaviors that cannot share one generic effect declaration.
- The build host currently has no `nuclei` binary, so design must include a pinned, checksum-verified installation and version contract before live loopback validation.
- Existing `ScanContext::require_tool_authorization` borrows the scan's broad DAST effect for Nuclei; TICKET-014 needs descriptor-specific exact authorization before workspace or process creation.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/trusted-nuclei.spec.md`
- Design: `docs/architecture/trusted-nuclei.md`

## Log

- 2026-08-20: opened.
- 2026-08-20: promoted from `INTAKE-trusted-nuclei`; plan locked to application HTTP templates and focused mutation validation.
- 2026-08-20: design fixed the manifest schema, two-stage signature proof, concrete-address network boundary, typed adapter assessment, and file/test manifest.
- 2026-08-20: implementation replaced ambient execution, installed and checksum-verified Nuclei
  3.11.1 on the build drive, and passed focused unit plus real signed loopback integration tests.
- 2026-08-20: adversarial inspection closed path-replacement, cumulative-resource,
  resolved-address ordering, incomplete-status projection, invocation-drift, and evidence-parity
  gaps; strict all-feature Clippy and focused repair tests are green.
- 2026-08-20: the owner-approved mutation scope is limited to 84 candidates in the 14 functions
  repaired during inspection; repository-wide and whole-ticket mutation inventories remain
  deferred.
- 2026-08-21: focused repair caught the remaining exact 128-byte identity-boundary mutation; the
  sealed current-tree evidence is 1/1 viable caught, and the pre-completion focused-repair gate
  passed 19 applicable lanes with zero failures and three named web-only skips.
- 2026-08-21: documentation, AAR, and roadmap closure are complete; SK-040 source/runtime
  correlation is the next product ticket.
