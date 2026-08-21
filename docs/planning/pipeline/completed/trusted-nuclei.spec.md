---
title: Trusted Nuclei templates and application-specific runtime probes
pipeline_id: 81cd1faf-62db-4af7-8f46-16eab2662845
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-014
ticket_doc: docs/planning/tickets/closed/TICKET-014-trusted-nuclei.md
aar: docs/planning/knowledge/aar/AAR-014-trusted-nuclei.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-014
created: 2026-08-20
---

# Trusted Nuclei templates and application-specific runtime probes — spec

## Intent

Replace Nuclei's ambient community-template execution with an application-only, reproducible trust
boundary. ScorchKit will resolve one versioned local collection, verify every approved template's
exact bytes and trusted signer before process creation, classify its strongest effect, require exact
engagement grants, and preserve template and collection provenance in every result. Repository-owned
application probes may be proposed by any agent, but remain non-executable until an external review
and signing step promotes them into an approved inventory.

## Scope

- In: versioned collection manifests; bounded template parsing; exact file, collection, and signer
  identities; application-protocol and effect classification; approval-state enforcement; isolated
  Nuclei execution; result, coverage, audit, CLI, MCP, report, and storage provenance; local proposal
  conventions; a pinned supported Nuclei release on the build host; focused validation of changed
  functions only.
- Out: ambient or auto-updated community collections; remote template URLs; Nuclei AI generation;
  arbitrary workflows; unsigned templates; code, JavaScript, file, DNS, raw network, WebSocket,
  WHOIS, or self-contained execution; broad internet discovery; automatic access to a signing key;
  a repository-wide mutation rerun.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a Nuclei profile resolves templates, ScorchKit shall select one explicit versioned local manifest, verify its schema, and compute a deterministic collection identity from the ordered approved inventory. | Manifest fixtures prove ordering, duplicate rejection, bounded counts, and reproducible identities. |
| REQ-002 | Before Nuclei is started, ScorchKit shall read each approved template through a bounded regular-file path, reject escapes or substitutions, verify its exact digest and declared template ID, and require a trusted native Nuclei signature whose signer identity matches the manifest. | Tamper, symlink, digest, ID, unsigned, wrong-signer, and executor non-invocation tests. |
| REQ-003 | When an inventory describes a Nuclei protocol or behavior, ScorchKit shall derive its minimum effect and resource requirements, reject an understated declaration, and deny every protocol outside the application HTTP allowlist before execution. | Exhaustive protocol and behavior classification table tests, including headless, file, network, code, JavaScript, workflow, unsafe HTTP, payload, and fuzzing fixtures. |
| REQ-004 | When an approved application template is selected, ScorchKit shall require exact DAST, external-tool, credential-use when applicable, and strongest-effect grants for the canonical target before creating a workspace or subprocess. | Two-arm authorization tests prove denial before artifacts or execution and acceptance with exact grants. |
| REQ-005 | When Nuclei runs, ScorchKit shall pass only explicit verified template paths and bounded settings through a private workspace and clean environment while disabling updates, remote interactions, redirects, ambient configuration, and unsigned templates. | Invocation golden tests and one loopback integration assert exact arguments, environment, ownership, limits, and cleanup. |
| REQ-006 | When a template result is parsed, ScorchKit shall preserve the verified collection, template, signer, matcher, target, request evidence, redaction state, tool version, and execution coverage without converting malformed or failed output into a clean scan. | JSONL, redaction, provenance, malformed-output, empty-output, report, SARIF, MCP, and storage round-trip tests. |
| REQ-007 | When an agent proposes an application-specific template, ScorchKit shall keep it in a non-executable proposal state and shall recognize it as approved only after its exact signed bytes and review metadata appear in the trusted inventory. | Proposal-state, unsigned, changed-after-review, promotion, and no-runtime-private-key tests. |
| REQ-008 | When the trusted Nuclei adapter is delivered, ScorchKit shall document the supported trust ceremony and shall verify only changed functions with focused mutation evidence rather than launching a repository-wide mutation scan. | Operator guide, architecture review, sealed focused outcomes, focused-repair gate, and exact-tree receipt. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | An explicit ScorchKit collection manifest is the only runtime template selector. | Nuclei otherwise executes most installed community templates and may update them at process start. |
| 2 | Trust requires both an exact whole-file digest and Nuclei-native signature verification against a pinned signer identity. | The digest makes the inventory reproducible; the signature proves review provenance independently. |
| 3 | The first trusted runtime accepts application HTTP templates only; every other protocol is classified and denied. | Code and JavaScript can execute on the host, file templates read local state, and network-oriented protocols exceed this application's DAST boundary. |
| 4 | Agent-created templates begin as proposals and the runtime never receives a signing private key. | Proposal generation is not approval, and an unattended agent must not promote its own executable probe. |
| 5 | The invocation disables template updates, remote interactions, redirects, ambient configuration, remote URLs, AI generation, and unsigned templates. | Exact local inputs and network behavior must remain reviewable and repeatable. |
| 6 | Nuclei runs in a private owned workspace with clean environment, output limits, rate limits, timeouts, and whole-process cancellation. | Templates and external tools are untrusted effectful inputs even after approval. |
| 7 | Validation will mutate only functions changed or repaired by TICKET-014. | The owner explicitly prohibited repeated repository-wide mutation scans. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-014-trusted-nuclei.md`
- AAR: `docs/planning/knowledge/aar/AAR-014-trusted-nuclei.md`
- Architecture: `docs/architecture/tools.md`, `docs/architecture/application-dast.md`, and a new
  `docs/architecture/trusted-nuclei.md`

## Phase plan

| Phase | Deliverable | Exit evidence |
|---|---|---|
| 1 Plan | ticket, AAR, spec, notes, recalled knowledge | operator confirmation |
| 2 Design | architecture, file manifest, regression plan | operator confirmation |
| 3 Implement | code per design | self-review |
| 3.5 Inspect | adversarial ledger with dispositions | lead review |
| 4 Validate | tests run and delivery gate green | matching receipt |
| 5 Complete | docs, submitted AAR, archive, closed ticket | archive complete |
| Delivery | gate rerun after archive, commit/PR | matching receipt |
