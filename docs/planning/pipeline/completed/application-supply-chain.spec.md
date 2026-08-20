---
title: Application supply-chain SBOM and vulnerability evidence
pipeline_id: 9320d21f-3214-43f2-a5e1-89058c58a2a2
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-012
ticket_doc: docs/planning/tickets/closed/TICKET-012-application-supply-chain.md
aar: docs/planning/knowledge/aar/AAR-012-application-supply-chain.md
created: 2026-08-20
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-012
---

# Application supply-chain SBOM and vulnerability evidence — spec

## Intent

Deliver reproducible source-dependency and built-artifact vulnerability evidence from an explicitly
authorized local target. Produce one versioned SBOM, consume it offline, preserve exact package and
provider provenance, expose incomplete coverage across every public projection, and keep Codex as a
preferred host rather than an engine dependency.

## Scope

- In: the complete TICKET-012 scope and public surfaces listed in the linked ticket.
- Out: remote registry/daemon effects, target build/package-manager execution, host inventory,
  cloud-account posture, general Trivy scanning, release signing, remote MCP, and full mutation.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an application source tree, archive, OCI layout, directory artifact, or existing SBOM is selected, ScorchKit shall canonicalize and authorize that exact local target before traversal or subprocess creation and shall not reinterpret it as a registry or daemon target. | Denial-before-execution, symlink/canonical-path, explicit source-scheme, and no-registry fixtures. |
| REQ-002 | When Syft is applicable, ScorchKit shall generate one bounded CycloneDX 1.6 JSON SBOM, validate it with embedded local-only schemas, record its SHA-256 and scanner version, and preserve the exact document used downstream. | Recording-executor invocation, schema, digest, size-limit, and artifact-lifetime tests. |
| REQ-003 | When supported lockfiles are present, ScorchKit shall run OSV in offline source mode on only those lockfiles, accept exactly documented result exits, and report source-dependency coverage separately from artifact coverage. | Multi-ecosystem, empty, finding, wrong-exit, no-package, malformed, and network-negative fixtures. |
| REQ-004 | When Grype or Trivy analyzes an application, ScorchKit shall provide the exact validated Syft SBOM rather than recataloging the target and shall preserve PURL, installed/fixed version, advisory aliases, data source, and tool/database provenance. | Exact-SBOM handoff plus Grype and Trivy golden-parser tests. |
| REQ-005 | When multiple tools report the same component vulnerability, ScorchKit shall correlate by target revision, normalized PURL, and advisory alias set while retaining each tool-specific observation and raw bounded evidence. | Cross-tool alias/PURL correlation and non-collision fixtures. |
| REQ-006 | When a required tool, SBOM producer, consumer, provider database, or parser is missing, stale, invalid, or failed, ScorchKit shall expose an exact typed coverage gap and shall not present the assessment as complete or clean. | CLI, MCP, SARIF, report, storage, and compatibility projection tests. |
| REQ-007 | When provider data is refreshed, ScorchKit shall authorize the provider and cache path separately, stream within a hard limit, verify digest and schema, stage on the cache filesystem, and atomically promote only a valid snapshot while retaining the prior snapshot on failure. | Authorized loopback server, redirect/DNS denial, oversize, digest mismatch, invalid archive, interrupted import, and atomic-promotion tests. |
| REQ-008 | When a supply-chain scan runs, external tools shall use owned config/home/cache/temp state, a clean environment, exact executable and exit policies, bounded time/output/artifacts, and no implicit update, telemetry, registry, daemon, credential, or project-config behavior. | Complete recording-executor contracts and hostile target-config fixtures. |
| REQ-009 | When profiles select supply-chain work, quick shall run source dependency coverage, standard shall add Syft and Grype, thorough and pentest shall add Trivy, and explicit local artifact scanning shall be available through agent-neutral facade, CLI, and MCP contracts. | Exact profile/capability/effect matrices across every public entry point. |
| REQ-010 | When TICKET-012 is delivered, its tool versions, checksums, cache layout, operator workflow, and unsupported remote-registry boundary shall be documented, and validation shall not run a repository-wide mutation campaign. | Doctor/tool-provenance tests, documentation inspection, focused development checks, and repository delivery evidence. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Keep scan-time execution offline and make provider refresh a separate operation. | Scanner defaults otherwise create hidden provider, registry, telemetry, and credential effects. |
| 2 | Generate CycloneDX 1.6 once with Syft and hand the exact verified document to consumers. | One producer identity prevents recataloging drift and enables defensible correlation. |
| 3 | Keep OSV source-lockfile coverage separate from Grype/Trivy artifact coverage. | Declared and shipped dependencies answer different security questions. |
| 4 | Add exact accepted exit codes to the shared invocation contract. | OSV uses 0/1 for clean/findings; accepting every nonzero status hides fatal failures. |
| 5 | Add a supply-chain service with explicit producer/consumer phases outside the unordered code-module batch. | Consumers cannot run before the SBOM exists, and a string-valued shared map is not a security boundary. |
| 6 | Use embedded CycloneDX 1.6/SPDX/JSF schemas with local-only resolution. | Schema validation must not become a network or filesystem retrieval effect. |
| 7 | Preserve typed cache state and atomically promote only verified same-filesystem snapshots. | Missing, stale, corrupt, or partially downloaded data must remain observable and never replace the last valid snapshot. |
| 8 | Support only explicit local target schemes in this ticket. | Unqualified image names can reach daemons, registries, and inherited credentials. |
| 9 | Normalize supplied PURLs but never fabricate absent identity. | Invented identifiers create false cross-tool correlation. |
| 10 | Use focused development and delivery validation; never launch a repository-wide mutation scan. | The owner explicitly prohibited repeat broad mutation work; SK-047 owns the scheduled full inventory. |
| 11 | Treat the owner's 2026-08-20 direction as standing authorization for local ticket commits after the delivery gate. | This removes a workflow pause without broadening authority to pushes, PRs, or external scans. |
| 12 | Repair and recheck only the 211 missed mutations in 68 mutated functions across 14 files from the one completed 570-mutation DIFF inventory. | The owner explicitly prohibited repeating broad mutation runs and authorized rechecking only repaired survivors; the 291 caught, 3 timed-out/caught, and 65 unviable outcomes remain sealed baseline evidence. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-012-application-supply-chain.md`
- AAR: `docs/planning/knowledge/aar/AAR-012-application-supply-chain.md`
- Architecture:
  `docs/architecture/application-supply-chain.md`,
  `docs/architecture/application-security-evidence.md`, `docs/architecture/runner.md`,
  `docs/architecture/tools.md`, `docs/architecture/config.md`

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
