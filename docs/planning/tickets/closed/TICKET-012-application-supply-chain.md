---
title: TICKET-012-application-supply-chain
status: done
ticket_number: 012
type: feature
created: 2026-08-20
closed: 2026-08-20
intake: docs/planning/intake/INTAKE-application-supply-chain.md
pipeline_spec: docs/planning/pipeline/completed/application-supply-chain.spec.md
focused_repair: approved
---

# Application supply-chain SBOM and vulnerability evidence

## Summary

Ship an application-only supply-chain pipeline that distinguishes declared source dependencies from
built artifacts, produces one reusable CycloneDX 1.6 SBOM, consumes that exact document with
offline vulnerability scanners, preserves provider and package identity, and reports missing or
stale coverage as incomplete rather than clean.

## Why

SK-034 narrowed the scanner catalog, SK-035 established durable evidence, and SK-036 added deep
source analysis. The current OSV and Grype wrappers still use stale or permissive command contracts,
Trivy is registered against a web URL despite invoking filesystem analysis, and no Syft producer or
security-critical cache lifecycle exists. Source/runtime correlation cannot make defensible package
claims until source declarations, SBOM components, built artifacts, advisories, and provider
snapshots have separate typed identities.

## EARS Requirements

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

## Scope

- In: Syft; OSV source dependency analysis; Grype and Trivy SBOM analysis; explicit local source,
  archive, OCI-layout, directory artifact, and SBOM targets; CycloneDX 1.6; normalized PURL/digest
  identity; source/artifact separation; typed cache status and policy-owned provider refresh;
  producer/consumer orchestration; facade, CLI, MCP, reporting, storage, doctor, documentation, and
  Codex-host integration.
- Out: unqualified or remote image references; registry pulls; Docker/containerd/Podman sockets;
  target package-manager execution; target build commands; guided remediation; general host
  inventory; cloud-account posture; Trivy IaC/secret scanning; ScorchKit release signing; remote MCP;
  and a repository-wide mutation campaign.

## Locked decisions

- Scans are offline. Provider refresh is a separate authorized effect; external scanners never
  update databases or contact registries during analysis.
- Syft produces one CycloneDX 1.6 document. Grype and Trivy consume those exact verified bytes.
- OSV analyzes explicitly discovered lockfiles separately and accepts exactly exits 0 and 1.
- Local source/artifact targets reuse canonical code-path authorization. Remote registries require a
  future target/authentication design and are not representable in this ticket.
- Missing, stale, invalid, or failed applicable coverage produces a typed incomplete/degraded result,
  never a clean result.
- PURLs are normalized only when supplied and valid; ScorchKit never invents them.
- Cache refresh uses policy-owned bounded streaming, checksum verification, same-filesystem staging,
  validation, and atomic promotion while retaining the prior valid snapshot on failure.
- Use pinned official Syft 1.50.0, OSV-Scanner 2.3.8, Grype 0.116.1, and Trivy 0.74.0 binaries on the
  build host. Replace the mutable Docker-socket Trivy wrapper.
- The owner's standing direction authorizes local per-ticket commits after a green delivery receipt;
  it does not authorize pushes, pull requests, or remote target scans.
- The owner directed that broad mutation work not be repeated. The focused repair scope is the exact
  211 missed outcomes in 68 mutated functions across 14 files from the completed 570-mutation DIFF
  inventory; only those repaired survivors may be rechecked.

## Recon

- `CodeOrchestrator` has one unordered execution batch; supply-chain work needs an explicit producer
  barrier before SBOM consumers.
- `ToolInvocation` distinguishes strict from arbitrary nonzero exits but cannot yet express OSV's
  exact `{0,1}` contract.
- Existing OSV uses removed v1 syntax, existing Grype accepts arbitrary exits and malformed empty
  results, and the web-family Trivy wrapper passes a URL to `trivy fs`.
- `PolicyHttp` owns endpoint, DNS-answer, and redirect authorization but not bounded streaming.
- The existing CVE cache intentionally maps corruption and expiry to a silent miss; supply-chain
  coverage requires typed `Ready`, `Missing`, `Stale`, and `Invalid` snapshots instead.
- The build host's `/mnt/fast` and `/mnt/buildtmp` are on the same 1.9 TiB NVMe filesystem with about
  1.6 TiB available, allowing same-filesystem atomic cache promotion and isolated Cargo output.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/application-supply-chain.spec.md`

## Log

- 2026-08-20: opened.
- 2026-08-20: promoted from SK-037 after the owner committed TICKET-011 and directed continuous
  execution with standing authorization for green local per-ticket commits.
- 2026-08-20: implementation produced the ordered offline OSV → Syft/import → Grype/Trivy service,
  immutable provider snapshots, typed coverage, public CLI/MCP/facade surfaces, durable execution
  evidence, native pinned build-host tools, and operator/Codex documentation. Focused unit,
  integration, report, MCP, catalog, compile, and database round-trip checks are green; inspection
  and delivery gates remain.
- 2026-08-20: adversarial inspection closed cache-ancestor redirects, configured-age bypass,
  quick-artifact empty success, unbounded direct report files, cumulative refresh growth, weak
  Grype status validation, and missing effect audit events. Focused regressions and the all-feature
  workspace check are green. Validation and delivery gates remain.
