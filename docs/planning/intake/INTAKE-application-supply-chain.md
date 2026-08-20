---
title: INTAKE-application-supply-chain
status: candidate
created: 2026-08-17
ticket: docs/planning/tickets/open/TICKET-012-application-supply-chain.md
pipeline_spec: docs/planning/pipeline/active/application-supply-chain.spec.md
---

# Application dependency artifact and SBOM security pipeline

## Problem or opportunity

Repository dependency checks, image scans, and release SBOMs currently overlap without a clear
ownership model. ScorchKit lacks a Syft adapter and cannot consistently connect a vulnerable
package declaration to a built application artifact.

## Proposed outcome

ScorchKit will produce a reusable application SBOM, analyze declared dependencies and built
artifacts with deliberately assigned tools, and normalize package identity using PURLs, digests,
and artifact provenance.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an authorized source tree or application artifact is selected, ScorchKit shall generate a versioned SPDX or CycloneDX SBOM with Syft and record its digest. | Source, archive, and container fixture tests. |
| REQ-002 | When lockfiles are present, ScorchKit shall use OSV-backed dependency analysis without conflating it with built-artifact coverage. | Multi-ecosystem lockfile fixtures. |
| REQ-003 | When an SBOM or application artifact is analyzed, ScorchKit shall use Grype or Trivy according to the declared profile and preserve PURL, installed version, fixed version, and advisory provenance. | SBOM and image parser golden tests. |
| REQ-004 | When two tools report the same component vulnerability, ScorchKit shall correlate their observations while preserving tool-specific evidence. | Cross-tool deduplication fixtures. |
| REQ-005 | When vulnerability data or registry access is unavailable, ScorchKit shall report the exact coverage gap and shall not present stale or partial analysis as complete. | Offline, stale-cache, and denied-provider tests. |

## Scope notes

- In: Syft, OSV, Grype, Trivy, SPDX/CycloneDX, PURL and digest identity, source/artifact distinction,
  cache and provider policy.
- Out: general host inventory, cloud-account posture, ScorchKit's own release signing.
