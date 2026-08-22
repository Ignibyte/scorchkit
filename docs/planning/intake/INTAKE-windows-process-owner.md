---
title: INTAKE-windows-process-owner
status: candidate
created: 2026-08-17
ticket: TICKET-023
pipeline_spec: docs/planning/pipeline/active/windows-process-owner.spec.md
---

# Windows Job Object process ownership

## Problem or opportunity

ScorchKit supports Linux and macOS because its Unix process-group owner can terminate scanner child
trees. Windows builds remain unsupported until equivalent descendant ownership and cleanup exist.

## Proposed outcome

Windows will use a Job Object backend with the same bounded success, timeout, cancellation,
output-limit, failure, and owner-drop guarantees as Unix process execution.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When ScorchKit launches an external tool on Windows, it shall assign the process and descendants to an owned Job Object before returning control to the adapter. | Windows process-tree integration tests. |
| REQ-002 | When execution succeeds, times out, is cancelled, exceeds output limits, errors, or loses its owner, ScorchKit shall release or terminate every owned descendant within the documented bound. | Windows CI lifecycle matrix. |
| REQ-003 | When Job Object ownership cannot be established, ScorchKit shall fail before scanner work continues. | Forced ownership-failure test. |
| REQ-004 | When Windows support is enabled, public behavior and serialized process results shall remain compatible with Unix hosts. | Cross-platform contract fixtures. |

## Scope notes

- In: Windows process owner, platform abstraction, Windows CI, descendant cleanup.
- Out: Windows-specific scanners or UI, weaker cleanup semantics.
