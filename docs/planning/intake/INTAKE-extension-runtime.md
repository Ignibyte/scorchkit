---
title: INTAKE-extension-runtime
status: candidate
created: 2026-08-21
ticket:
pipeline_spec:
---

# Capability-declared extension runtime and SDK

## Problem or opportunity

ScorchKit supports public Rust module traits and explicit family registration, but third-party
modules still require compilation into the process. A general extension surface needs versioned
schemas, effect declarations, isolation, provenance, and conformance without giving untrusted code
the policy engine's memory or ambient host access.

## Proposed outcome

First-party compiled modules and isolated third-party application-security modules share one
descriptor and evidence contract. Third-party extensions execute through a bounded out-of-process
protocol, and every requested effect passes through ScorchKit policy and audit enforcement.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an extension is registered, ScorchKit shall require a versioned manifest naming its identity, digest, runtime, input/output schemas, strongest effect, capabilities, resource budgets, and compatibility range. | Manifest schema, malformed-input, and compatibility tests. |
| REQ-002 | When an extension requests an undeclared or unauthorized network, filesystem, credential, or subprocess effect, ScorchKit shall deny the request before the effect begins and shall emit an audit decision. | Capability/effect denial matrix and no-side-effect fixtures. |
| REQ-003 | When a third-party extension runs, ScorchKit shall execute it outside the engine process with bounded time, memory, output, owned temporary artifacts, cancellation, and descendant cleanup. | Process isolation, overflow, timeout, cancellation, and cleanup tests. |
| REQ-004 | When an extension produces observations, findings, or evidence, ScorchKit shall attach the extension identity, version, digest, invocation identity, parser outcome, and source artifacts without allowing the extension to claim trusted engine provenance. | Provenance and spoofing fixtures across reports, MCP, API, and storage. |
| REQ-005 | When a first-party module and third-party extension implement the same application-security category, ScorchKit shall expose them through the same provider-neutral catalog and policy contract while retaining their distinct trust and runtime labels. | Catalog, selection, and descriptor parity tests. |
| REQ-006 | When a third-party extension returns output, ScorchKit shall validate and persist that output through engine-owned repositories and shall not give the extension a database connection, canonical storage path, or direct finding-state mutation handle. | Hostile-extension, storage-access, malformed-output, and transaction tests. |

## Scope notes

- In: manifest, SDK, out-of-process protocol, capability broker, resource ownership, engine-owned
  output persistence, conformance harness, first-party descriptor parity.
- Out: in-process third-party native libraries, arbitrary ambient plugin discovery, extension
  marketplace distribution, or restoration of general network/cloud posture to default profiles.
