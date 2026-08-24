---
title: TICKET-028-extension-runtime
status: done
ticket_number: 028
type: feature
created: 2026-08-23
closed: 2026-08-23
intake:
  docs/planning/intake/INTAKE-extension-runtime.md
pipeline_spec: docs/planning/pipeline/completed/extension-runtime.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-028
---

# Capability-declared extension runtime and SDK

## Summary

Add a versioned, provider-neutral extension contract and SDK for explicitly registered
application-security modules. Third-party code runs as digest-bound WebAssembly in a separate
owned worker process with no ambient WASI imports; all effects are requested through a bounded
engine broker, and all returned observations, findings, evidence, and artifacts are validated and
persisted by existing ScorchKit owners.

## Why

SK-049 established the one application-service boundary that future clients and runtimes consume.
SK-050 must establish extension identity, isolation, effect, provenance, and persistence contracts
before SK-051 adds lifecycle hooks or any later catalog distributes third-party modules. The
existing Rust traits and TOML command wrappers remain trusted configuration and cannot provide this
isolation boundary.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an extension is registered, ScorchKit shall require a versioned manifest naming its identity, exact module digest, runtime and protocol versions, input/output schemas, application-security descriptor, strongest effect, requested capabilities, resource budgets, and engine compatibility range. | Manifest schema snapshot, canonicalization, malformed-input, digest, duplicate, and compatibility tests. |
| REQ-002 | When a third-party extension is loaded, ScorchKit shall execute only the digest-verified WebAssembly module in a separate owned worker process with no WASI or undeclared imports and shall reject native in-process or ambiently discovered third-party code. | Import allow-list, explicit-registration, digest-race, worker-process identity, and native-library rejection tests. |
| REQ-003 | When an extension requests an undeclared, unsupported, or unauthorized network, filesystem, credential, or subprocess effect, ScorchKit shall deny it before the effect begins and shall publish a redacted audit decision. | Capability/effect denial matrix, recording-broker no-side-effect fixtures, and audit-event assertions. |
| REQ-004 | When a third-party extension runs, ScorchKit shall enforce nonzero bounded wall time, WebAssembly instructions, linear memory, request/output bytes, effect count, owned temporary artifacts, cancellation, and descendant cleanup. | Exact-boundary, overflow, fuel exhaustion, timeout, cancellation, worker crash, artifact cleanup, and process-tree tests. |
| REQ-005 | When an extension produces observations, findings, evidence, artifacts, or diagnostics, ScorchKit shall validate, bound, normalize, and redact them and shall attach extension identity, version, digest, invocation identity, parser outcome, and source-artifact identities without accepting extension-claimed engine trust. | Hostile-output, spoofing, redaction, stable-identity, report, MCP, control-catalog, and storage round-trip tests. |
| REQ-006 | When a first-party module and third-party extension implement the same application-security category, ScorchKit shall expose them through the same provider-neutral descriptor and selection contract while retaining distinct trust and runtime labels. | Exhaustive first-party descriptor parity, extension catalog, profile selection, and compatibility-surface tests. |
| REQ-007 | When extension output enters durable state, ScorchKit shall route it through existing engine-owned repositories and transactions and shall never expose a database connection, canonical storage path, finding-state mutation handle, engagement object, or policy memory to the extension. | Protocol/source-boundary negatives, PostgreSQL persistence test, malformed-output rollback, and direct-handle absence assertions. |

## Scope

- In: manifest and JSON Schemas; provider-neutral extension package/SDK; explicit registration;
  digest-bound WebAssembly ABI; separate worker process; no-ambient import allow-list; engine effect
  broker; wall-time/instruction/memory/request/output/effect/artifact budgets; cancellation and
  cleanup; normalized provenance; first-party descriptor parity; engine-owned persistence;
  conformance fixtures and public documentation.
- Out: in-process third-party native libraries; arbitrary executable plugins; ambient filesystem,
  network, credential, or subprocess access; directory scanning or automatic discovery; extension
  marketplace/distribution/signing/revocation; general network/cloud posture defaults; lifecycle
  preprocessors/hooks; model analysis; triage; UI or team hosting.

## Locked decisions

- Stable extension contracts live below root composition; policy, execution, storage, and transport
  adapters stay in the root package.
- First-party Rust modules remain compiled and trusted; third-party modules use only the isolated
  WebAssembly runtime and carry explicit `first_party`/`third_party` and `compiled`/`wasm_worker`
  labels in the shared descriptor.
- WebAssembly receives no WASI imports. A narrow versioned ABI is the sole input/output/effect
  surface, so the worker cannot grant ambient host access.
- Registration is explicit and binds canonical manifest bytes, module bytes, and SHA-256 before
  process creation. No plugin directory is scanned implicitly.
- Extension declarations are constraints, never authority. The active engagement and engine broker
  independently authorize each requested effect before execution and publish the decision.
- Extension output is a proposal to engine validation and existing repositories; no storage,
  policy, engagement, credential value, or canonical host path enters the guest protocol.
- Development uses `bash bin/gate.sh --fast`; validation and post-archive delivery use
  `bash bin/gate.sh --diff`. The mode-less and `--full` gates are not authorized for this ticket.

## Owner-approved focused repair amendment

The repository owner directed ScorchKit to stop repeating broad mutation runs, repair all and only
the 140 survivors recorded by the completed TICKET-028 DIFF baseline, recheck that exact survivor
set, and then move to the next ticket. The immutable discovery source is
`.git/scorchkit-mutants-baseline-ticket-028`: 418 selected mutations, 239 ordinary catches, 6
timeouts, 140 misses, and 33 unviable outcomes. Focused evidence is sealed under
`.git/scorchkit-mutants-focused-ticket-028`; no other mutation selection is authorized during this
repair. Pre-completion and post-archive delivery therefore use `bash bin/gate.sh
--focused-repair`, whose mutation lane verifies that evidence without launching cargo-mutants.

## Recon

- Existing `ScanModule`/`CodeModule` traits are trusted in-process source APIs; `PluginDef` TOML
  wrappers are trusted external-command configuration and currently skip malformed records.
- `AdapterContractV1` already owns application domains, lifecycle, targets, strongest effect,
  output, provenance, and artifact policy, but lacks runtime/trust labels.
- `scorchkit-tools` already owns bounded stdio, wall time, artifact monitoring, Unix process groups,
  and Windows Job Objects; it is the worker lifecycle seam, while guest memory/instruction limits
  belong inside the WebAssembly worker.
- `ScanContext` already has exact adapter-effect authorization and structured event publication;
  the extension broker must reuse those seams rather than create raw clients or subprocesses.
- Existing finding normalization/redaction and PostgreSQL repositories remain authoritative; the
  extension runtime should return normal engine-owned records instead of creating a parallel store.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/extension-runtime.spec.md`

## Log

- 2026-08-23: opened.
- 2026-08-23: owner directed work through roughly five successive tickets and required DIFF-only,
  not full, mutation validation; plan scope and gate mode confirmed.
