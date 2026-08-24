---
title: Capability-declared extension runtime and SDK
pipeline_id: db68b03e-a4b5-4cfa-996a-caae014e5473
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-028
ticket_doc: docs/planning/tickets/closed/TICKET-028-extension-runtime.md
aar: docs/planning/knowledge/aar/AAR-028-extension-runtime.md
created: 2026-08-23
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-028
---

# Capability-declared extension runtime and SDK — spec

## Intent

Ship the isolated extension foundation required before lifecycle hooks, model roles, or a signed
catalog can consume third-party application-security modules. The ticket adds a stable manifest,
SDK, digest-bound WebAssembly ABI, separate owned worker, policy/audit effect broker, bounded and
normalized output, first-party descriptor parity, and engine-owned persistence without widening
trusted Rust constructors or introducing ambient guest access.

## Scope

- In: versioned manifest/schema and SDK package; explicit registration; WebAssembly guest ABI;
  separate owned worker; import allow-list; digest/compatibility validation; effect broker; time,
  instruction, memory, protocol, output, effect, and artifact budgets; cancellation/cleanup;
  provenance normalization; descriptor parity; existing repository persistence; conformance tests.
- Out: native or in-process third-party code; arbitrary executable plugins; ambient discovery or
  host access; extension marketplace/signing/revocation; non-application default catalogs;
  lifecycle hooks, model analysis, triage, UI, and team deployment.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an extension is registered, ScorchKit shall require a versioned manifest naming its identity, exact module digest, runtime and protocol versions, input/output schemas, application-security descriptor, strongest effect, requested capabilities, resource budgets, and engine compatibility range. | Manifest schema snapshot, canonicalization, malformed-input, digest, duplicate, and compatibility tests. |
| REQ-002 | When a third-party extension is loaded, ScorchKit shall execute only the digest-verified WebAssembly module in a separate owned worker process with no WASI or undeclared imports and shall reject native in-process or ambiently discovered third-party code. | Import allow-list, explicit-registration, digest-race, worker-process identity, and native-library rejection tests. |
| REQ-003 | When an extension requests an undeclared, unsupported, or unauthorized network, filesystem, credential, or subprocess effect, ScorchKit shall deny it before the effect begins and shall publish a redacted audit decision. | Capability/effect denial matrix, recording-broker no-side-effect fixtures, and audit-event assertions. |
| REQ-004 | When a third-party extension runs, ScorchKit shall enforce nonzero bounded wall time, WebAssembly instructions, linear memory, request/output bytes, effect count, owned temporary artifacts, cancellation, and descendant cleanup. | Exact-boundary, overflow, fuel exhaustion, timeout, cancellation, worker crash, artifact cleanup, and process-tree tests. |
| REQ-005 | When an extension produces observations, findings, evidence, artifacts, or diagnostics, ScorchKit shall validate, bound, normalize, and redact them and shall attach extension identity, version, digest, invocation identity, parser outcome, and source-artifact identities without accepting extension-claimed engine trust. | Hostile-output, spoofing, redaction, stable-identity, report, MCP, control-catalog, and storage round-trip tests. |
| REQ-006 | When a first-party module and third-party extension implement the same application-security category, ScorchKit shall expose them through the same provider-neutral descriptor and selection contract while retaining distinct trust and runtime labels. | Exhaustive first-party descriptor parity, extension catalog, profile selection, and compatibility-surface tests. |
| REQ-007 | When extension output enters durable state, ScorchKit shall route it through existing engine-owned repositories and transactions and shall never expose a database connection, canonical storage path, finding-state mutation handle, engagement object, or policy memory to the extension. | Protocol/source-boundary negatives, PostgreSQL persistence test, malformed-output rollback, and direct-handle absence assertions. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Put stable manifest, protocol, output, and descriptor-label types in a dependency-light `scorchkit-extension` package; keep policy/execution/storage in root composition. | Preserves workspace dependency direction and provider neutrality. |
| 2 | Keep trusted first-party Rust modules compiled; run third-party modules only as digest-bound WebAssembly in a separate worker with no WASI imports. | A plain native subprocess still has ambient host authority and is not an isolation boundary. |
| 3 | Use an explicit versioned memory ABI and framed JSON protocol; reject every undeclared import and every unknown frame or schema version. | Makes guest access auditable, bounded, and independent of an agent or language SDK. |
| 4 | Treat manifest capabilities as a maximum request set, not grants; the root broker authorizes and audits every effect against the active engagement. | Preserves the safety kernel and confused-deputy boundary. |
| 5 | Return bounded typed proposals through engine validation and existing repositories; expose no storage or canonical-path handles. | Preserves normalization, provenance, append-only evidence, and transaction ownership. |
| 6 | Extend the common adapter descriptor with explicit trust/runtime labels rather than create a parallel extension catalog type. | First- and third-party modules need one provider-neutral selection surface with visible trust differences. |
| 7 | Register explicit manifest/module paths only; do not scan directories or infer approval from file presence. | File placement is context, not operator intent or authority. |
| 8 | Use `--fast` during development and `--diff` for validation/delivery; never run the mode-less or `--full` gate. | Matches the owner's cost boundary while retaining changed-code mutation evidence. |
| 9 | After the one completed 418-mutant DIFF baseline, repair and recheck all and only its 140 recorded survivors; use the sealed focused-repair receipt for completion and delivery. | Implements the owner's explicit stop-and-squash direction without another broad mutation run. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-028-extension-runtime.md`
- AAR: `docs/planning/knowledge/aar/AAR-028-extension-runtime.md`
- Intake: `docs/planning/intake/INTAKE-extension-runtime.md`
- Architecture: `docs/architecture/modules.md`, `docs/architecture/executor.md`,
  `docs/architecture/workspace.md`, `docs/architecture/control-api.md`,
  `docs/architecture/application-security-catalog.md`

## Confirmed design

### Contract and package ownership

Add `scorchkit-extension` as a lower provider-neutral package. It owns manifest v1, protocol v1,
guest SDK, effect-request/result, typed output, validation errors, constants, and generated JSON
Schemas. It may depend on `scorchkit-core` and `scorchkit-policy` for the common descriptor,
findings/evidence vocabulary, capabilities, and effects, but never on root composition, config,
tools, storage, control, MCP, CLI, or an agent provider. Root composition owns file authorization,
digest verification, worker lifecycle, policy decisions, HTTP/process effects, normalization,
catalog integration, and persistence.

Extend `AdapterContractV1` with `AdapterTrust::{FirstParty,ThirdParty}` and
`AdapterRuntime::{Compiled,WasmWorker}`. Every current descriptor is explicitly first-party and
compiled. An extension descriptor uses the same application domain, lifecycle, target, strongest
effect, output, provenance, and artifact fields but remains visibly third-party and worker-backed.

Manifest `scorchkit.extension-manifest/v1` contains a bounded stable ID/name/description/version,
lowercase SHA-256 module digest, `wasm32-unknown-unknown` runtime, protocol/ABI versions, engine
semantic compatibility range, input/output schema identities, one application-security adapter
descriptor, a sorted unique capability maximum, and nonzero bounded resource budgets. Validation
rejects unknown versions, compatibility domains, duplicates, control characters, inconsistent
effect/capability declarations, oversized values, zero/over-ceiling budgets, path-bearing or
credential-bearing fields, and noncanonical digests before any worker starts.

### Explicit registration and identity

Add a disabled-by-default `[extensions]` config with an explicit ordered manifest-path list; there
is no directory discovery. Keep `scan.plugins_dir` as the documented legacy trusted native-command
surface and never project those wrappers as isolated third-party extensions. At host composition,
canonicalize and no-follow open each declared manifest and its manifest-relative WebAssembly file,
authorize both exact paths as `LocalState/Passive` plus `ExtensionExecute/Passive`, bound their
bytes, parse the manifest, and hash the exact in-memory module bytes. Duplicate extension IDs or a
digest mismatch fail the complete registry. The loaded registry retains those exact bytes, so no
later path reopen can change execution.

`Capability::ExtensionExecute` is a separate explicit grant. Before an extension can run against a
target, root composition additionally requires `ExtensionExecute` at the manifest's exact strongest
family capability for that exact target. Each brokered effect independently requires its declared
capability plus the existing operation capability; declaration and registration never grant it.

### Guest ABI and worker isolation

Third-party modules compile for `wasm32-unknown-unknown`. The module may import nothing: WASI,
filesystem, socket, environment, clock, random, process, and host-memory imports are all rejected.
It exports exactly one linear memory plus `scorchkit_abi_version`, `scorchkit_reserve_input`, and
`scorchkit_run`. The SDK implements the input/output buffers with safe Rust and a turn-based trait.
No guest pointer enters root code; the worker performs checked memory reads and writes through the
runtime API.

The turn protocol is `scorchkit.extension-protocol/v1`. The engine sends one bounded invocation;
the guest returns either one typed effect request, a completed typed output, or a safe failure. For
an effect request, the parent authorizes and performs or denies it, then sends the typed result as
the next turn. This state-machine protocol needs no guest host imports and makes every effect an
observable parent decision.

The official binary exposes an exact hidden worker mode used only by the root runtime. The parent
spawns its trusted worker program with a cleared environment, null filesystem arguments, piped
stdio, and the existing Unix process-group/Windows Job Object owner. It transfers the already
verified manifest and module bytes in the initial bounded frame; the worker never opens the
registration paths. The worker uses Wasmi with extra checks, fuel, one-memory limits, bounded
module structure and stack, and no linker imports. Parent wall time, frame/output/effect ceilings,
owned scratch, cancellation, protocol failure, and worker exit all terminate and reap the complete
process tree before returning.

### Effect broker and output ownership

V1 supports a bounded credential-free `GET`/`HEAD` HTTP request through the existing policy-owned
client and bounded body reader. URL, redirects, and resolved addresses retain existing checks. A
guest can also request bytes only by an opaque invocation input ID already opened and bounded by
the engine; guest messages never contain host paths. Filesystem paths, raw credential values, and
arbitrary subprocess requests are recognized protocol classes but are unsupported in v1 and
receive typed denials before any effect. This preserves a forward-compatible capability matrix
without pretending unsupported authority exists.

For every request, validate the manifest declaration and request shape first, then the active
engagement's exact target/capability/effect tuple, then publish a redacted durable
`extension.effect_decision` event, and only then construct the effect. Count both allowed and denied
requests against the invocation budget. Broker responses contain bounded redacted bytes and
metadata, never headers or values classified as secrets.

Guest completion returns bounded observation/finding/evidence proposals. Root validates module ID,
target, severity, confidence, schema, counts, nested bytes, locations, and source-artifact
identities; recursively redacts untrusted strings; ignores guest-supplied trust; and rebuilds
`ScannerProvenance` from manifest version/digest and engine invocation identity. The resulting
normal `Finding` values flow through orchestrator events, reports, control/MCP projections, and the
existing transactional storage repository. No protocol or SDK type contains a pool, table, row,
canonical host path, engagement, policy object, or direct finding-state operation.

### Catalog, compatibility, and public surface

`WasmExtensionModule` implements the existing web `ScanModule` contract in v1 and is appended only
from an explicitly loaded registry. Profile selection reads the same descriptor as first-party
modules; compatibility domains are rejected from extension manifests, so an extension cannot
restore general network/cloud posture to defaults. The provider-neutral extension registry also
supplies dynamic module views to control and MCP hosts that compose it. Existing built-in module
IDs, trusted Rust traits, legacy TOML wrappers, serialized findings, and no-extension behavior stay
compatible.

The public SDK includes a minimal pure extension example compiled for
`wasm32-unknown-unknown`, WAT hostile/conformance fixtures for protocol edges, a schema export, and
an explicit host registration example. Documentation labels trusted Rust/TOML and isolated
WebAssembly surfaces separately.

### File manifest

- Add `crates/scorchkit-extension/Cargo.toml` and
  `crates/scorchkit-extension/src/{lib,manifest,protocol,sdk,validation}.rs`.
- Modify `Cargo.toml`, `Cargo.lock`, `crates/scorchkit-core/src/{adapter,lib}.rs`,
  `crates/scorchkit-policy/src/policy.rs`, `tests/workspace_architecture.rs`, and `src/lib.rs` for
  the package, Wasmi runtime, trust/runtime labels, extension capability, dependency direction, and
  compatibility re-exports.
- Add `crates/scorchkit-config/src/extension.rs`; modify its `lib.rs` and `types.rs` for explicit
  disabled-by-default registrations and bounded validation.
- Add `src/extension/{mod,broker,loader,module,runtime,worker}.rs`; modify `src/main.rs`,
  `src/engine/scan_context.rs`, `src/facade.rs`, `src/runner/{orchestrator,subprocess}.rs`, and
  `crates/scorchkit-tools/src/lib.rs` only as needed for trusted worker selection, registry
  propagation, interactive bounded frames, cancellation, and process ownership.
- Modify `src/adapter_catalog.rs`, the four family descriptor constructors, control module views,
  MCP module projections, and relevant fixtures for explicit first-party/compiled parity and
  dynamic third-party/worker views.
- Add `tests/extension_contract.rs`, `tests/extension_runtime.rs`,
  `tests/fixtures/extensions/{valid,hostile}` manifests/Wasm modules, and
  `examples/custom_wasm_extension`; extend external-tool, module-census, control, MCP, storage,
  report, CLI, workspace, config, and security source-boundary tests narrowly.
- Add `docs/architecture/extensions.md`; update `docs/plugin-sdk.md`,
  `docs/architecture/{modules,executor,workspace,control-api,application-security-catalog}.md`,
  `README.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/planning/ROADMAP.md`, current pipeline artifacts,
  AAR, and knowledge register.

### Regression plan

1. Package tests pin manifest/protocol/schema constants, canonical round trips, every validator arm,
   exact numeric boundaries, duplicate handling, compatibility ranges, and guest SDK turn behavior.
2. Workspace contracts pin dependency edges, type identity, every first-party descriptor's
   trust/runtime labels, the new policy capability, and the absence of storage/root/provider types
   from the extension package and protocol.
3. Loader tests use no-follow handles and post-open replacement fixtures to prove exact bytes and
   digest identity; invalid, duplicate, implicit-directory, native-library, unsupported-domain, and
   unauthorized-path registrations start no worker.
4. Worker fixtures prove a distinct PID, zero imports, exact ABI exports, bounded module structure,
   one linear memory, memory growth denial, fuel exhaustion, malformed pointers/frames, oversized
   input/output, timeout, cancellation, crash, descendant cleanup, and owned scratch cleanup.
5. Broker truth tables cover undeclared, unsupported, missing-capability, wrong-effect,
   out-of-scope, disabled/expired, exact-boundary, and allowed loopback HTTP requests; recording
   seams prove denial before effects and durable redacted decisions for both arms.
6. Hostile output tests cover spoofed trust/digest/module/target/invocation, secret-bearing nested
   strings, malformed findings/evidence, invalid counts/confidence/severity, duplicate identities,
   and all-or-nothing conversion. Positive fixtures prove normalized provenance and stable IDs.
7. Orchestrator, report, control, MCP, and PostgreSQL tests prove a configured extension shares the
   application catalog and existing persistence path while no configured extensions preserve exact
   current behavior. The standalone SDK example must compile for the Wasm target.
8. Run focused tests and `bash bin/gate.sh --fast` during implementation. Validate and deliver with
   database-backed `bash bin/gate.sh --diff` only. Never invoke the mode-less or `--full` gate.

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
