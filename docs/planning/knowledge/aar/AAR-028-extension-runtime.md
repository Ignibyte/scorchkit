---
aar: AAR-028-extension-runtime
ticket: TICKET-028
pipeline: extension-runtime
status: submitted
opened: 2026-08-23
submitted: 2026-08-23
effectiveness: 4
---

# AAR-028 — Capability-declared extension runtime and SDK

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Manifests declare effects but cannot authorize them. | Yes; every guest request goes through a root policy/audit broker. |
| `PR-scorchkit-extension-persistence-boundary-001` | Guest output needs durable findings/evidence. | Yes; output remains a proposal to existing engine repositories with no storage handle in the protocol. |
| `PR-scorchkit-executor-contract-001` | The isolated runtime adds a child lifecycle. | Yes; reuse owned bounded process execution instead of adding detached spawn logic. |
| `PR-scorchkit-cancellation-whole-lifecycle-001` | Cancellation can occur during guest startup, effects, output, or cleanup. | Yes; one token and deadline cover the whole worker protocol and success edge. |
| `PR-scorchkit-adapter-execution-descriptor-parity-001` | First- and third-party modules share catalog claims. | Yes; add explicit trust/runtime labels to the existing common descriptor and test execution parity. |
| `PR-scorchkit-public-evidence-revalidation-001` | Guest output is untrusted serialized data. | Yes; normalize and redact at decode, projection, and persistence boundaries. |
| `docs/architecture/modules.md` | Existing contexts and traits are policy sealed but in process. | Yes; preserve them as trusted first-party APIs and do not call them a sandbox. |
| `docs/architecture/executor.md` | Existing process ownership already handles cancellation and descendants. | Yes; isolate the guest in the same lifecycle while enforcing memory/fuel inside the worker. |
| `AAR-020-post-release-platform-roadmap` | SK050 was originally framed as a generic extension surface. | Yes; it explicitly ruled out extension storage handles and ambient authority. |

## What happened

- Added a dependency-light `scorchkit-extension` package with separate host-contract and portable
  guest-SDK feature graphs, a public manifest/schema, a turn-based JSON protocol, and a standalone
  `wasm32-unknown-unknown` example.
- Added explicit digest-bound registration and a separate owned Wasmi worker with no guest imports,
  bounded structural resources, fuel, memory, table capacity, stack, frames, effects, output, wall
  time, cancellation, and process-tree cleanup.
- Routed guest requests through the existing engagement policy, redacted audit publication, and
  effect-specific host seams. V1 permits only credential-free no-redirect HTTP `GET`/`HEAD` and
  digest-bound opaque inputs; filesystem, credential, and subprocess requests fail closed.
- Treated guest output as an untrusted proposal: root composition reauthorizes its target, validates
  every nested bound, redacts it, constructs engine provenance, and routes normal findings through
  the existing report, control/MCP, event, and PostgreSQL paths.
- Extended the shared adapter descriptor with explicit trust/runtime labels so first-party compiled
  modules and third-party worker modules share one catalog without sharing authority.
- Adversarial inspection closed six findings, including worker table-capacity and bearer-redaction
  flaws. The focused delivery gate passed every applicable lane at 84.40% line coverage. Its
  mutation step verified the sealed 140-survivor repair set at 100% viable MSI and did not launch a
  second broad campaign.

## Novel findings

- WebAssembly limit builders expose independent resource dimensions: bounding table count does not
  bound table element capacity. Both structural count and capacity need explicit ceilings.
- A dynamic catalog needs one identity-claim set spanning immutable and dynamic entries. Comparing
  every dynamic entry only with the built-in slice misses collisions between two dynamic entries.
- A protocol capability is not complete merely because guest and broker types exist; a bounded,
  authorized host attachment seam and an end-to-end allowed test must make it reachable.
- Assignment-shaped bearer credentials are multi-token secrets. A redactor that consumes only the
  first whitespace-delimited token can expose the credential after the scheme.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-guest-host-dependency-leak-001` | The first portable guest feature graph inherited host policy and manifest dependencies. | Real `wasm32-unknown-unknown` example compilation. |
| `BF-scorchkit-dynamic-catalog-identity-split-001` | Two configured extensions could claim the same ID because CLI collision checks compared only against built-ins. | Adversarial catalog-consistency review. |
| `BF-scorchkit-wasm-table-capacity-gap-001` | Wasmi table count was bounded while element capacity remained unbounded. | Adversarial resource-exhaustion review. |
| `BF-scorchkit-extension-capability-unreachable-001` | `input_read` existed in the guest protocol and broker but no host API could attach input bytes. | Adversarial effect-reachability review. |
| `BF-scorchkit-bearer-assignment-redaction-tail-001` | `authorization=Bearer token` redacted the scheme but left the following token. | Hostile extension-output redaction review. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-guest-feature-graph-portability-001` | Compile the portable guest feature graph and standalone example for the real guest target with host defaults disabled. | Native compilation cannot prove that host-only dependencies stay out of a Wasm SDK. |
| `PR-scorchkit-dynamic-catalog-global-identity-001` | Claim identities in one set spanning every built-in and dynamic catalog entry before publishing any result. | Pairwise checks against an immutable prefix miss dynamic-to-dynamic collisions. |
| `PR-scorchkit-wasm-resource-dimensions-001` | Bound both the count and capacity of every independently limited WebAssembly resource and test oversized instantiation. | Runtime limit APIs commonly separate resource objects from their allocation capacity. |
| `PR-scorchkit-extension-host-reachability-001` | Every advertised extension capability needs a bounded authorized host seam plus allowed and denied end-to-end tests. | Protocol vocabulary alone can advertise behavior that no valid invocation can exercise. |
| `PR-scorchkit-multitoken-secret-redaction-001` | Treat scheme plus credential as one sensitive range in assignment-shaped and header-shaped redaction fixtures. | Whitespace tokenization otherwise preserves the secret-bearing tail. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 4/5. Recalled policy-before-effects, process ownership, cancellation, descriptor parity,
public revalidation, and mutation-boundary rules directly shaped the isolated worker, effect
broker, output boundary, and portable guest contract. Inspection still found two high and four
medium-to-low gaps in resource ceilings, identity claims, capability reachability, wire strictness,
and secret handling, so the initial design was not complete enough for a perfect score. All six
were fixed, covered by focused regressions, and distilled into five reusable prevention rules.
