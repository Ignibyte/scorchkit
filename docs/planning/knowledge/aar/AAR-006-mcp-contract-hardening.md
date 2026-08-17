---
aar: AAR-006-mcp-contract-hardening
ticket: TICKET-006
pipeline: mcp-contract-hardening
status: submitted
opened: 2026-08-17
submitted: 2026-08-17
effectiveness: 5 - recalled policy, host-contract, and evidence rules shaped the boundary and exposed one verification-plan mismatch plus one generated-metadata test gap
---

# AAR-006 — Typed MCP contracts and principal-aware tool boundaries

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Principal work could accidentally create a second authorization source. | Yes — principal context is attribution only and the existing engagement remains authoritative. |
| `PR-scorchkit-host-workflow-tool-contract-001` | SK-031 documented the exact schema/result/transport gap that SK-032 closes. | Yes — acceptance requires advertised schemas, immediate native results, and both direct-router and duplex execution. |
| `PR-scorchkit-semantic-token-policy-check-001` | Read/state/effect separation must not depend on descriptions. | Yes — one exhaustive machine-checked contract inventory owns the class. |
| `PR-scorchkit-exact-failure-source-001` | A failed effect call alone would not prove principal metadata cannot authorize it. | Yes — no-engagement tests require the exact authorization denial through the router. |
| `PR-scorchkit-green-baseline-reuse-001` | SK-032 changes mutation-relevant Rust. | Yes — it requires a new DIFF result and forbids reuse of SK-031 mutation evidence. |

## What happened

SK-032 added a versioned native MCP result envelope without removing the prior text payload. One
exhaustive inventory now classifies all 30 tools as read, local-state, or external-effect and owns
their four standard annotations, generated title, schema/version metadata, and response class. The
current stdio boundary reports a local-process principal while MCP client name/version remain
explicitly untrusted attribution. Neither is passed to engagement policy.

The implementation kept every `do_*` business handler unchanged and adapted only the generated
router wrappers. Schema and inventory snapshots, direct adapter tests, generated-router mismatch
tests, and duplex framing prove the contract. A client calling itself `local-administrator` still
received the exact no-engagement denial. The one DIFF mutation batch found two missed return-value
mutations in generated tool titles; one exact assertion caught both in the only repaired-function
rerun. Sealed focused evidence reconstructs 13/13 viable mutations caught and 100% MSI.

## Novel findings

- Transport identity and client implementation metadata answer “where did this request arrive
  from?” and “what did the peer call itself?” They do not answer “what may it scan?” Authentication
  and principal-to-engagement binding must be separate before remote MCP is enabled.
- A single behavior inventory can bind host hints, response provenance, and startup drift checks,
  but generated presentation metadata still needs an exact assertion; semantic flag tests alone do
  not prove the entire advertised contract.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-rmcp-private-router-context-001` | The initial verification plan promised direct router invocation, but rmcp keeps the peer constructor required for a valid `ToolCallContext` private outside its crate. | Adversarial correctness inspection while adding the planned direct call. |
| `BF-scorchkit-generated-tool-title-gap-001` | Router tests asserted schemas, classes, annotations, and metadata but not the generated human-readable title, allowing two return-value mutations to survive. | The single SK-032 DIFF mutation batch. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-attribution-not-authorization-001` | Keep transport principal and self-asserted client attribution separate from engagement grants; label trust explicitly and prove a privileged-looking client name cannot authorize an effect. | Trace context is not authentication, and authentication alone is not ScorchKit target/effect authorization. |
| `PR-scorchkit-effect-contract-single-source-001` | Let one exhaustive inventory own every tool's strongest behavior class, annotations, and response provenance, and fail router construction when names or counts drift. | Duplicated wrapper hints can under-classify composite tools and diverge from the result an agent consumes. |
| `PR-scorchkit-generated-metadata-exactness-001` | Pin generated titles and other presentation metadata with exact representative assertions in addition to semantic schema/flag tests. | Generated metadata is part of the advertised protocol even when it does not change engine behavior. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5. Recalled rules preserved text compatibility, centralized effect classification, kept principal
data out of authorization, and forced exact failure-source assertions. They also led directly to
the spoofed-client denial and sealed focused evidence. Inspection and mutation testing exposed both
new failure patterns before delivery, and all accepted findings were closed without a repeated
broad mutation run.
