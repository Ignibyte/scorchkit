---
aar: AAR-004-typed-ai-provider-contracts
ticket: TICKET-004
pipeline: typed-ai-provider-contracts
status: submitted
opened: 2026-08-16
submitted: 2026-08-17
effectiveness: 5 - recalled boundary and process rules shaped the design and inspection closed the external-provider bypass
---

# AAR-004 — Typed and versioned AI provider contracts

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Provider CLIs are external effects even though they only reason over stored evidence. | Yes — every CLI, MCP, and autonomous host still authorizes before the built-in adapter executes. |
| `PR-scorchkit-process-output-contract-001` | Codex and Claude need semantic fixture equality, not helper-only prompt tests. | Yes — one recording-executor suite runs all four tasks through both adapters and checks their real invocation contracts. |
| `PR-scorchkit-exact-failure-source-001` | Wrong task, wrong version, disabled, unavailable, and malformed output can all fail. | Yes — decoder and workflow tests distinguish exact errors from deterministic fallback. |
| `PR-scorchkit-store-invariants-falsification-001` | The provider trait is another public boundary whose implementations must enforce the same invariants. | Yes — inspection found that built-in validation alone was insufficient and added workflow-boundary validation for external implementations. |
| `docs/architecture/ai.md` | The generic prompt method is explicitly recorded as a compatibility stage ending at SK-030. | Yes — the raw method and caller-owned provider parsers/prompts were removed rather than wrapped. |

## What happened

SK-030 replaced the raw system/user provider method with four typed tasks under the required
`scorchkit.ai/v1` envelope. Codex is still the default and runs read-only, ephemeral, and
non-interactive; Claude uses the same renderer and decoder behind a compatibility transport.
Planner and analyst callers now construct typed input. Correlation and remediation own deterministic
fallbacks. Provider output stays labeled interpretation and cannot overwrite scanner evidence or
authorization.

The adversarial review found one high-severity boundary defect: a third-party `AiProvider` could
construct a mismatched public response and bypass checks that existed only in the built-in adapter.
The fix validates schema/task at every workflow boundary and repeats plan-target and analysis-focus
invariants outside the adapter. The normal DIFF gate passed 19 applicable lanes, measured 79.63%
line coverage, executed 1,432 Nextest cases, and produced a 100% scoped mutation result with 26
viable cases caught, 58 unviable, and zero survivors.

## Novel findings

- A typed return value is not an invariant when external trait implementations can construct its
  public envelope fields. Provider-neutral workflows must validate at the consumption boundary.
- A completed green mutation baseline with zero survivors needs a sealed reuse path distinct from
  survivor repair. Repeating the same inventory adds no evidence when mutation inputs are unchanged.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-provider-envelope-bypass-001` | An external provider implementation could return the wrong schema/task or analysis variant and be trusted by workflow code. | SK-030 adversarial inspection. |
| `BF-scorchkit-empty-survivor-proof-gap-001` | Focused delivery could verify repaired survivors but could not represent a green baseline whose survivor set was empty. | SK-030 post-validation delivery preparation. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-provider-consumption-validation-001` | Revalidate public provider envelopes and request-bound invariants where workflows consume them, regardless of adapter validation. | Agent-neutral provider implementations are outside the built-in adapter's trust boundary. |
| `PR-scorchkit-green-baseline-reuse-001` | Reuse a completed green DIFF/FULL mutation result only when raw outcomes prove zero misses and the exact mutation-input hash is unchanged. | An empty survivor set has no repaired-function recheck, but delivery still needs receipt-bound evidence without a duplicate sweep. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Every recalled rule changed implementation or proof: host authorization stayed outside
the provider, Codex and Claude share executable four-task fixtures, exact failure sources received
typed tests, and public-boundary falsification found and fixed the only high-severity inspection
defect. No remote target or provider API was used. The only mutation inventory was the ticket-scoped
DIFF; its zero-survivor result is sealed for non-mutation delivery reuse under the owner's direction.
