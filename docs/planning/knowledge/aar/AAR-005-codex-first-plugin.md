---
aar: AAR-005-codex-first-plugin
ticket: TICKET-005
pipeline: codex-first-plugin
status: submitted
opened: 2026-08-17
submitted: 2026-08-17
effectiveness: 5 - recalled host, policy, and evidence boundaries directly shaped the package and exposed two MCP workflow contract gaps
---

# AAR-005 — Codex-first plugin and workflow skills

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Operational skills can request scans, external tools, database changes, and finding transitions. | Yes — every effectful skill requires exact user direction and names engine engagement policy as authoritative; a new persisted-scan denial test proves registered inventory is not authority. |
| `PR-scorchkit-public-mode-dependency-contract-001` | The plugin becomes a new public execution mode over existing MCP operations. | Yes — phase ownership is enforced statically and executing duplex/project tests bind the workflow to real MCP schemas and behavior. |
| `PR-scorchkit-loopback-integration-001` | Acceptance requires an authorized engagement through MCP. | Yes — all executing tests used an in-process loopback server or a must-not-connect loopback address; no remote target was scanned. |
| `PR-scorchkit-process-output-contract-001` | A valid manifest alone does not prove the MCP invocation or skill semantics. | Yes — exact startup, skill inventory, phase tools, outcome fields, and advertised input schema have positive and negative evidence. |
| `PR-scorchkit-provider-consumption-validation-001` | Reporting consumes optional provider analysis at a public host boundary. | Yes — provider output follows stored scanner evidence, remains labeled interpretation, and the reporting workflow rejects finding-state mutation. |
| `PR-scorchkit-green-baseline-reuse-001` | A completed zero-survivor DIFF result can avoid an unnecessary repeated mutation run. | Yes — the two-mutant green result is sealed to the exact mutation inputs for post-archive non-mutation delivery proof. |
| Official OpenAI plugin and skill documentation | Codex packages skills and MCP servers under one plugin manifest. | Yes — the documented layout and independent validators passed without changing installed plugin or marketplace state. |

## What happened

SK-031 added a repository-owned Codex plugin with one local stdio MCP server and five focused skills
for preparation, planning, execution, reporting, and remediation verification. The package stores
no target, policy, database value, or credential, and production crates do not depend on Codex. The
engine remains the only authorization authority and every operational skill stops when MCP is
unavailable instead of introducing a terminal bypass.

Recon found that the documented AI plan-to-persisted-scan path could not carry module selectors.
The MCP request now accepts include/skip selectors after profile filtering and returns actual module
outcomes. Inspection also strengthened the repository validator so forbidden phase tools are
recognized independently of prose. The DIFF gate passed 19 applicable lanes, measured 79.54% line
coverage, ran 1,433 strict tests, and caught both selected MCP mutants with zero survivors.

## Novel findings

- Host workflow text is a public contract: every promised input and output must exist in the MCP
  schema and be proven through an executing client, not inferred from internal storage.
- Static phase policy should reject the protected tool or effect token itself. Matching one command
  verb leaves equivalent instructions able to cross the boundary.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-project-scan-contract-gap-001` | Persisted scans could neither consume planned module selectors nor initially return the module outcome lists promised by the host workflow. | MCP schema/skill reconciliation during implementation and inspection. |
| `BF-scorchkit-plugin-phase-verb-bypass-001` | The first phase-separation regex depended on the verb “Call” and could miss equivalent scan instructions. | Adversarial negative-fixture review. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-host-workflow-tool-contract-001` | Bind every host-workflow input and output claim to the advertised MCP schema, immediate tool result, and an executing transport test. | A coherent internal implementation does not make an unavailable host contract executable. |
| `PR-scorchkit-semantic-token-policy-check-001` | Enforce static phase boundaries on protected tool/effect tokens independently of surrounding prose, and prove alternate wording fails. | Safety validation must survive harmless wording changes. |

## Effectiveness

5. Recalled policy and host-contract rules changed the implementation, added the persisted-scan
authorization negative, prevented profile broadening, and exposed both the selector/outcome gap and
the wording-dependent phase check before delivery.
