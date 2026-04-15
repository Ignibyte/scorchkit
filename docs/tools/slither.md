# Slither

Solidity static analyzer from Trail of Bits — detects common smart-contract vulnerabilities (reentrancy, locked ether, suicidal contracts, integer issues) and emits high-signal findings with source mapping. License: AGPL-3.0 (upstream: [crytic/slither](https://github.com/crytic/slither)).

## Install

```
pipx install slither-analyzer
```

Requires `solc` (the Solidity compiler) installed and reachable on `$PATH`. Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `slither <path> --json -` and iterates `results.detectors[]`. One finding per detector hit:

| Slither `impact` | ScorchKit severity |
|---|---|
| `High` | High |
| `Medium` | Medium |
| `Low` | Low |
| other (`Informational`) | Info |

Each finding carries:

- **Title**: `slither <check-name>` (e.g. `slither reentrancy-eth`)
- **Description**: first line of Slither's description
- **Affected**: `<contract-file>.sol` (from `elements[0].source_mapping.filename_relative`)
- **Evidence**: `check=<name> impact=<level>`
- **OWASP**: A04:2021 Insecure Design
- **Confidence**: 0.85

## How to run

```
scorchkit code /path/to/solidity/project --modules slither
```

180s timeout. Project must compile (slither invokes `solc` under the hood).

## Limitations vs alternatives

- **Solidity only**. For other smart-contract languages (Vyper, Cairo, Move) use their native tooling — slither doesn't cover them.
- **Slither's `confidence` field is not currently mapped** — all findings get a flat 0.85. The raw confidence is available in the JSON; a follow-up pass could multiply through.
- **Project layout matters**. Slither follows Truffle / Foundry / Hardhat layouts automatically; for bare `.sol` files with complex imports, operators may need to point slither at the specific file and add `--solc-remaps`.
- Complementary with `semgrep` Solidity rules for lightweight taint-style checks.
