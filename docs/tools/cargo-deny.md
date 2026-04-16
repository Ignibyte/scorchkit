# cargo-deny

Rust dependency policy + advisory enforcement. Complements cargo-audit (advisories only) with license compliance, banned crates, and source-registry restrictions. License: Apache-2.0 or MIT (upstream: [EmbarkStudios/cargo-deny](https://github.com/EmbarkStudios/cargo-deny)).

## Install

```
cargo install cargo-deny
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `cargo-deny --manifest-path <path>/Cargo.toml --format json check` and parses JSON-Lines diagnostics from stderr. Each `type == "diagnostic"` entry becomes one finding:

| cargo-deny `severity` | ScorchKit severity |
|---|---|
| `error` | High |
| `warning` | Medium |
| `note` / `help` | Low |
| other | Info |

Each finding carries:

- **Title**: `cargo-deny <code>: <message>` (e.g. `cargo-deny banned: crate banned`)
- **Evidence**: `severity=error code=banned`
- **Affected**: `Cargo.toml`
- **Remediation**: generic — adjust `deny.toml`, update the crate, or add a documented ignore
- **Confidence**: 0.85

The wrapper uses `run_tool_lenient` because cargo-deny exits non-zero on any policy violation; that's expected, not an error.

## How to run

```
scorchkit code /path/to/rust/project --modules cargo_deny
```

120s timeout. Requires `Cargo.toml` and (for the most value) a project `deny.toml` configuring policy.

## Limitations vs alternatives

- **vs `cargo-audit`**: cargo-deny subsumes cargo-audit's advisory check (`check advisories`) but adds license / banned / sources / bans. Run both or run cargo-deny alone — they don't conflict.
- **No OWASP mapping** — cargo-deny diagnostics span several categories (licensing, supply-chain, ban policy), so each finding is left uncategorized. Operators triage based on the `code` field.
- **Project-specific policy required for full value**. Without a `deny.toml`, cargo-deny falls back to conservative defaults — useful but not bespoke.
