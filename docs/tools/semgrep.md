# Semgrep

Multi-language static analysis — fast, rule-based SAST covering Python, JavaScript/TypeScript, Go, Java, Ruby, C#, PHP, Rust, Solidity, and more. License: LGPL-2.1 for the CLI / Apache-2.0 for rules (upstream: [semgrep/semgrep](https://github.com/semgrep/semgrep)).

## Install

```
pip install semgrep
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `semgrep scan --config auto --json --quiet <path>` and iterates `results[]`. One finding per rule hit:

| Semgrep `extra.severity` | ScorchKit severity |
|---|---|
| `ERROR` | High |
| `WARNING` | Medium |
| `INFO` | Low |
| other | Info |

Each finding carries:

- **Title**: the rule's `check_id` (e.g. `python.lang.security.audit.eval-detected`)
- **Description**: the rule's message
- **Affected**: `<file>:<line>`
- **Evidence**: the matched source lines (`extra.lines`) when present
- **CWE**: extracted from `extra.metadata.cwe` when present (format `CWE-<n>`)
- **OWASP**: extracted from `extra.metadata.owasp` when present
- **Remediation**: `Review and fix the issue identified by Semgrep rule: <check_id>`
- **Confidence**: 0.8

## How to run

```
scorchkit code /path/to/source --modules semgrep
```

300s timeout. `--config auto` pulls community rules appropriate to the detected languages in the target.

## Limitations vs alternatives

- **The universal SAST**. Semgrep usually runs alongside every language-specific scanner (`bandit` for Python, `gosec` for Go, `brakeman` for Rails, etc.). It's broader; the native scanners are deeper.
- **`--config auto` relies on network** to fetch rulesets. For air-gapped CI, vendor a ruleset and invoke semgrep directly.
- **Custom rules** are Semgrep's superpower — write YAML rules for organisation-specific anti-patterns. The wrapper doesn't surface a knob for custom rule paths; run semgrep directly to use them.
- **Pro / Supply-chain features** (cross-function taint, SCA) are paid / registered-only — not invoked here.
