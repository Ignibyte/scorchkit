# Bandit

Python security static analyzer — detects hardcoded passwords, unsafe deserialisation (pickle, yaml.load), SQL injection patterns, command injection, weak crypto, and more. License: Apache-2.0 (upstream: [PyCQA/bandit](https://github.com/PyCQA/bandit)).

## Install

```
pipx install bandit
# or: pip install bandit
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `bandit -r -f json <path>` and iterates `results[]`. One finding per issue:

| Bandit `issue_severity` | ScorchKit severity | | Bandit `issue_confidence` | ScorchKit confidence |
|---|---|---|---|---|
| `HIGH` | High | | `HIGH` | 0.9 |
| `MEDIUM` | Medium | | `MEDIUM` | 0.7 |
| `LOW` | Low | | `LOW` | 0.5 |

Each finding carries:

- **Title**: `<test-id>: <test-name>` (e.g. `B301: blacklist_imports`)
- **Description**: Bandit's `issue_text`
- **Affected**: `<file>:<line>`
- **Evidence**: the offending source line (from `code`)
- **CWE**: extracted from `issue_cwe.id` when present
- **OWASP**: A03:2021 Injection (generic — Bandit's `test_id` in the title disambiguates)
- **Remediation**: points back to the Bandit rule ID

## How to run

```
scorchkit code /path/to/python/project --modules bandit
```

120s timeout. Scans recursively from the target path.

## Limitations vs alternatives

- **Python-only**. For multi-language projects, chain with `semgrep` (broader coverage, deeper rules).
- **Hardcoded A03:2021 OWASP tag**. Many Bandit findings are actually A02 (crypto), A07 (auth), or A08 (integrity). Operators disambiguate using the `test_id` field.
- **No taint tracking** — Bandit is AST-based pattern matching, not data-flow analysis. It catches "dangerous function called" but not "user input reaches dangerous function". For real taint, use semgrep's taint mode or a paid SAST.
- **`# nosec` comments** are respected by Bandit and will silently suppress findings — review them during triage.
