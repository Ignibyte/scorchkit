# Gosec

Go security static analyzer — scans Go AST for SQL injection patterns, command injection, weak crypto (MD5, SHA1, RC4), hardcoded credentials, file-permission issues, and unhandled errors. License: Apache-2.0 (upstream: [securego/gosec](https://github.com/securego/gosec)).

## Install

```
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `gosec -fmt json -quiet <path>/...` and iterates `Issues[]`. One finding per issue:

| Gosec `severity` | ScorchKit severity | | Gosec `confidence` | ScorchKit confidence |
|---|---|---|---|---|
| `HIGH` | High | | `HIGH` | 0.9 |
| `MEDIUM` | Medium | | `MEDIUM` | 0.7 |
| `LOW` | Low | | `LOW` | 0.5 |

Each finding carries:

- **Title**: `<rule-id>: <details>` (e.g. `G201: SQL string formatting`)
- **Description**: Gosec's `details` field
- **Affected**: `<file>:<line>`
- **Evidence**: the source `code` Gosec captured at the site
- **CWE**: parsed from `cwe.id` (accepts bare number or `CWE-<n>`)
- **OWASP**: A03:2021 Injection (generic)
- **Remediation**: points back to the Gosec rule ID

## How to run

```
scorchkit code /path/to/go/project --modules gosec
```

120s timeout. The `...` suffix in the invocation means gosec recurses into all sub-packages.

## Limitations vs alternatives

- **Go-only**. For multi-language projects, `semgrep` with Go rules covers most of gosec's ground plus cross-language consistency.
- **Hardcoded A03:2021 OWASP tag** — many gosec rules are in A02 (crypto) or A04 (insecure design). `rule_id` in the title disambiguates.
- **`// #nosec` comments** suppress findings. Review during triage.
- **No data-flow analysis** — AST pattern matching only. Cross-function taint requires heavier tooling (semgrep taint mode, paid SAST).
