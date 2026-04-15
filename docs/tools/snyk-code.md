# Snyk Code

Source-code SAST from Snyk — detects taint-based vulnerabilities (SQL injection, XSS, hardcoded secrets, path traversal) across many languages. Free tier has limited scans; CLI accepts both unauthenticated and token-authenticated usage. License: Apache-2.0 for the CLI, proprietary for the rule engine (upstream: [snyk/cli](https://github.com/snyk/cli)).

## Install

```
npm install -g snyk
```

Run `snyk auth` to log in for higher scan quotas. Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `snyk code test --json <path>` and walks the SARIF-like `runs[0].results[]`. One finding per result:

| Snyk `priorityScore` | ScorchKit severity |
|---|---|
| 3 | High |
| 2 | Medium |
| 1 | Low |
| other | Info |

Each finding carries:

- **Title**: `<rule-id>: <message>` (e.g. `javascript/SqlInjection: Unsanitized input from HTTP request flows into SQL query`)
- **Affected**: `<file>:<line>` (from `locations[0].physicalLocation`)
- **OWASP**: A03:2021 Injection (generic; the rule id encodes category)
- **Remediation**: points back to the Snyk rule
- **Confidence**: 0.8

## How to run

```
scorchkit code /path/to/project --modules snyk-code
```

300s timeout.

## Limitations vs alternatives

- **Free-tier quotas apply**. Unauthenticated runs are rate-limited; `snyk auth` lifts the limit for registered users. CI-heavy workflows need a paid plan.
- **vs `semgrep`**: Snyk Code has taint-style inter-procedural analysis that semgrep's free rules don't match; semgrep is faster and fully local. For CI gates, prefer semgrep; for release-stage audits, run Snyk Code.
- **vs language-native tools** (`bandit`, `gosec`, `brakeman`): language-native tools are offline, free, and well-tuned for their ecosystem. Use them for the hot-path in CI; layer Snyk Code on top for deeper flow analysis when budget allows.
- **Data leaves the machine**. Snyk Code uploads source for analysis (by default). For regulated codebases, verify with your security policy — or don't enable this module.
