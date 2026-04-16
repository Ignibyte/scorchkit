# Gitleaks

Hardcoded-secret scanner — detects exposed API keys, tokens, and credentials in source code and git history using a large regex ruleset plus entropy heuristics. License: MIT (upstream: [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)).

## Install

```
go install github.com/gitleaks/gitleaks/v8@latest
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `gitleaks detect --source <path> --report-format json --report-path /dev/stdout --no-git` and iterates the emitted array. Every leak is **High** severity:

- **Title**: `Exposed secret: <description>` (e.g. `Exposed secret: AWS Access Key`)
- **Description**: `Hardcoded <description> detected by rule <rule-id>`
- **Affected**: `<file>:<line>`
- **Evidence**: `Matched: <first 8 chars>... (redacted)` — full secret is never written to the finding
- **OWASP**: A07:2021 Identification and Authentication Failures
- **CWE**: 798 (Use of Hard-coded Credentials)
- **Confidence**: scaled by Shannon entropy — 0.9 for `entropy > 4.5`, 0.8 for `> 3.5`, 0.7 otherwise

Remediation instructs operators to remove the secret, **rotate the credential immediately** (the commit history leaks it regardless of later edits), and move to environment variables or a secrets manager.

## How to run

```
scorchkit code /path/to/source --modules gitleaks
```

120s timeout. `--no-git` means this wrapper scans the working tree, not the commit history. For history-depth scanning, invoke gitleaks directly (omit `--no-git`).

## Limitations vs alternatives

- **vs `trufflehog`**: trufflehog ships with verification (it can attempt to validate a detected AWS key against the AWS API); gitleaks is pattern-only. Run both — trufflehog confirms liveness, gitleaks catches a wider set of formats.
- **History scanning disabled** in this wrapper for speed. A leaked secret already pushed to a public repo is already exposed; rotate regardless of whether current HEAD contains it.
- **Entropy thresholds are generic**. Noise level depends on the codebase — test fixtures, base64-encoded assets, and UUID constants can trigger false positives. Tune via a `.gitleaks.toml` config file (invoke gitleaks directly).
