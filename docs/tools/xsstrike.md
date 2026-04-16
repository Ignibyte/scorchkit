# XSStrike

Advanced XSS scanner covering reflected, DOM, and (with extra flags) blind XSS, with built-in WAF fingerprinting and payload mutation. License: unlicensed / source-available (upstream: [s0md3v/XSStrike](https://github.com/s0md3v/XSStrike) — consult the repo before redistribution).

## Install

```
pipx install xsstrike
# or: git clone https://github.com/s0md3v/XSStrike
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `xsstrike -u <url> --skip` (no confirmation prompts) and scans stdout for `Payload:` or `Vulnerable webpage:` markers. Any hit yields one aggregate **High** finding:

- **Title**: `XSStrike: XSS payload landed on <url>`
- **Evidence**: concatenated payload / webpage lines
- **OWASP**: A03:2021 Injection
- **CWE**: 79 (Cross-site Scripting)
- **Confidence**: 0.9

Remediation recommends context-aware output encoding plus a strict CSP.

## How to run

```
scorchkit run https://target.example.com --modules xsstrike
```

180s timeout.

## Limitations vs alternatives

- **vs `dalfox`**: dalfox is Go-based, faster, and produces machine-readable output; XSStrike is Python-based with smarter payload mutation and better DOM XSS heuristics. Run both on important targets — they find different things.
- **vs built-in `xss` module**: the built-in scanner is a quick reflected-XSS checker; XSStrike goes deeper (mutation fuzzing, WAF evasion). Treat it as the heavyweight option.
- Blind XSS requires explicit `--blind` and an out-of-band callback; not enabled by default in this wrapper. Use the `interactsh` module as a correlated callback receiver when chaining manually.
