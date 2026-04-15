# Wapiti

Batteries-included web vulnerability scanner — SQLi, XSS, command injection, file disclosure, CRLF, SSRF, XXE, and more. Alternative to OWASP ZAP with a smaller footprint. License: GPL-2.0 (upstream: [wapiti-scanner/wapiti](https://github.com/wapiti-scanner/wapiti)).

## Install

```
pipx install wapiti3
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `wapiti -u <url> -f json -o <temp.json>`, reads the emitted JSON report, and converts each entry in `vulnerabilities.<category>[]` into its own finding. Wapiti's `level` (1-4) maps to severity:

| Wapiti level | ScorchKit severity |
|---|---|
| 4 | High |
| 3 | Medium |
| 2 | Low |
| 1 or other | Info |

Each finding carries:

- **Title**: `Wapiti <category>: <method> <path>` (e.g. `Wapiti SQL Injection: GET /?id=1`)
- **Evidence**: `category=... method=... path=...`
- **OWASP**: A03:2021 Injection (default — category is recorded in evidence for triage)
- **Confidence**: 0.85

## How to run

```
scorchkit run https://target.example.com --modules wapiti
```

300s timeout (5 min). Wapiti crawls + fuzzes, so expect a full run on non-trivial targets.

## Limitations vs alternatives

- **vs `zap`**: OWASP ZAP is the heavyweight — more modules, proxy mode, passive scanning, scripting. Wapiti is lighter and easier to run headless. Use both; they have different strength profiles.
- **vs `nuclei`**: nuclei is template-based (known CVEs + misconfigs); wapiti is traffic-based (fuzzing forms + parameters). Complementary, not redundant.
- The OWASP tag is hardcoded to A03:2021 Injection because most Wapiti categories are injection-flavored. Richer mapping would require a per-category lookup; not yet implemented.
