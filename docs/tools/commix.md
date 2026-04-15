# commix

Command-injection detection + exploitation. Complements ScorchKit's built-in `cmdi` scanner (detection-only) with deeper exploitation primitives. License: GPL-3.0 (upstream: [commixproject/commix](https://github.com/commixproject/commix)).

## Install

```
pipx install commix
# or: git clone https://github.com/commixproject/commix
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `commix -u <url> --batch --skip-waf` (non-interactive) and parses stdout for lines matching `[+] ... vulnerable`. Any positive detection yields one aggregate **High** finding:

- **Title**: `commix: command injection confirmed on <url>`
- **Evidence**: joined `[+] ...vulnerable` lines (e.g. `[+] Type: results-based...`)
- **OWASP**: A03:2021 Injection
- **CWE**: 78 (OS Command Injection)
- **Confidence**: 0.95

commix is high-confidence: when it says vulnerable, it has already demonstrated exploitation.

## How to run

```
scorchkit run https://target.example.com --modules commix
```

180s timeout.

## Limitations vs alternatives

- **vs built-in `cmdi`**: the built-in module is a lightweight payload-based detector; commix runs a deeper fuzzer and confirms exploitability. Run `cmdi` for broad coverage and commix on a shortlist.
- **Default `--batch` mode** picks sensible defaults and never prompts. Operators who need custom techniques (`--technique=T` for time-based, `--os-cmd=...` for specific payloads) invoke commix directly.
- **`--skip-waf`** disables commix's WAF-bypass heuristics; enable them manually if the target sits behind Cloudflare / AWS WAF.
