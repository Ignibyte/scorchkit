# LinkFinder

JavaScript endpoint extractor — mines URLs and API paths out of bundled JS. License: MIT (upstream: [GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder)).

## Install

```
pipx install linkfinder
# or: git clone https://github.com/GerbenJavado/LinkFinder
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `linkfinder -i <url> -o cli` (prints one URL per line) and aggregates every non-empty, non-bracketed line into a single **Info** finding:

- **Title**: `LinkFinder: N endpoint(s) extracted from JavaScript`
- **Evidence**: `Sample: /api/v1/users, /api/v1/sessions, /admin/dashboard, ...` (first 50 endpoints)
- **OWASP**: A05:2021 Security Misconfiguration
- **Confidence**: 0.85

Remediation recommends auditing each discovered endpoint for auth, authz, and input validation — some may be intended as internal-only.

## How to run

```
scorchkit run https://target.example.com --modules linkfinder
```

120s timeout.

## Limitations vs alternatives

- **vs built-in `js_analysis` recon module**: built-in extracts endpoints via lighter regexes; LinkFinder uses a deeper heuristic set and catches more. Run both.
- **vs `katana`**: katana is a full crawler that executes JS and captures runtime traffic; LinkFinder is a static extractor over fetched JS files. Use LinkFinder when you have the JS but can't run a headless browser (CI environments); use katana when you can.
- **vs `vespasian`**: vespasian goes further still — runtime browser + API spec synthesis. LinkFinder is the cheapest option of the three.
- No URL resolution — relative paths are reported as-is. Operators join them to the base URL themselves.
