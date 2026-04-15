# EyeWitness

Visual recon — captures browser screenshots of the target. The highest-signal artifact for human review: default installs, login pages, and exposed admin panels that don't fit in a finding's text field. License: GPL-3.0 (upstream: [RedSiege/EyeWitness](https://github.com/RedSiege/EyeWitness)).

## Install

```
apt install eyewitness    # Debian / Kali
# or: git clone https://github.com/RedSiege/EyeWitness && ./setup/setup.sh
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper writes the target URL into a temp file and runs `eyewitness -f <file> -d <out-dir> --no-prompt --web`. EyeWitness writes `report.html` plus per-target PNGs to the output dir. If `report.html` exists, the wrapper emits one **Info** finding:

- **Title**: `EyeWitness: screenshot captured for <url>`
- **Evidence**: `EyeWitness output dir: /tmp/... | report.html: /tmp/.../report.html`
- **OWASP**: A05:2021 Security Misconfiguration
- **Confidence**: 0.8

The screenshot image itself is **not** embedded in the report — the finding points operators at the temp file. For persistent archival, copy the output directory somewhere durable before the scan's temp dirs are reaped.

## How to run

```
scorchkit run https://target.example.com --modules eyewitness
```

120s timeout. Requires a headless browser (EyeWitness bundles one on install).

## Limitations vs alternatives

- **Screenshots live in temp storage**. No persistence hook yet — operators who want every scan's screenshots should either copy the out_dir mid-run or run EyeWitness directly with a named `-d <persistent-dir>`.
- **One target per invocation**. EyeWitness supports bulk URL lists; this wrapper feeds only the single scan target. For portfolio screenshotting, run it directly with an `httpx`-filtered list.
- **No OCR / no diffing**. Value is entirely human-review — ScorchKit's `diff` command doesn't currently compare screenshot sets.
