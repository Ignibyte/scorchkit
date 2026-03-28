# WAF Detection (wafw00f)

**Module ID:** `wafw00f` | **Category:** Recon | **Binary:** `wafw00f`
**Source:** `src/tools/wafw00f.rs`

## Overview

wafw00f is a Web Application Firewall (WAF) detection tool. ScorchKit wraps it to identify whether the target is protected by a WAF and, if so, which product is in use. Knowing the WAF helps contextualize scan results -- certain findings may be blocked by the WAF in practice, and the WAF product itself may have known bypass techniques relevant to the assessment.

## Installation

```bash
# pip (recommended)
pip install wafw00f

# pipx (isolated install)
pipx install wafw00f

# From source
git clone https://github.com/EnableSecurity/wafw00f.git
cd wafw00f
python setup.py install
```

## How ScorchKit Uses It

**Command:** `wafw00f <target> -o - -f json`
**Output format:** JSON (streamed to stdout via `-o -`)
**Timeout:** 60s (1 minute)

The wrapper passes the full target URL. The `-o -` flag sends output to stdout, and `-f json` requests JSON format.

## What Gets Parsed

The JSON output is expected as an array of objects. For each entry:

- `firewall` -- the WAF product name (e.g., "Cloudflare", "AWS WAF", "ModSecurity")
- `manufacturer` -- the WAF manufacturer/vendor

If JSON parsing fails, the wrapper falls back to text parsing, looking for:
- Lines containing `is behind` -- indicates a WAF was detected
- Lines containing `No WAF` -- indicates no WAF was found

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| WAF Detected: {waf_name} | Info | WAF identified (firewall field is not "None") |
| WAF Detected | Info | Text output indicates target is behind a WAF |
| No WAF Detected | Info | No WAF was found |

All WAF findings are informational -- the presence or absence of a WAF is useful context for interpreting other scan results but is not a vulnerability in itself.

## Configuration

```toml
[tools]
wafw00f = "/custom/path/to/wafw00f"
```

## Standalone Usage

```bash
# Detect WAF with JSON output
wafw00f https://example.com -o - -f json

# Basic WAF detection
wafw00f https://example.com

# Verbose output
wafw00f https://example.com -v

# Test all WAF fingerprints (not just first match)
wafw00f https://example.com -a

# List all detectable WAFs
wafw00f -l
```
