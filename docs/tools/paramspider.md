# ParamSpider Parameter Miner

**Module ID:** `paramspider` | **Category:** Recon | **Binary:** `paramspider`
**Source:** `src/tools/paramspider.rs`

## Overview

ParamSpider mines URLs with query parameters from web archives, discovering potential injection points for SQLi, XSS, SSRF, and other parameter-based attacks. ScorchKit wraps ParamSpider to build a comprehensive list of parameterized URLs that can inform further fuzzing and injection testing.

## Installation

```bash
# pip (recommended)
pip install paramspider

# From source
git clone https://github.com/devanshbatham/ParamSpider.git
cd ParamSpider && pip install .
```

## How ScorchKit Uses It

**Command:** `paramspider -d <domain> --quiet`
**Output format:** Plain text (one parameterized URL per line)
**Timeout:** 120s (2 minutes)

Key flags:
- `-d` -- target domain
- `--quiet` -- suppress banner and informational output

The wrapper resolves the target to a domain before passing it to ParamSpider. Only lines containing both `?` and `=` (indicating query parameters) are included in the results.

## What Gets Parsed

ParamSpider outputs one URL per line. ScorchKit filters for URLs containing query parameters and extracts:

- Total count of parameterized URLs
- Unique parameter names across all URLs (up to 15 displayed)
- Sample of up to 10 parameterized URLs

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| Parameterized URLs Found | Info | Any URLs with query parameters discovered |

All findings are tagged with **OWASP A03:2021 Injection**. Evidence includes the total URL count and unique parameter count. These results identify attack surface for injection testing.

## Configuration

```toml
[tools]
paramspider = "/custom/path/to/paramspider"
```

## Standalone Usage

```bash
# Mine parameters for a domain
paramspider -d example.com

# Quiet mode (suppress banner)
paramspider -d example.com --quiet

# Exclude specific extensions
paramspider -d example.com --exclude png,jpg,gif,css,js

# Output to file
paramspider -d example.com -o params.txt
```
