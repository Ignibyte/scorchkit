# Arjun Parameter Discovery

**Module ID:** `arjun` | **Category:** Recon | **Binary:** `arjun`
**Source:** `src/tools/arjun.rs`

## Overview

Arjun is an HTTP parameter discovery tool that finds hidden or undocumented query and body parameters accepted by a web application. ScorchKit wraps Arjun to uncover parameters that may not be visible in the application's UI but could be vulnerable to injection attacks. Discovered parameters feed into further testing by tools like SQLMap and Dalfox.

## Installation

```bash
# pip (recommended)
pip install arjun

# pipx (isolated install)
pipx install arjun

# From source
git clone https://github.com/s0md3v/Arjun.git
cd Arjun
pip install -r requirements.txt
```

## How ScorchKit Uses It

**Command:** `arjun -u <target> --json /dev/stdout -q`
**Output format:** JSON
**Timeout:** 120s (2 minutes)

Key flags:
- `-u` -- target URL
- `--json /dev/stdout` -- JSON output to stdout
- `-q` -- quiet mode (suppress progress output)

## What Gets Parsed

**JSON mode:** The output is a JSON object where keys are URLs and values are arrays of discovered parameter names:

```json
{
  "https://example.com/page": ["id", "name", "action", "debug"]
}
```

For each URL, the array of parameter names is extracted.

**Text fallback:** If JSON parsing fails, the wrapper scans lines for keywords "parameter" or "param" and includes those as informational findings.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| {count} Hidden Parameters Found | Low | JSON output contains discovered parameters |
| Parameters Discovered | Info | Text output mentions parameters |

Each finding includes:
- **Evidence:** Comma-separated list of discovered parameter names
- **Remediation:** "Test discovered parameters for injection vulnerabilities"

## Configuration

```toml
[tools]
arjun = "/custom/path/to/arjun"
```

## Standalone Usage

```bash
# Discover parameters for a URL
arjun -u https://example.com/page --json /dev/stdout

# Discover parameters with custom wordlist
arjun -u https://example.com/page -w custom_params.txt

# Test POST parameters
arjun -u https://example.com/api -m POST

# Test JSON body parameters
arjun -u https://example.com/api -m JSON

# Include headers
arjun -u https://example.com/page -H "Cookie: session=abc123"

# Set thread count
arjun -u https://example.com/page -t 10

# Multiple URLs from file
arjun -i urls.txt --json output.json
```
