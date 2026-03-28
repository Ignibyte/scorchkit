# Nuclei Vulnerability Scanner

**Module ID:** `nuclei` | **Category:** Scanner | **Binary:** `nuclei`
**Source:** `src/tools/nuclei.rs`

## Overview

Nuclei is a template-based vulnerability scanner from ProjectDiscovery. It uses a massive community-maintained library of YAML templates to detect CVEs, misconfigurations, exposed panels, default credentials, and more. ScorchKit wraps Nuclei to perform broad vulnerability detection across all severity levels, parsing structured results into normalized findings with OWASP and CWE mappings.

## Installation

```bash
# Go install (recommended, gets latest)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Homebrew (macOS / Linux)
brew install nuclei

# Download binary from GitHub releases
# https://github.com/projectdiscovery/nuclei/releases

# Update templates after install
nuclei -update-templates
```

## How ScorchKit Uses It

**Command:** `nuclei -u <target> -jsonl -silent -severity critical,high,medium,low -no-color`
**Output format:** JSON-lines (one JSON object per line)
**Timeout:** 600s (10 minutes)

The wrapper runs Nuclei against the full target URL. The `-jsonl` flag produces machine-parseable JSON-lines output. The `-silent` and `-no-color` flags suppress banner and ANSI escape codes. All severity levels from low to critical are included.

## What Gets Parsed

Each JSON line is parsed for the following fields:

- `template-id` -- the template identifier (e.g., `cve-2021-44228-log4j-rce`)
- `info.name` -- human-readable vulnerability name
- `info.description` -- detailed description
- `info.severity` -- severity level (critical/high/medium/low/info)
- `matched-at` -- the URL where the vulnerability was found
- `matcher-name` -- specific matcher that triggered
- `extracted-results` -- data extracted by the template (up to 3 items)
- `info.tags` -- template tags used for OWASP mapping
- `info.reference` -- external references (CVE links, advisories)
- `info.classification.cwe-id` -- CWE identifiers

## Findings Produced

Nuclei produces findings at all severity levels depending on which templates match. Each finding includes:

| Field | Value |
|-------|-------|
| Title | `{vulnerability name} [{template-id}]` |
| Severity | Mapped from Nuclei's severity (critical/high/medium/low/info) |
| Evidence | Template ID, matcher name, and up to 3 extracted results |
| OWASP | Automatically mapped from template tags (see below) |
| CWE | Extracted from template classification when available |
| Remediation | Populated from template references (first 2 links) |

**Tag-to-OWASP mapping:**

- `sqli`, `injection`, `xss`, `ssti` -- A03:2021 Injection
- `auth`, `default-login`, `brute` -- A07:2021 Identification and Authentication Failures
- `misconfig`, `exposure`, `disclosure` -- A05:2021 Security Misconfiguration
- `cve`, `outdated` -- A06:2021 Vulnerable and Outdated Components
- `ssl`, `tls`, `crypto` -- A02:2021 Cryptographic Failures
- `ssrf` -- A10:2021 Server-Side Request Forgery
- `idor`, `access-control` -- A01:2021 Broken Access Control

## Configuration

```toml
[tools]
nuclei = "/custom/path/to/nuclei"
```

## Standalone Usage

```bash
# Scan a target with JSON-lines output
nuclei -u https://example.com -jsonl -silent

# Scan with specific severity filter
nuclei -u https://example.com -severity critical,high

# Scan with specific templates
nuclei -u https://example.com -t cves/ -t misconfigurations/

# Scan with rate limiting
nuclei -u https://example.com -rate-limit 50 -jsonl

# Scan multiple targets from a file
nuclei -l targets.txt -jsonl -o results.jsonl
```
