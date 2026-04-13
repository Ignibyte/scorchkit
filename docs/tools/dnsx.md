# DNSx DNS Toolkit

**Module ID:** `dnsx` | **Category:** Recon | **Binary:** `dnsx`
**Source:** `src/tools/dnsx.rs`

## Overview

DNSx is a fast, multi-purpose DNS toolkit from ProjectDiscovery for DNS resolution, wildcard detection, and multi-record-type queries. ScorchKit wraps DNSx to perform rapid DNS resolution and complement the built-in subdomain module and amass/subfinder wrappers with efficient bulk DNS lookups.

## Installation

```bash
# Go install (recommended)
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Homebrew (macOS / Linux)
brew install dnsx

# Download binary from GitHub releases
# https://github.com/projectdiscovery/dnsx/releases
```

## How ScorchKit Uses It

**Command:** `dnsx -silent -resp -d <domain>`
**Output format:** Plain text (one resolved record per line)
**Timeout:** 120s (2 minutes)

Key flags:
- `-silent` -- suppress banner and informational output
- `-resp` -- display DNS response alongside the domain
- `-d` -- specify the target domain

## What Gets Parsed

DNSx outputs one line per resolved record in the format `domain [IP/record]`. ScorchKit collects all non-empty lines and consolidates them into a single finding with the total count and a sample of up to 10 records.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| DNS Records Resolved | Info | Any DNS records resolved |

All findings are tagged with **OWASP A05:2021 Security Misconfiguration**. Evidence includes the total record count and sample entries.

## Configuration

```toml
[tools]
dnsx = "/custom/path/to/dnsx"
```

## Standalone Usage

```bash
# Resolve a domain with response display
dnsx -silent -resp -d example.com

# Resolve multiple record types
dnsx -silent -resp -a -aaaa -mx -ns -d example.com

# Bulk resolution from a file
cat subdomains.txt | dnsx -silent -resp

# Wildcard detection
dnsx -wd example.com
```
