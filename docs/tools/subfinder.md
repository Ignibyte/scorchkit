# Subfinder

**Module ID:** `subfinder` | **Category:** Recon | **Binary:** `subfinder`
**Source:** `src/tools/subfinder.rs`

## Overview

Subfinder is a fast passive subdomain discovery tool from ProjectDiscovery. It uses multiple search engines, certificate transparency logs, and online APIs to enumerate subdomains without actively querying the target. ScorchKit wraps Subfinder as a lightweight, fast alternative to Amass for subdomain enumeration, often completing in seconds rather than minutes.

## Installation

```bash
# Go install (recommended)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Homebrew (macOS / Linux)
brew install subfinder

# Download binary from GitHub releases
# https://github.com/projectdiscovery/subfinder/releases
```

## How ScorchKit Uses It

**Command:** `subfinder -d <domain> -silent -json`
**Output format:** JSON-lines or plain text (the parser handles both)
**Timeout:** 120s (2 minutes)

Key flags:
- `-d` -- target domain
- `-silent` -- suppress banner and status output
- `-json` -- JSON output mode

**Domain requirement:** The wrapper requires a domain to be extracted from the target URL. If no domain is available, a `ScorchError::InvalidTarget` error is returned.

## What Gets Parsed

The parser handles two output formats:

**JSON mode:** Each line is parsed as JSON, extracting the `host` field.

**Plain text fallback:** If JSON parsing fails, each non-empty line containing a `.` is treated as a subdomain.

Duplicates are removed in both modes. The collected subdomains are sorted alphabetically and truncated to the first 100 entries for the evidence field.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| {count} Subdomains Found (Subfinder) | Info | At least one subdomain discovered |

The finding includes:
- **Title:** `{count} Subdomains Found (Subfinder)`
- **Description:** Summary with total count
- **Evidence:** Newline-separated list of discovered subdomains (up to 100)

No findings are produced if zero subdomains are found.

## Configuration

```toml
[tools]
subfinder = "/custom/path/to/subfinder"
```

## Standalone Usage

```bash
# Basic subdomain discovery
subfinder -d example.com -silent

# JSON output
subfinder -d example.com -silent -json

# Save to file
subfinder -d example.com -o subdomains.txt

# Use specific sources only
subfinder -d example.com -sources crtsh,dnsdumpster,hackertarget

# Recursive enumeration
subfinder -d example.com -recursive

# Multiple domains
subfinder -dL domains.txt -silent

# With rate limiting
subfinder -d example.com -rate-limit 5

# Configure API keys (in ~/.config/subfinder/provider-config.yaml)
# See: subfinder -ls to list available sources
```
