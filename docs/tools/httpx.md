# httpx HTTP Prober

**Module ID:** `httpx` | **Category:** Recon | **Binary:** `httpx`
**Source:** `src/tools/httpx.rs`

## Overview

httpx is a fast, multi-purpose HTTP toolkit from ProjectDiscovery. ScorchKit wraps it for HTTP technology probing -- detecting web servers, frameworks, CDN usage, page titles, and technology stacks. This reconnaissance data helps ScorchKit determine which further scanning modules are relevant (e.g., running WPScan only if WordPress is detected).

> **NOTE:** ProjectDiscovery's httpx (Go binary) conflicts with the Python `httpx` HTTP library. Make sure the Go binary is in your PATH and takes precedence. You can verify with `which httpx` -- it should point to the Go binary, not a Python package.

## Installation

```bash
# Go install (recommended)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Homebrew (macOS / Linux)
brew install httpx

# Download binary from GitHub releases
# https://github.com/projectdiscovery/httpx/releases
```

**Important:** If you have the Python `httpx` package installed, ensure the Go binary appears first in your PATH:
```bash
# Check which httpx is being used
which httpx
# Should output something like: /home/user/go/bin/httpx (Go binary)
# NOT: /usr/local/bin/httpx or a Python path
```

## How ScorchKit Uses It

**Command:** `httpx -u <domain> -json -silent -tech-detect -status-code -title -web-server -cdn`
**Output format:** JSON-lines (one JSON object per line)
**Timeout:** 60s (1 minute)

Key flags:
- `-u` -- target domain
- `-json` -- JSON output
- `-silent` -- suppress banner and progress
- `-tech-detect` -- detect web technologies (via Wappalyzer signatures)
- `-status-code` -- include HTTP status code
- `-title` -- extract page title
- `-web-server` -- identify web server
- `-cdn` -- detect CDN usage

**Domain requirement:** The wrapper requires a domain to be extracted from the target URL. If no domain is available, a `ScorchError::InvalidTarget` error is returned.

## What Gets Parsed

Each JSON line is parsed for:

- `url` -- the probed URL
- `title` -- HTML page title
- `webserver` -- web server header (e.g., nginx, Apache)
- `tech` -- array of detected technologies (e.g., jQuery, PHP, WordPress)
- `cdn` -- boolean indicating CDN usage

Only lines with at least one non-empty evidence field produce findings.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| httpx Probe Results | Info | At least one piece of evidence extracted |

The evidence string combines all detected information, pipe-separated:
- `Title: {page_title}`
- `Server: {web_server}`
- `Tech: {technology1, technology2, ...}`
- `CDN: yes` (when CDN is detected)

## Configuration

```toml
[tools]
httpx = "/custom/path/to/httpx"
```

## Standalone Usage

```bash
# Probe a single domain
httpx -u example.com -json -silent -tech-detect -status-code -title -web-server -cdn

# Probe multiple domains from a file
cat domains.txt | httpx -json -silent -tech-detect

# Probe with all detection features
httpx -u example.com -json -silent -tech-detect -status-code -title -web-server -cdn -ip -cname -asn

# Screenshot capture
httpx -u example.com -screenshot

# Filter by status code
cat domains.txt | httpx -mc 200,301 -silent

# Follow redirects
httpx -u example.com -follow-redirects -json -silent
```
