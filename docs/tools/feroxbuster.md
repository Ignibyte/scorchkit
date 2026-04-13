# Feroxbuster Directory Scanner

**Module ID:** `feroxbuster` | **Category:** Recon | **Binary:** `feroxbuster`
**Source:** `src/tools/feroxbuster.rs`

## Overview

Feroxbuster is a fast, recursive content discovery tool written in Rust. ScorchKit wraps it to discover hidden directories, files, and endpoints on the target web server. Unlike simple directory brute-forcers, feroxbuster recursively scans discovered directories, uncovering deeply nested content. Discovered paths are severity-classified based on their nature (exposed secrets, admin panels, API documentation, etc.).

## Installation

```bash
# Debian / Ubuntu
sudo apt install feroxbuster

# Cargo (Rust)
cargo install feroxbuster

# macOS
brew install feroxbuster

# Download binary from GitHub releases
# https://github.com/epi052/feroxbuster/releases
```

## How ScorchKit Uses It

**Command:** `feroxbuster -u <target> --json -q --no-state -t 20 --time-limit 5m -C 404,403`
**Output format:** JSON-lines (one JSON object per line)
**Timeout:** 360s (6 minutes)

Key flags:
- `--json` -- JSON-lines output for machine parsing
- `-q` -- quiet mode (suppress banner)
- `--no-state` -- disable state file creation
- `-t 20` -- 20 concurrent threads
- `--time-limit 5m` -- hard stop after 5 minutes
- `-C 404,403` -- filter out 404 and 403 responses

## What Gets Parsed

Each JSON line with `"type": "response"` is parsed for:

- `url` -- the discovered URL
- `status` -- HTTP status code
- `content_length` -- response body size in bytes

Lines with other types (statistics, errors) are skipped. Results are sorted by severity and truncated to the top 50 most interesting findings.

## Findings Produced

Discovered paths are classified by URL pattern:

| Severity | URL Pattern | Category |
|----------|-------------|----------|
| Critical | `.env`, `backup`, `.sql`, `dump`, `.key`, `credentials` | secrets/backup |
| High | `.git`, `.svn`, `config`, `phpinfo`, `server-status`, `server-info` | configuration/source |
| Medium | `admin`, `debug`, `console`, `dashboard`, `manager` | admin/management |
| Low | `api`, `swagger`, `graphql`, `docs` | api/docs |
| Info | Everything else | content |

All findings are tagged with **OWASP A05:2021 Security Misconfiguration**. Evidence includes the HTTP status code, response size, and classification category.

## Configuration

```toml
[tools]
feroxbuster = "/custom/path/to/feroxbuster"
```

## Standalone Usage

```bash
# Basic recursive scan with JSON output
feroxbuster -u https://example.com --json -q

# Scan with a custom wordlist
feroxbuster -u https://example.com -w /path/to/wordlist.txt

# Scan with extensions
feroxbuster -u https://example.com -x php,asp,aspx,jsp,html,js

# Scan with authentication
feroxbuster -u https://example.com -H "Authorization: Bearer token123"

# Limit depth and threads
feroxbuster -u https://example.com -d 3 -t 10 --time-limit 10m
```
