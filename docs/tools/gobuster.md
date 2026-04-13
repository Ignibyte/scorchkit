# Gobuster Directory Scanner

**Module ID:** `gobuster` | **Category:** Recon | **Binary:** `gobuster`
**Source:** `src/tools/gobuster.rs`

## Overview

Gobuster is a fast brute-forcing tool for discovering directories, files, DNS subdomains, and virtual hosts on web servers. ScorchKit wraps Gobuster in directory mode to discover hidden paths and endpoints, complementing the feroxbuster and ffuf wrappers. Each discovered path is individually reported with severity based on its HTTP status code.

## Installation

```bash
# Go install (recommended)
go install github.com/OJ/gobuster/v3@latest

# Debian / Ubuntu
sudo apt install gobuster

# Homebrew (macOS)
brew install gobuster

# Download binary from GitHub releases
# https://github.com/OJ/gobuster/releases
```

## How ScorchKit Uses It

**Command:** `gobuster dir -u <target> -w /usr/share/wordlists/dirb/common.txt -q --no-error --no-color`
**Output format:** Plain text (quiet mode, one result per line)
**Timeout:** 300s (5 minutes)

Key flags:
- `dir` -- directory/file brute-forcing mode
- `-w` -- wordlist path (uses dirb common.txt by default)
- `-q` -- quiet mode (suppress banner)
- `--no-error` -- suppress error messages
- `--no-color` -- disable ANSI color codes

## What Gets Parsed

Gobuster quiet mode outputs one line per discovered path in the format `/path (Status: 200) [Size: 1234]`. ScorchKit parses each line for:

- Path -- extracted from the beginning of the line
- HTTP status code -- extracted from `Status: NNN`

Each discovered path becomes its own finding, unlike feroxbuster which consolidates results.

## Findings Produced

| Severity | HTTP Status | Meaning |
|----------|-------------|---------|
| Low | 401, 403 | Forbidden/unauthorized (access control in place) |
| Medium | 500-599 | Server errors (potential misconfigurations) |
| Info | All others (200, 301, etc.) | Accessible content |

All findings are tagged with **OWASP A01:2021 Broken Access Control**. Evidence includes the full output line with status code and response size.

## Configuration

```toml
[tools]
gobuster = "/custom/path/to/gobuster"
```

## Standalone Usage

```bash
# Directory brute-force with common wordlist
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt

# With file extensions
gobuster dir -u https://example.com -w wordlist.txt -x php,asp,html

# Virtual host enumeration
gobuster vhost -u https://example.com -w vhosts.txt

# DNS subdomain brute-force
gobuster dns -d example.com -w subdomains.txt

# Adjust threads and timeout
gobuster dir -u https://example.com -w wordlist.txt -t 50 --timeout 10s
```
