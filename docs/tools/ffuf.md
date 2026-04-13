# ffuf Web Fuzzer

**Module ID:** `ffuf` | **Category:** Recon | **Binary:** `ffuf`
**Source:** `src/tools/ffuf.rs`

## Overview

ffuf (Fuzz Faster U Fool) is a fast web fuzzer written in Go. ScorchKit wraps ffuf for content discovery, using it to find hidden directories, files, and endpoints by fuzzing URL paths with a wordlist. ffuf complements feroxbuster by providing an alternative discovery approach with different matching and filtering capabilities.

## Installation

```bash
# Go install (recommended)
go install github.com/ffuf/ffuf/v2@latest

# Homebrew (macOS / Linux)
brew install ffuf

# Debian / Ubuntu (if available)
sudo apt install ffuf

# Download binary from GitHub releases
# https://github.com/ffuf/ffuf/releases
```

## How ScorchKit Uses It

**Command:** `ffuf -u <target>/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -fc 404 -t 20 -maxtime 120 -o /dev/stdout -of json -s`
**Output format:** JSON
**Timeout:** 180s (3 minutes)

Key flags:
- `-u <target>/FUZZ` -- URL with FUZZ keyword as the injection point
- `-w /usr/share/wordlists/dirb/common.txt` -- default wordlist (DIRB common)
- `-mc 200,301,302,403` -- match these HTTP status codes
- `-fc 404` -- filter out 404 responses
- `-t 20` -- 20 concurrent threads
- `-maxtime 120` -- stop after 120 seconds
- `-o /dev/stdout -of json` -- JSON output to stdout
- `-s` -- silent mode (no progress output)

The wrapper uses `ctx.target.base_url()` to construct the fuzz URL, appending `/FUZZ` as the injection point.

## What Gets Parsed

The JSON output is parsed from the `results` array. For each result:

- `url` -- the discovered URL
- `status` -- HTTP status code
- `length` -- response body length in bytes
- `input.FUZZ` -- the wordlist entry that produced the match

## Findings Produced

All ffuf discoveries are reported as **Info** severity:

| Finding | Severity | Details |
|---------|----------|---------|
| Discovered: /{fuzz_input} | Info | Path found via wordlist fuzzing |

Evidence includes the HTTP status code and response size in bytes. All findings are tagged with **OWASP A05:2021 Security Misconfiguration**.

Results are sorted by severity and truncated to the top 50 findings.

## Configuration

```toml
[tools]
ffuf = "/custom/path/to/ffuf"
```

## Standalone Usage

```bash
# Basic directory discovery
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Fuzz with extensions
ffuf -u https://example.com/FUZZ -w wordlist.txt -e .php,.asp,.html,.js

# Fuzz POST parameters
ffuf -u https://example.com/login -X POST -d "user=admin&pass=FUZZ" -w passwords.txt

# Fuzz with custom headers
ffuf -u https://example.com/FUZZ -w wordlist.txt -H "Authorization: Bearer token"

# Filter by response size
ffuf -u https://example.com/FUZZ -w wordlist.txt -fs 4242

# Virtual host discovery
ffuf -u https://example.com -w subdomains.txt -H "Host: FUZZ.example.com"

# JSON output to file
ffuf -u https://example.com/FUZZ -w wordlist.txt -of json -o results.json
```
