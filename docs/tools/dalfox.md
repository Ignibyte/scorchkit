# Dalfox XSS Scanner

**Module ID:** `dalfox` | **Category:** Scanner | **Binary:** `dalfox`
**Source:** `src/tools/dalfox.rs`

## Overview

Dalfox is a powerful open-source XSS (Cross-Site Scripting) scanner written in Go. It performs parameter analysis, DOM-based XSS detection, and reflected XSS scanning with advanced payload generation. ScorchKit wraps Dalfox for targeted XSS testing, complementing the built-in XSS module with Dalfox's extensive payload library and DOM analysis capabilities.

## Installation

```bash
# Go install (recommended)
go install github.com/hahwul/dalfox/v2@latest

# Homebrew (macOS / Linux)
brew install dalfox

# Snap
sudo snap install dalfox

# Download binary from GitHub releases
# https://github.com/hahwul/dalfox/releases
```

## How ScorchKit Uses It

**Command:** `dalfox url <target> --format json --silence`
**Output format:** JSON-lines (one JSON object per line)
**Timeout:** 300s (5 minutes)

Key flags:
- `url` -- scan a single URL
- `--format json` -- JSON output format
- `--silence` -- suppress non-essential output

## What Gets Parsed

Each JSON line is parsed for:

- `data` or `message` -- description of the finding
- `type` -- finding type (`V` for verified vulnerability, other values for informational)
- `poc` -- proof-of-concept payload URL
- `param` -- the vulnerable parameter name

## Findings Produced

| Finding | Severity | CWE | Condition |
|---------|----------|-----|-----------|
| Dalfox XSS: {param} | High | 79 | Type is `V` (verified XSS) |
| Dalfox XSS: {param} | Info | 79 | Any other finding type |

Each finding includes:
- **OWASP:** A03:2021 Injection
- **CWE:** 79 (Improper Neutralization of Input During Web Page Generation)
- **Evidence:** The proof-of-concept URL (when available)

## Configuration

```toml
[tools]
dalfox = "/custom/path/to/dalfox"
```

## Standalone Usage

```bash
# Scan a single URL
dalfox url "https://example.com/search?q=test" --format json

# Scan with a custom payload file
dalfox url "https://example.com/search?q=test" --custom-payload payloads.txt

# Pipe mode (from stdin)
echo "https://example.com/search?q=test" | dalfox pipe

# Scan multiple URLs from file
dalfox file urls.txt --format json

# Scan with specific options
dalfox url "https://example.com/search?q=test" --blind https://your-callback.xss.ht --format json

# Scan with cookie/header
dalfox url "https://example.com/search?q=test" -H "Cookie: session=abc123"

# Mining mode (DOM analysis without active scanning)
dalfox url "https://example.com" --mining-dom
```
