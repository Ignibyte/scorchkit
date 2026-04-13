# Nikto Web Scanner

**Module ID:** `nikto` | **Category:** Scanner | **Binary:** `nikto`
**Source:** `src/tools/nikto.rs`

## Overview

Nikto is a comprehensive web server scanner that checks for dangerous files, outdated server software, version-specific problems, and server configuration issues. ScorchKit wraps Nikto to perform broad web server vulnerability scanning, complementing Nuclei's template-based approach with Nikto's extensive database of known web server issues.

## Installation

```bash
# Debian / Ubuntu
sudo apt install nikto

# macOS
brew install nikto

# Fedora / RHEL
sudo dnf install nikto

# From source
git clone https://github.com/sullo/nikto.git
```

## How ScorchKit Uses It

**Command:** `nikto -h <target> -Format json -output -`
**Output format:** JSON (streamed to stdout via `-output -`)
**Timeout:** 600s (10 minutes)

The wrapper passes the full target URL to Nikto with JSON output format. The `-output -` flag directs output to stdout for capture.

## What Gets Parsed

ScorchKit handles both single-object and array JSON formats from Nikto. For each vulnerability entry, the following fields are extracted:

- `id` or `OSVDB` -- the Nikto/OSVDB identifier
- `msg` or `message` -- the vulnerability description
- `url` -- the affected URL
- `method` -- the HTTP method used (GET, POST, etc.)

The parser also handles line-by-line JSON as a fallback when the output is not a single valid JSON document.

## Findings Produced

Findings are severity-classified based on keyword analysis of the vulnerability message:

| Severity | Keywords in Message |
|----------|-------------------|
| Critical | remote code, command injection, backdoor, rce |
| High | sql injection, xss, directory traversal, file inclusion |
| Medium | information disclosure, default file, version |
| Low | header, cookie |
| Info | Everything else |

All Nikto findings are tagged with **OWASP A05:2021 Security Misconfiguration**. Evidence includes the Nikto ID, HTTP method, and affected URL.

## Configuration

```toml
[tools]
nikto = "/custom/path/to/nikto"
```

## Standalone Usage

```bash
# Scan with JSON output to stdout
nikto -h https://example.com -Format json -output -

# Scan with HTML report
nikto -h https://example.com -Format htm -output report.html

# Scan specific port
nikto -h example.com -port 8080

# Scan with tuning (specific test types)
nikto -h https://example.com -Tuning 123bde

# Scan with authentication
nikto -h https://example.com -id admin:password
```
