# Interactsh OOB Detection

**Module ID:** `interactsh` | **Category:** Scanner | **Binary:** `interactsh-client`
**Source:** `src/tools/interactsh.rs`

## Overview

Interactsh is an out-of-band (OOB) interaction detection tool from ProjectDiscovery. ScorchKit uses the `interactsh-client` to detect blind vulnerabilities -- SSRF, XXE, RCE, and SQLi -- by injecting callback URLs into target parameters and monitoring for DNS/HTTP interactions that confirm exploitability. This is one of the most powerful detection techniques for vulnerabilities that produce no visible response.

## Installation

```bash
# Go install (recommended)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Homebrew (macOS / Linux)
brew install interactsh

# Download binary from GitHub releases
# https://github.com/projectdiscovery/interactsh/releases
```

## How ScorchKit Uses It

**Workflow:** Start session -> inject OOB payloads -> poll for interactions -> correlate -> stop session
**Output format:** Internal OOB interaction protocol (managed via `InteractshSession`)
**Poll wait:** 10 seconds after injection

The module operates differently from other tool wrappers. Rather than running a single command, it:

1. Starts an `interactsh-client` session to get a unique callback domain
2. Generates blind payloads for SSRF, XXE, RCE, and SQLi categories
3. Injects payloads into existing query parameters or common parameter names (`url`, `redirect`, `page`, `cmd`, `query`, `input`, `data`)
4. Sends an XXE payload via POST with `Content-Type: application/xml`
5. Polls for OOB interactions and correlates them to injected payloads

## Findings Produced

| Finding | Severity | Category | CWE |
|---------|----------|----------|-----|
| Blind SSRF Confirmed | Critical | SSRF | CWE-918 |
| Blind XXE Confirmed | Critical | XXE | CWE-611 |
| Blind RCE Confirmed | Critical | RCE | CWE-78 |
| Blind SQLi Confirmed | High | SQLi | CWE-89 |

Each confirmed finding includes the OOB callback protocol, correlation ID, and remote address as evidence. Findings are tagged with their respective OWASP categories:
- SSRF: **A10:2021 Server-Side Request Forgery**
- XXE: **A05:2021 Security Misconfiguration**
- RCE/SQLi: **A03:2021 Injection**

## Configuration

```toml
[tools]
interactsh-client = "/custom/path/to/interactsh-client"
```

## Standalone Usage

```bash
# Start an interactive client session
interactsh-client

# Generate a unique URL and use it in testing
interactsh-client -v

# Use a self-hosted server
interactsh-client -server https://your-interactsh-server.com
```
