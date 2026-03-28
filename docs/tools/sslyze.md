# SSLyze TLS Analyzer

**Module ID:** `sslyze` | **Category:** Scanner | **Binary:** `sslyze`
**Source:** `src/tools/sslyze.rs`

## Overview

SSLyze is a fast and comprehensive TLS/SSL configuration analyzer. ScorchKit wraps SSLyze to assess the security of a target's TLS configuration, checking for deprecated protocols, weak cipher suites, certificate trust issues, and critical vulnerabilities like Heartbleed and ROBOT. This complements ScorchKit's built-in SSL module with deeper protocol-level analysis.

## Installation

```bash
# pip (recommended)
pip install sslyze

# pipx (isolated install)
pipx install sslyze
```

## How ScorchKit Uses It

**Command:** `sslyze --json_out=- <target:port>`
**Output format:** JSON (streamed to stdout via `--json_out=-`)
**Timeout:** 300s (5 minutes)

The wrapper constructs the target as `domain:port`. If the target port is 443, only the domain is passed. For non-standard ports, the `domain:port` format is used. A fallback text parser handles older SSLyze versions that may not produce JSON.

## What Gets Parsed

The JSON output is parsed from `server_scan_results[]`, extracting:

**Protocol support:**
- `ssl_2_0_cipher_suites` -- SSL 2.0 accepted cipher suites
- `ssl_3_0_cipher_suites` -- SSL 3.0 accepted cipher suites
- `tls_1_0_cipher_suites` -- TLS 1.0 accepted cipher suites
- `tls_1_1_cipher_suites` -- TLS 1.1 accepted cipher suites

For each deprecated protocol, up to 5 accepted cipher suite names are included as evidence.

**Certificate validation:**
- `certificate_deployments[].path_validation_results` -- whether the certificate chain is trusted by all certificate stores

**Vulnerability checks:**
- `heartbleed.result.is_vulnerable_to_heartbleed` -- Heartbleed (CVE-2014-0160)
- `robot.result.robot_result` -- ROBOT attack vulnerability

## Findings Produced

| Finding | Severity | CWE | Condition |
|---------|----------|-----|-----------|
| Deprecated Protocol: SSL 2.0 | Critical | 326 | SSL 2.0 has accepted cipher suites |
| Deprecated Protocol: SSL 3.0 | Critical | 326 | SSL 3.0 has accepted cipher suites |
| Deprecated Protocol: TLS 1.0 | High | 326 | TLS 1.0 has accepted cipher suites |
| Deprecated Protocol: TLS 1.1 | High | 326 | TLS 1.1 has accepted cipher suites |
| Vulnerable to Heartbleed (CVE-2014-0160) | Critical | 119 | Heartbleed check returns true |
| Vulnerable to ROBOT Attack | High | -- | ROBOT result contains "VULNERABLE" |
| Certificate Not Trusted | High | 295 | Path validation fails for any store |

All findings are tagged with **OWASP A02:2021 Cryptographic Failures**.

## Configuration

```toml
[tools]
sslyze = "/custom/path/to/sslyze"
```

## Standalone Usage

```bash
# Full JSON scan to stdout
sslyze --json_out=- example.com

# Scan non-standard port
sslyze --json_out=- example.com:8443

# Regular scan with text output
sslyze example.com

# Check specific protocols only
sslyze --tlsv1_0 --tlsv1_1 example.com

# Scan with certificate info
sslyze --certinfo example.com
```
