# Nmap Port Scanner

**Module ID:** `nmap` | **Category:** Scanner | **Binary:** `nmap`
**Source:** `src/tools/nmap.rs`

## Overview

Nmap is the industry-standard network port scanner and service detection tool. ScorchKit wraps nmap to discover open ports, identify running services, and detect software versions on the target host. This information forms the foundation for further vulnerability scanning -- knowing what ports and services are exposed tells ScorchKit which additional modules are relevant.

## Installation

```bash
# Debian / Ubuntu
sudo apt install nmap

# macOS
brew install nmap

# Fedora / RHEL
sudo dnf install nmap
```

## How ScorchKit Uses It

**Command:** `nmap -sV --top-ports 1000 -oX - <target>`
**Output format:** XML (streamed to stdout via `-oX -`)
**Timeout:** 600s (10 minutes)

The wrapper resolves the target to a domain (falling back to the full URL) before passing it to nmap. Service version detection (`-sV`) is enabled to identify software and version strings on open ports.

## What Gets Parsed

ScorchKit parses the XML output by extracting `<port>` elements with `state="open"`. For each open port, the following attributes are extracted:

- `portid` -- the port number (e.g., 80, 443, 8080)
- `protocol` -- the transport protocol (tcp/udp)
- `name` -- the service name (e.g., http, ssh, mysql)
- `product` -- the software product (e.g., nginx, OpenSSH)
- `version` -- the software version string (e.g., 1.18.0, 8.4p1)

The parser also checks for known outdated software versions (Apache 2.0.x/2.2.x, old nginx, OpenSSH < 8.x) and flags them separately.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| Open Port (web: 80, 443, 8080, 8443) | Info | Standard web ports open |
| Open Port (SSH: 22) | Low | SSH port open |
| Open Port (other) | Low | Any other port open |
| Open Port (dangerous service: FTP, telnet, rsh, rlogin, rexec) | High | Cleartext remote access |
| Open Port (database: MySQL, PostgreSQL, MSSQL, Redis, MongoDB, Memcached) | High | Database directly exposed |
| Open Port (SMB/NetBIOS) | Medium | Windows file sharing exposed |
| Outdated Service Version | High | Known old major version detected |

All open-port findings are tagged with **OWASP A05:2021 Security Misconfiguration**. Outdated version findings are tagged with **OWASP A06:2021 Vulnerable and Outdated Components** and **CWE-1104**.

## Configuration

```toml
[tools]
nmap = "/custom/path/to/nmap"
```

## Standalone Usage

```bash
# Service version scan on top 1000 ports, XML output to stdout
nmap -sV --top-ports 1000 -oX - example.com

# Full port scan with OS detection
nmap -sV -p- -O example.com

# Quick scan (top 100 ports)
nmap -sV --top-ports 100 example.com

# Scan specific ports
nmap -sV -p 80,443,8080,3306 example.com
```
