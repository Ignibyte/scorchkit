# Metasploit Scanner

**Module ID:** `metasploit` | **Category:** Scanner | **Binary:** `msfconsole`
**Source:** `src/tools/metasploit.rs`

## Overview

Metasploit Framework is the world's most widely used penetration testing tool. ScorchKit wraps the `msfconsole` CLI to run a curated set of safe auxiliary scanner modules -- specifically HTTP version detection, HTTP options enumeration, and robots.txt analysis. ScorchKit deliberately avoids exploit modules, using only non-destructive auxiliary scanners for reconnaissance and validation.

## Installation

```bash
# Official installer script (recommended)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall

# Debian / Ubuntu
sudo apt install metasploit-framework

# macOS
brew install metasploit

# Kali Linux (pre-installed)
# Already available at /usr/bin/msfconsole
```

## How ScorchKit Uses It

**Command:** `msfconsole -q -x "<resource commands>"`
**Output format:** Console text (parsed for `[+]` and `[*]` markers)
**Timeout:** 120s (2 minutes)

The wrapper constructs a chain of auxiliary module commands:

```
use auxiliary/scanner/http/http_version; set RHOSTS <target>; set RPORT <port>; set SSL <true|false>; run;
use auxiliary/scanner/http/options; set RHOSTS <target>; set RPORT <port>; set SSL <true|false>; run;
use auxiliary/scanner/http/robots_txt; set RHOSTS <target>; set RPORT <port>; set SSL <true|false>; run;
exit
```

Key flags:
- `-q` -- quiet mode (suppress banner)
- `-x` -- execute commands inline (non-interactive)

The SSL option is set based on whether the target uses HTTPS.

## What Gets Parsed

The wrapper scans each line of console output:

- **`[+]` lines** -- positive results (vulnerability found or confirmed). If the line contains "vulnerable", it gets Critical severity; otherwise Medium.
- **`[*]` lines** -- informational results. Only lines containing "detected", "found", "version", or "server" are included (to filter noise). These get Info severity.
- **`[-]` lines** -- negative results (skipped, not parsed into findings).

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| MSF: {positive result} | Critical | `[+]` line mentioning "vulnerable" |
| MSF: {positive result} | Medium | Any other `[+]` line |
| MSF: {info result} | Info | `[*]` line with detection/version info |

Evidence is the raw Metasploit output line.

## Configuration

```toml
[tools]
msfconsole = "/custom/path/to/msfconsole"
```

## Standalone Usage

```bash
# Run a specific auxiliary module
msfconsole -q -x "use auxiliary/scanner/http/http_version; set RHOSTS example.com; run; exit"

# Interactive scanning
msfconsole
msf6 > use auxiliary/scanner/http/dir_scanner
msf6 auxiliary(scanner/http/dir_scanner) > set RHOSTS example.com
msf6 auxiliary(scanner/http/dir_scanner) > run

# Search for modules
msfconsole -q -x "search type:auxiliary name:http; exit"

# Run with a resource script
msfconsole -q -r scan_script.rc
```
