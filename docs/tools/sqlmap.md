# SQLMap Injection Scanner

**Module ID:** `sqlmap` | **Category:** Scanner | **Binary:** `sqlmap`
**Source:** `src/tools/sqlmap.rs`

## Overview

SQLMap is the premier open-source tool for automated SQL injection detection and exploitation. ScorchKit wraps SQLMap to test URL parameters for SQL injection vulnerabilities using conservative settings (level 1, risk 1) to minimize false positives and avoid destructive actions. The wrapper only runs when the target URL contains query parameters.

## Installation

```bash
# Debian / Ubuntu
sudo apt install sqlmap

# macOS
brew install sqlmap

# pip
pip install sqlmap

# From source
git clone https://github.com/sqlmapproject/sqlmap.git
```

## How ScorchKit Uses It

**Command:** `sqlmap -u <target> --batch --level 1 --risk 1 --forms --crawl=2 --output-dir=/tmp/scorchkit-sqlmap`
**Output format:** Console text (parsed line by line)
**Timeout:** 600s (10 minutes)

**Pre-flight check:** The wrapper only executes SQLMap if the target URL contains both `?` and `=` characters (indicating query parameters). If no parameters are present, it returns an informational finding stating that no parameters were available to test.

Key flags:
- `--batch` -- non-interactive mode (uses defaults for all prompts)
- `--level 1` -- basic test level (fewest requests)
- `--risk 1` -- safe tests only (no OR-based injections that could modify data)
- `--forms` -- also test HTML form parameters
- `--crawl=2` -- crawl 2 levels deep to find additional injectable pages

## What Gets Parsed

The wrapper scans SQLMap's console output line by line, looking for:

- **Parameter declarations:** Lines starting with `Parameter:` (e.g., `Parameter: id (GET)`)
- **Injection types:** Lines starting with `Type:` (e.g., `Type: boolean-based blind`)
- **Confirmation markers:** Lines containing `is vulnerable` or `injectable`
- **Database identification:** Lines containing `back-end DBMS:` (e.g., `back-end DBMS: MySQL`)

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| Confirmed SQL Injection: {param} | Critical | SQLMap confirms injection in a parameter |
| Database Identified: {dbms} | Info | SQLMap identifies the back-end DBMS |
| SQLMap: No Parameters to Test | Info | Target URL has no query parameters |
| SQLMap: No Injection Points Found | Info | SQLMap ran but found nothing at this level/risk |

Confirmed SQL injection findings include:
- **OWASP:** A03:2021 Injection
- **CWE:** 89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Remediation:** Use parameterized queries / prepared statements

## Configuration

```toml
[tools]
sqlmap = "/custom/path/to/sqlmap"
```

## Standalone Usage

```bash
# Test a URL with parameters
sqlmap -u "https://example.com/page?id=1" --batch

# Test with higher level/risk
sqlmap -u "https://example.com/page?id=1" --batch --level 5 --risk 3

# Test POST data
sqlmap -u "https://example.com/login" --data="user=admin&pass=test" --batch

# Test with cookie-based injection
sqlmap -u "https://example.com/page" --cookie="session=abc123" --batch

# Enumerate databases after finding injection
sqlmap -u "https://example.com/page?id=1" --batch --dbs
```
