# Command Injection Detection

**Module ID:** `cmdi` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/cmdi.rs`

## What It Does

Detects OS command injection vulnerabilities by injecting shell metacharacters into URL query parameters. It uses canary marker strings to confirm command execution and also flags HTTP 500 errors caused by injection attempts as indicators of potential vulnerability.

## Checks Performed

### Payloads (8)

| # | Payload | Expected Marker | Technique |
|---|---------|-----------------|-----------|
| 1 | `; echo scorchkit_cmdi_test` | `scorchkit_cmdi_test` | Semicolon command separator |
| 2 | `\| echo scorchkit_cmdi_test` | `scorchkit_cmdi_test` | Pipe command chaining |
| 3 | `` `echo scorchkit_cmdi_test` `` | `scorchkit_cmdi_test` | Backtick subshell |
| 4 | `$(echo scorchkit_cmdi_test)` | `scorchkit_cmdi_test` | Dollar-paren subshell |
| 5 | `; cat /etc/hostname` | _(none -- 500 check only)_ | File read attempt |
| 6 | `\| id` | `uid=` | Identity command via pipe |
| 7 | `; id` | `uid=` | Identity command via semicolon |
| 8 | `$(id)` | `uid=` | Identity command via subshell |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Command Injection in Parameter | Critical | 78 | Canary marker found in response but not in baseline |
| Possible Command Injection | High | 78 | Injection payload caused HTTP 500 |

## OWASP Coverage

**A03:2021 -- Injection.** Covers OS command injection via multiple shell metacharacter techniques (semicolons, pipes, backticks, and `$()` subshells).

## How It Works

1. The target URL is parsed and its query parameters extracted.
2. A baseline GET request is made with the original parameters to capture the normal response body.
3. For each parameter, each payload is appended to the original value and the modified URL is requested.
4. **Canary detection:** If the payload's expected marker string (e.g., `scorchkit_cmdi_test` or `uid=`) appears in the response body but was not present in the baseline, command execution is confirmed and a Critical finding is emitted.
5. **500 detection:** If no marker is found but the response returns HTTP 500, a High finding flags potential command injection.
6. Testing stops at the first confirmed finding for any parameter (early return).

## Example Output

```
[Critical] Command Injection in Parameter: file
  The parameter 'file' is vulnerable to OS command injection. The command output
  marker 'scorchkit_cmdi_test' was found in the response.
  Evidence: Parameter: file | Payload: ; echo scorchkit_cmdi_test | Marker: scorchkit_cmdi_test
  Remediation: Never pass user input to shell commands. Use parameterized APIs instead of system()/exec().
  OWASP: A03:2021 Injection | CWE-78
```
