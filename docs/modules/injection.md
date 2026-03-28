# SQL Injection Detection

**Module ID:** `injection` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/injection.rs`

## What It Does

Detects SQL injection vulnerabilities using error-based and blind detection techniques. It tests URL query parameters and HTML form fields by appending SQL metacharacter payloads and analyzing responses for database error messages, HTTP 500 errors, and significant response size differences.

## Checks Performed

### Injection Vectors

| Vector | Description |
|--------|-------------|
| URL parameters | Tests each query parameter in the target URL |
| Spidered links | Extracts same-origin links with query parameters from the page (up to 20) |
| Form fields | Extracts forms and tests each non-hidden, non-submit input (up to 10 forms, first 3 payloads per field) |

### SQL Payloads (10)

| # | Payload | Technique |
|---|---------|-----------|
| 1 | `'` | Single quote break |
| 2 | `"` | Double quote break |
| 3 | `' OR '1'='1` | Boolean true (single quote) |
| 4 | `" OR "1"="1` | Boolean true (double quote) |
| 5 | `'; --` | Statement termination with comment |
| 6 | `1' AND '1'='1` | Boolean condition |
| 7 | `1 AND 1=1` | Numeric boolean |
| 8 | `' UNION SELECT NULL--` | UNION injection probe |
| 9 | `1; SELECT 1` | Statement stacking |
| 10 | `') OR ('1'='1` | Parenthesized boolean |

### Database Error Patterns (30)

| Database | Patterns |
|----------|----------|
| MySQL (7) | `you have an error in your sql syntax`, `warning: mysql`, `unclosed quotation mark...`, `mysql_fetch`, `mysql_num_rows`, `mysql_query`, `mysqli_` |
| PostgreSQL (5) | `pg_query`, `pg_exec`, `error: syntax error at or near`, `unterminated quoted string at or near`, `pgsql` |
| MSSQL (4) | `microsoft sql server`, `mssql_query`, `odbc sql server driver`, `sqlsrv_` |
| SQLite (4) | `sqlite_error`, `sqlite3::`, `sqlite.error`, `unrecognized token` |
| Oracle (3) | `ora-`, `oracle error`, `oracleexception` |
| Generic (5) | `sql syntax`, `sql error`, `query failed`, `database error`, `jdbc.sqlex` |
| Java/JDBC (1) | `jdbc.sqlex` |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Potential SQL Injection in Parameter | Critical | 89 | Database error pattern detected in response |
| SQL Injection in Form Field | Critical | 89 | Database error from form field injection |
| Server Error on SQL Injection Attempt | High | 89 | HTTP 500 when baseline was 2xx |
| Possible Blind SQL Injection | Medium | 89 | Response body size differs by >50% with OR-based payload |

## OWASP Coverage

**A03:2021 -- Injection.** Covers error-based SQL injection across five database engines and blind SQL injection via response size differential analysis.

## How It Works

1. **Baseline capture:** A normal GET request records the HTTP status and body length for comparison.
2. **Parameter injection:** Each URL parameter is tested by appending the 10 SQL payloads to the original value. The modified URL is requested and the response analyzed.
3. **Error-based detection:** The response body is lowercased and scanned against 30 database error patterns. If any match, a Critical finding is emitted identifying the database type.
4. **500 detection:** If the injection causes a 500 error where the baseline returned 2xx, a High finding is emitted.
5. **Blind detection:** For `OR`-based payloads, the response body length is compared to the baseline. A difference greater than 50% suggests boolean-based blind SQL injection.
6. **Form extraction:** HTML forms are parsed using `scraper`. Each text/password/etc. input is tested with the first 3 payloads. Hidden, submit, button, file, and image inputs are skipped.
7. **Deduplication:** Testing stops after the first confirmed finding per parameter or per form.

## Example Output

```
[Critical] Potential SQL Injection in Parameter: id
  The parameter 'id' appears vulnerable to SQL injection. A MySQL error was
  triggered by injecting SQL metacharacters.
  Evidence: Payload: ' | Parameter: id | Database: MySQL
  Remediation: Use parameterized queries / prepared statements.
  OWASP: A03:2021 Injection | CWE-89
```
