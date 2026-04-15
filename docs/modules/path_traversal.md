# Path Traversal / Local File Inclusion

**Module ID:** `path_traversal` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/path_traversal.rs`

## What It Does

Tests URL query parameters, crawled links, and HTML form fields for
directory traversal and local file inclusion. The module replaces (or
appends, for forms) each parameter with a payload targeting
`/etc/passwd`, `/etc/shadow`, `windows\win.ini`, `boot.ini`, or the
Windows hosts file, then scans the response for well-known file-content
signatures. A match confirms the server resolved user input into a
filesystem read.

## What It Checks

**Payloads** (24): depth-varying basic traversals (`../etc/passwd` through
`../../../../../../../../etc/passwd`), URL-encoded (`..%2f`, `%2e%2e/`),
double-URL-encoded (`..%252f`, `%252e%252e/`), null-byte extension bypass
(`…%00.png`, `…%00.html`), Windows backslash (`..\..\windows\win.ini`),
Windows hosts file, UTF-8 overlong encoding (`..%c0%af`), Unicode fullwidth
slash (`..%ef%bc%8f`), filter-stripping variants (`....//`, `..../`), and
absolute paths (`/etc/passwd`, `/etc/shadow`, `C:\windows\win.ini`).

**File indicators** (12): `root:x:0:0`, `root:*:0:0`, `daemon:`, `bin:x:`,
`nobody:`, `root:$` (shadow), `[extensions]`, `[fonts]`, `[mci extensions]`
(win.ini), `[boot loader]`, `[operating systems]` (boot.ini),
`# localhost name resolution` (Windows hosts).

| Condition | Severity |
|-----------|----------|
| Any file-indicator substring matches the response body | High |

## How to Run

```
scorchkit run 'https://example.com/view?file=report.pdf' --modules path_traversal
```

The module also crawls the target for parameterized links (up to 20) and
forms (up to 10), testing each. Forms only try the first five payloads per
field to bound request volume.

## Limitations

- Stops at the first matching payload per parameter.
- Detection is purely content-based — partial file reads (first N bytes
  with no `:` separator) and files served with character-set transforms
  may be missed.
- The payload list uses a fixed depth range (1–8 `../` levels). Very
  deeply-nested chroots may need custom payloads.
- For POST-JSON file-read endpoints, use `injection` or manual testing —
  this module only tests query parameters and form fields.

## OWASP / CWE

- **A01:2021 Broken Access Control**, CWE-22 (Improper Limitation of a
  Pathname to a Restricted Directory).
