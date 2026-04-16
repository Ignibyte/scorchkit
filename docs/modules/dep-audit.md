# Dependency Auditor

**Module ID:** `dep-audit` | **Category:** SAST (SCA) | **Type:** Built-in
**Source:** `src/sast/dep_audit.rs`

## What It Does

Parses lockfiles found in a source tree and runs three structural checks
without contacting an external advisory database. It is the portable,
zero-config complement to `osv-scanner` and `grype`: duplicate-version
detection, unpinned-dependency detection, and a curated blocklist of
historically compromised or sabotaged packages.

## Supported Lockfiles

| File | Ecosystem | Notes |
|------|-----------|-------|
| `Cargo.lock` | cargo | TOML `[[package]]` entries; always pinned |
| `package-lock.json` | npm | v2/v3 `packages` map (preferred) or v1 `dependencies` |
| `requirements.txt` | pip | `==` (pinned), `>=`/`~=`/`<=`/`>`/`<`/`!=` (unpinned), bare package (unpinned) |
| `go.sum` | go | `module version h1:hash`; dedupes `/go.mod` suffix variants |

Multiple lockfiles in the same project are merged and analyzed together.

## What It Checks

| Check | Condition | Severity |
|-------|-----------|----------|
| Duplicate versions | Same package name appears in two or more versions within one ecosystem | Medium (CWE-1104) |
| Unpinned dependency | Any `requirements.txt` entry without `==` or with no version specifier | Medium (CWE-829) |
| Known-risky package | Package name matches the curated blocklist below | High (CWE-506) |

### Known-risky package blocklist

| Ecosystem | Package | Event |
|-----------|---------|-------|
| npm | `event-stream` | Compromised 2018 — flatmap-stream wallet theft |
| npm | `ua-parser-js` | Compromised 2021 — cryptominer + password stealer |
| npm | `coa`, `rc` | Compromised 2021 — hijacked maintainer accounts |
| npm | `colors`, `faker` | Sabotaged 2022 — infinite loop / functionality removal |
| npm | `node-ipc`, `peacenotwar` | Sabotaged 2022 — geo-targeted protestware |
| pip | `ctx` | Typosquat 2022 — env-var exfiltration |
| pip | `colourama` | Typosquat of `colorama` — credential stealer |
| pip | `python-dateutil` (typo variant) | Typosquat — credential stealer |

## How to Run

```
scorchkit code ./path/to/project --modules dep-audit
```

`scorchkit code` auto-detects lockfiles in the target directory; `dep-audit`
runs silently and produces no findings when no supported lockfile is
present.

## Limitations

- No CVE correlation. Compromised versions outside the curated blocklist
  are not flagged; use `osv-scanner` or `grype` for advisory-driven scans.
- Lockfile parsing is best-effort — parse errors yield an empty dependency
  list for that file rather than an error.
- The unpinned-dependency check is requirements.txt-only today; Cargo,
  npm, and Go lockfiles are treated as fully pinned by construction.
- Packages are matched by exact (case-insensitive) name; scoped npm
  packages (`@scope/name`) and typo-variants of risky names are not fuzzy-matched.

## OWASP

- Duplicates: **A06:2021 Vulnerable and Outdated Components**.
- Unpinned / risky: **A08:2021 Software and Data Integrity Failures**.
