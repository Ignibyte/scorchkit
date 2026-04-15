# cargo-audit

Rust SCA against the RustSec advisory database. License: Apache-2.0 or MIT (upstream: [rustsec/rustsec](https://github.com/rustsec/rustsec/tree/main/cargo-audit)).

## Install

```
cargo install cargo-audit
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `cargo-audit audit --json --file <path>/Cargo.lock` and iterates `vulnerabilities.list[]`. One finding per advisory:

- **Title**: `<RUSTSEC-id>: <package> <version>`
- **Severity**:
  - `Low` if the advisory is `informational: "unmaintained"` or `"notice"`
  - `High` otherwise (security advisories are treated uniformly high; operators use CVSS / exploitability context from the advisory link to tier further)
- **Evidence**: `Advisory: <id> | Package: <name> <version>`
- **Affected**: `Cargo.lock:<pkg>@<ver>`
- **OWASP**: A06:2021 Vulnerable and Outdated Components
- **CWE**: 1104 (Use of Unmaintained Third Party Components)
- **Remediation**: points to `https://rustsec.org/advisories/<id>`
- **Confidence**: 0.95

## How to run

```
scorchkit code /path/to/rust/project --modules cargo_audit
```

60s timeout. Requires a populated `Cargo.lock` in the target directory.

## Limitations vs alternatives

- **vs `cargo-deny`**: cargo-audit is advisory-only. cargo-deny also enforces license policy, banned crates, and source-registry restrictions. Run both on Rust projects — they cover different risks.
- **vs `osv-scanner`**: osv-scanner pulls from the OSV database (which ingests RustSec), so findings overlap heavily. Prefer cargo-audit for Rust-only projects (tighter, language-native); use osv-scanner for polyglot repos.
- **No `--allow-yanked` / `--deny warnings` knobs surfaced**. If you need CI-gating semantics, invoke cargo-audit directly.
