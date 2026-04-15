# OSV-Scanner

Google's dependency vulnerability scanner — matches project dependencies against the OSV (Open Source Vulnerabilities) database covering all major package ecosystems (npm, PyPI, Go, Maven, RubyGems, crates.io, NuGet, and more). License: Apache-2.0 (upstream: [google/osv-scanner](https://github.com/google/osv-scanner)).

## Install

```
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `osv-scanner --json --recursive <path>` and walks `results[].packages[].vulnerabilities[]`. One finding per `(package, vuln)` pair:

| OSV `severity` | ScorchKit severity |
|---|---|
| `CRITICAL` | Critical |
| `HIGH` | High |
| `MODERATE` / `MEDIUM` | Medium |
| `LOW` | Low |
| other | Info |

Each finding carries:

- **Title**: `<vuln-id>: <summary>` (e.g. `GHSA-jf85-cpcp-j695: Prototype Pollution in lodash`)
- **Description**: `Vulnerable dependency <pkg> <version>: <summary>`
- **Affected**: `<pkg>@<version>`
- **Evidence**: `Package: <name> <version> | Aliases: <cve>, <ghsa>, ...` when cross-references exist
- **Remediation**: `Update <pkg> to a patched version.`
- **OWASP**: A06:2021 Vulnerable and Outdated Components
- **CWE**: 1104
- **Confidence**: 0.9

## How to run

```
scorchkit code /path/to/project --modules osv-scanner
```

120s timeout. Recurses — finds every `package-lock.json`, `go.sum`, `Cargo.lock`, `requirements.txt`, etc. in the target tree.

## Limitations vs alternatives

- **The polyglot SCA default**. For single-language projects, language-native tools give tighter results — `cargo-audit` for Rust, `snyk-test` with better npm data, etc. Use osv-scanner when a repo spans multiple ecosystems.
- **vs `grype`**: grype uses Anchore's database; osv-scanner uses Google's OSV. Sources overlap but differ at the margins. For high-stakes audits, run both.
- **vs `trivy`**: trivy is broader (images + IaC + SBOMs); osv-scanner is dep-focused. Use osv-scanner for quick CI gates, trivy for fleet-level image inventory.
- **No call-graph analysis yet**. osv-scanner flags every vulnerable transitive dep; reachability analysis (is this function actually called?) is on Google's roadmap but not wrapped here.
