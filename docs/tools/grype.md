# Grype

Container image and filesystem vulnerability scanner from Anchore — matches detected packages against the Anchore vulnerability database covering CVEs across all major package ecosystems. License: Apache-2.0 (upstream: [anchore/grype](https://github.com/anchore/grype)).

## Install

```
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
# or: brew install grype
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `grype dir:<path> -o json --quiet` and iterates `matches[]`. One finding per CVE match:

| Grype `severity` | ScorchKit severity |
|---|---|
| `Critical` | Critical |
| `High` | High |
| `Medium` | Medium |
| `Low` | Low |
| other (`Unknown`, `Negligible`) | Info |

Each finding carries:

- **Title**: `<vuln-id>: <pkg>@<version>` (e.g. `CVE-2023-44487: golang.org/x/net@0.15.0`)
- **Description**: the vulnerability's `description` field
- **Affected**: `<pkg>@<version>`
- **Evidence**: `Package: <name> <version> (<type>) | Refs: <urls>`
- **Remediation**: `Update <pkg> to version <fix1> or <fix2>.` when fix versions exist, else `No fix available yet for <id>.`
- **OWASP**: A06:2021 Vulnerable and Outdated Components
- **CWE**: 1104 (Use of Unmaintained Third Party Components)
- **Confidence**: 0.9

## How to run

```
scorchkit code /path/to/project --modules grype
# or scan an image:
scorchkit code myimage:tag --modules grype    # wrapper uses dir: mode, invoke grype directly for image: mode
```

120s timeout.

## Limitations vs alternatives

- **vs `trivy`**: trivy and grype overlap almost entirely for filesystem + container scanning. Both are first-rate; pick one based on ecosystem fit (trivy has better IaC checks, grype has better SBOM generation via syft). Running both catches the small diff in vuln databases.
- **vs `osv-scanner`**: osv-scanner pulls from Google's OSV database; grype uses Anchore's. Sources overlap heavily but not completely. For polyglot repos where every missed CVE matters, run both.
- **`dir:` mode only in this wrapper**. For container image scanning (`grype <image>:tag`), invoke grype directly — ScorchKit's wrapper always prefixes the path with `dir:`.
- **Needs DB refresh**. Grype caches its vuln DB locally; stale caches miss recent CVEs. Run `grype db update` periodically.
