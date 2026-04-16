# Snyk Test (dependency scanner)

Snyk's dependency-vulnerability scanner — matches project manifests (`package.json`, `requirements.txt`, `pom.xml`, etc.) against the Snyk vulnerability database. Free tier has scan quotas; authenticated usage raises them. License: Apache-2.0 for the CLI, proprietary DB (upstream: [snyk/cli](https://github.com/snyk/cli)).

## Install

```
npm install -g snyk
```

Run `snyk auth` for higher quotas. Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `snyk test --json --file <path>` and iterates `vulnerabilities[]`. One finding per vulnerability:

| Snyk `severity` | ScorchKit severity |
|---|---|
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| other | Info |

Each finding carries:

- **Title**: `<snyk-id>: <title>` (e.g. `SNYK-JS-LODASH-1018905: Prototype Pollution`)
- **Description**: `Vulnerable dependency <pkg>@<ver>: <title>`
- **Affected**: `<pkg>@<ver>`
- **Evidence**: `Package: <name> <version>`
- **Remediation**: `Upgrade <pkg> to version <fix1> or <fix2>.` when `fixedIn` is populated, else `No fix available yet...`
- **OWASP**: A06:2021 Vulnerable and Outdated Components
- **CWE**: 1104
- **Confidence**: 0.9

## How to run

```
scorchkit code /path/to/project --modules snyk-test
```

300s timeout. The `--file` arg expects a manifest file path — for multi-manifest repos, invoke snyk directly per manifest or use `snyk test --all-projects`.

## Limitations vs alternatives

- **Free-tier quotas** — same caveat as `snyk-code`.
- **vs `osv-scanner`**: osv-scanner uses Google's OSV database (broader community coverage); snyk uses its proprietary database (often faster to add new CVEs, richer metadata). Sources overlap heavily but not completely.
- **vs `trivy` / `grype`**: trivy and grype handle both container images and dependency manifests; snyk-test is manifest-only in this wrapper. For image scanning, reach for trivy/grype.
- **vs language-native**: `cargo-audit` (Rust), `bundler-audit` (Ruby), etc. are offline and free. Use snyk-test when you want a single cross-ecosystem source of truth.
