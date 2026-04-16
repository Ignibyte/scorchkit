# Dockle

Container-image linter — inspects the built image against the CIS Docker Benchmark plus image-history secrets. Complements hadolint (Dockerfile lint) by examining the runtime image itself. License: Apache-2.0 (upstream: [goodwithtech/dockle](https://github.com/goodwithtech/dockle)).

## Install

```
brew install goodwithtech/r/dockle
# or: download from https://github.com/goodwithtech/dockle/releases
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `dockle --format json <image>` (the wrapper passes the `CodeContext.path` as the image reference — in CI, first build the image and then point ScorchKit at the tag). It iterates `details[]`. One finding per check:

| Dockle `level` | ScorchKit severity |
|---|---|
| `FATAL` | Critical |
| `WARN` | High |
| `INFO` | Medium |
| other (`SKIP`, `PASS`) | Low |

Each finding carries:

- **Title**: `dockle <code>: <title>` (e.g. `dockle CIS-DI-0001: Create user`)
- **Description**: joined `alerts[]` list
- **Affected**: `container-image`
- **Evidence**: `code=<code> level=<level>`
- **OWASP**: A05:2021 Security Misconfiguration
- **Confidence**: 0.85

## How to run

```
scorchkit code <image-tag> --modules dockle
```

120s timeout. Requires the image to be built and locally available (or reachable via a configured Docker daemon / registry credentials).

## Limitations vs alternatives

- **vs `hadolint`**: hadolint lints the Dockerfile source; Dockle lints the built image. Use both — they find different things (hadolint: `FROM scratch` misuse, pinned versions; Dockle: leftover package-manager caches, baked-in secrets in layers, missing user).
- **vs `trivy image`**: trivy scans the image for CVEs in installed packages; Dockle checks CIS / best-practice config. Not redundant — pair them.
- **vs `grype`**: same split as trivy — grype finds CVEs, Dockle finds misconfig.
- This wrapper treats `ctx.path` as an image reference (tag or digest). For CI: `docker build -t myimg:scan . && scorchkit code myimg:scan --modules dockle`.
