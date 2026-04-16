# Hadolint

Dockerfile linter — checks Dockerfiles for best-practice violations, security issues (running as root, unpinned versions, `:latest` tags), and efficiency problems. Wraps ShellCheck under the hood to also lint inline shell in `RUN` directives. License: GPL-3.0 (upstream: [hadolint/hadolint](https://github.com/hadolint/hadolint)).

## Install

```
brew install hadolint
# or: curl -sL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper looks for `<path>/Dockerfile` and (if present) runs `hadolint --format json <Dockerfile>`. Each issue becomes a finding:

| Hadolint `level` | ScorchKit severity |
|---|---|
| `error` | High |
| `warning` | Medium |
| `info` | Low |
| `style` / other | Info |

Each finding carries:

- **Title**: `<code>: <message>` (e.g. `DL3007: Using latest is prone to errors`)
- **Affected**: `<file>:<line>`
- **OWASP**: A05:2021 Security Misconfiguration
- **Remediation**: points to the Hadolint rule code
- **Confidence**: 0.85

If no `Dockerfile` exists in the target directory, the module returns zero findings (no error).

## How to run

```
scorchkit code /path/to/project --modules hadolint
```

60s timeout.

## Limitations vs alternatives

- **vs `dockle`**: hadolint lints the Dockerfile source; dockle lints the built image. Use both — they catch different things.
- **One Dockerfile per run**. Projects with multiple Dockerfiles (`api/Dockerfile`, `web/Dockerfile`) need separate invocations; this wrapper only inspects `./Dockerfile`.
- **`# hadolint ignore=DLxxxx` comments** suppress rules. Review during triage.
- **ShellCheck rules apply to `RUN` directives** — you'll see `SC2086` et al. show up alongside the `DLxxxx` codes.
