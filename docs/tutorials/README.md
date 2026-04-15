# ScorchKit Tutorials

Step-by-step guides for getting work done with ScorchKit. Pick the path that matches what you're trying to do.

## New to ScorchKit

| | Tutorial | What you'll do |
|--|----------|----------------|
| 1 | [First scan](01-first-scan.md) | Install, run `doctor`, scan a single web target, read the report — ~30 minutes |

## Operators

| | Tutorial | What you'll do |
|--|----------|----------------|
| 2 | [CVE correlation](02-cve-correlation.md) | Stand up NVD or OSV; scan an internal host; read CVE-tagged findings |
| 3 | [Unified `assess`](03-unified-assess.md) | DAST + SAST + Infra against the same target in one command |
| 4 | [Claude Code workflow](04-claude-code-workflow.md) | Use `/scan`, `/code`, `/analyze`, `/diff` conversationally |
| 5 | [TLS + DNS hygiene](05-tls-and-dns-hygiene.md) | Probe your own domain's mail / directory TLS and DNS posture |

## Contributors

| | Tutorial | What you'll do |
|--|----------|----------------|
| 6 | [Extending with custom modules](06-extending-with-custom-modules.md) | Implement a `ScanModule` from scratch using `examples/custom_scanner` |
| 7 | [Extending CVE backends](07-extending-cve-backends.md) | Add a third `CveLookup` backend (CSAF / GitHub Advisory) |

## DevSecOps

| | Tutorial | What you'll do |
|--|----------|----------------|
| 8 | [CI/CD integration](08-ci-cd-integration.md) | Wire ScorchKit into GitHub Actions / GitLab CI with SARIF upload |

## Conventions used in these tutorials

- Commands you should type are shown in fenced ```bash blocks.
- Where a tutorial expects you to substitute your own value, the placeholder is `<like-this>`.
- Output excerpts are trimmed to the lines that matter — assume scrollback above and below.
- Tutorials assume the v2.0+ public release. Earlier versions may diverge.

If you find a tutorial step that doesn't work as written, please file an issue.
