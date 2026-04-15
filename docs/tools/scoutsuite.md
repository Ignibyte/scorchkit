# Scout Suite

Multi-cloud security posture auditor from NCC Group — covers AWS, GCP, Azure, AliCloud, and OCI. Complements prowler (AWS-deep) with broader cloud coverage. License: GPL-2.0 (upstream: [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite)).

## Install

```
pipx install scoutsuite
```

The wrapper invokes the `scout` binary. Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `scout aws --report-dir <out> --no-browser` (AWS is the default provider; operators targeting GCP / Azure / etc. invoke scout directly for those). It reads `scoutsuite-results/scoutsuite-results.json` and walks `services.<svc>.findings.<rule>`. Any rule with `flagged_items > 0` becomes one finding:

| Scout `level` | ScorchKit severity |
|---|---|
| `danger` | High |
| `warning` | Medium |
| other | Low |

Each finding carries:

- **Title**: `Scout <service>: <rule-id>` (e.g. `Scout ec2: ec2-public-instance`)
- **Description**: rule's own `description` field
- **Affected**: `cloud:<service>`
- **Evidence**: `service=<svc> rule=<id> flagged_items=<n>`
- **OWASP**: A05:2021 Security Misconfiguration
- **Confidence**: 0.85

Credentials come from the standard provider environment (`AWS_PROFILE`, `GOOGLE_APPLICATION_CREDENTIALS`, etc.) — the wrapper doesn't manage auth.

## How to run

```
scorchkit code /placeholder --modules scoutsuite
```

(The path argument is placeholder — Scout audits the cloud via API, not a local directory.)

600s (10 min) timeout — full-account scans can take a while on large accounts.

## Limitations vs alternatives

- **AWS-only via this wrapper**. For GCP / Azure / AliCloud / OCI, run scout directly with `--provider gcp` etc. This choice avoids surfacing an N-provider arg matrix for a tool operators usually want to tune per cloud (regions, services filter, resource limits).
- **vs `prowler`**: prowler goes deeper on AWS (500+ checks, full CIS / SOC2 / HIPAA / PCI mapping). Scout is broader (multi-cloud, simpler report). Pair them for AWS work; Scout alone for other clouds.
- **Scout's schema evolves between versions** — the parser is best-effort, skipping entries it doesn't recognise rather than failing. If a new Scout version drops fields the parser expects, findings will silently decrease. Validate against Scout's HTML report when this matters.
- **No CWE mapping** — cloud misconfigurations don't cleanly map. OWASP A05 is the only tag.
