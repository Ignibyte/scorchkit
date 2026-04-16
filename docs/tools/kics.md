# KICS

Keeping Infrastructure as Code Secure — Checkmarx's multi-format IaC scanner. Covers Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, Ansible, Pulumi, OpenAPI, and more. License: Apache-2.0 (upstream: [Checkmarx/kics](https://github.com/Checkmarx/kics)).

## Install

```
brew install kics
# or: download from https://github.com/Checkmarx/kics/releases
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `kics scan --path <dir> --output-path <out> --report-formats json`, reads the generated `results.json`, and iterates the `queries[]` array. One finding per `(query, file)` pair:

| KICS `severity` | ScorchKit severity |
|---|---|
| `HIGH` | High |
| `MEDIUM` | Medium |
| `LOW` | Low |
| other (`INFO`, `TRACE`) | Info |

Each finding carries:

- **Title**: `KICS <query-name>` (e.g. `KICS Bucket without encryption`)
- **Affected**: `<file>:<line>`
- **Evidence**: `query=<name> severity=<level>`
- **OWASP**: A05:2021 Security Misconfiguration
- **Confidence**: 0.85

The `expected_value` field (what the rule wanted to see) is copied into the finding's description for quick triage.

## How to run

```
scorchkit code /path/to/iac --modules kics
```

180s timeout.

## Limitations vs alternatives

- **vs `checkov`**: checkov and KICS overlap substantially. KICS covers a broader format spectrum (Pulumi, OpenAPI, gRPC); checkov is more actively developed for cloud-specific rules. Run both if you can tolerate the duplicate-reporting cost — they catch different things.
- **vs `tflint`**: kics is security-focused (misconfig), tflint is style-focused (syntax, unused vars). Complementary.
- **vs `kubescape`**: for pure Kubernetes manifests, kubescape maps findings to NSA / MITRE / ArmoBest / CIS frameworks — better traceability for compliance work. Use both.
- Query descriptions are sometimes terse — consult the KICS rule catalog for full remediation guidance.
