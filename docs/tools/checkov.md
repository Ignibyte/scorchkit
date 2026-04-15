# Checkov

Infrastructure-as-Code security scanner from Prisma Cloud / Palo Alto — covers Terraform, CloudFormation, Kubernetes, Dockerfile, ARM, Serverless Framework, Helm, and more. License: Apache-2.0 (upstream: [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov)).

## Install

```
pipx install checkov
# or: pip install checkov
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `checkov --directory <path> -o json --quiet --compact` and iterates `results.failed_checks[]` for each framework block. One finding per failure:

| Checkov `severity` | ScorchKit severity |
|---|---|
| `CRITICAL` | Critical |
| `HIGH` | High |
| `MEDIUM` | Medium |
| `LOW` | Low |
| other | Info |

Each finding carries:

- **Title**: `<check-id>: <name>` (e.g. `CKV_AWS_18: Ensure the S3 bucket has access logging enabled`)
- **Description**: `IaC misconfiguration in <framework> resource <resource-name>: <check-name>`
- **Affected**: `<file>:<line>` (from `file_line_range`)
- **Evidence**: `Framework: <tf|cfn|k8s|...> | Resource: <name>`
- **OWASP**: A05:2021 Security Misconfiguration
- **Remediation**: the `guideline` URL when Checkov provides one, else a generic pointer to the rule ID
- **Confidence**: 0.85

## How to run

```
scorchkit code /path/to/iac --modules checkov
```

300s timeout — Checkov loads a large Python ruleset; first runs are slow.

## Limitations vs alternatives

- **vs `kics`**: checkov and KICS overlap substantially. Checkov has better cloud-native rule depth (AWS, Azure, GCP) and first-class CSPM integration; KICS is more format-diverse (adds Pulumi, OpenAPI, gRPC). Pair them or pick based on stack.
- **vs `tflint`**: different jobs — tflint is HCL style + syntax, checkov is security misconfig. Not redundant.
- **vs `trivy config`**: trivy's IaC mode is lighter and faster; checkov has deeper rules. Use trivy for fast CI gates, checkov for release / audit.
- **Python startup overhead**. The wrapper's 300s timeout is generous but not unlimited; very large monorepos may need direct invocation with `--framework` to scope.
