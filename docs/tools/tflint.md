# tflint

Terraform linter — deprecated-syntax detection, unused variables, and provider-specific best-practice rules. License: MPL-2.0 (upstream: [terraform-linters/tflint](https://github.com/terraform-linters/tflint)).

## Install

```
brew install tflint
# or: curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `tflint --format json --chdir <path>` and iterates the `issues[]` array. One finding per issue:

| tflint `rule.severity` | ScorchKit severity |
|---|---|
| `ERROR` / `error` | High |
| `WARNING` / `warning` | Medium |
| other (`NOTICE`, `INFO`) | Low |

Each finding carries:

- **Title**: `tflint <rule-name>: <message>` (e.g. `tflint unused_variable: Variable foo is unused`)
- **Affected**: `<file>:<line>`
- **Evidence**: `rule=<name> file=<path>:<line>`
- **Remediation**: "Address the lint per tflint's rule documentation"
- **Confidence**: 0.85

No OWASP / CWE mapping — tflint findings are mostly style + correctness, not direct security issues.

## How to run

```
scorchkit code /path/to/terraform/project --modules tflint
```

60s timeout. Requires Terraform source in the target directory.

## Limitations vs alternatives

- **vs `checkov`**: checkov focuses on security misconfigurations (public buckets, open SGs, missing encryption). tflint focuses on style + correctness (deprecated HCL, unused vars, provider best practices). Run both on Terraform repos — they don't overlap.
- **vs `kics`**: kics covers more IaC formats (CFN, K8s, Dockerfile, Helm, Ansible) at the cost of less Terraform depth. tflint is Terraform-native with provider-specific rules (AWS, Azure, GCP plugins).
- **Plugins required for provider rules**. Operators who want AWS / Azure / GCP provider lints must install the corresponding tflint plugin (`tflint --init` after adding to `.tflint.hcl`).
