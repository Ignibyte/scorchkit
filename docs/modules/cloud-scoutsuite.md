# `scoutsuite-cloud` — Multi-Cloud Posture Audit (WORK-152)

Second concrete `CloudModule` after WORK-151 Prowler. Wraps the `scout` binary for posture audits across **AWS, GCP, and Azure** in a single scan invocation. Module id `"scoutsuite-cloud"`; `CloudCategory::Compliance` × `CloudProvider::{Aws, Gcp, Azure}`.

## Quick start

```bash
# Install Scout Suite (already in `scorchkit doctor` from WORK-114)
pip install scoutsuite

# Scan a single cloud
scorchkit cloud aws:123456789012
scorchkit cloud gcp:my-project
scorchkit cloud azure:abcd-1234-...

# Multi-cloud fan-out — runs Scout once per configured provider
scorchkit cloud all
```

## Configuration

The module reads cloud credentials from `[cloud]` in `config.toml`:

```toml
[cloud]
aws_profile = "production"
gcp_service_account_path = "/home/me/.config/gcloud/sa.json"
gcp_project_id = "my-project-123"
azure_subscription_id = "abcd-1234-..."
```

Each provider has independent credentials; populate only the ones you need. `CloudTarget::All` automatically skips providers whose credentials are absent (with a `debug!` log) — no error, just no work for that provider.

Env-var overrides apply per the WORK-150 `CloudCredentials` contract:

| Env var | Overrides |
|---------|-----------|
| `SCORCHKIT_AWS_PROFILE` | `aws_profile` |
| `SCORCHKIT_GCP_SERVICE_ACCOUNT_PATH` | `gcp_service_account_path` |
| `SCORCHKIT_GCP_PROJECT_ID` | `gcp_project_id` |
| `SCORCHKIT_AZURE_SUBSCRIPTION_ID` | `azure_subscription_id` |

## Provider-specific behavior

### AWS

```
scout aws [--profile <aws_profile>] --report-dir <tmp> --no-browser
```

Uses Scout's `--profile` flag if `aws_profile` is set; otherwise Scout reads the AWS CLI default profile / env vars.

### GCP

```
scout gcp --service-account <gcp_service_account_path> [--project-id <gcp_project_id>] --report-dir <tmp> --no-browser
```

**Requires `gcp_service_account_path`.** Without it, GCP scans error with a remediation message (single-provider `Project(_)` target) or are silently skipped (`All` target). The path must point to a valid Google Cloud service-account JSON key file; Scout reads the file directly.

### Azure

```
scout azure [--subscription-id <azure_subscription_id>] --cli --report-dir <tmp> --no-browser
```

The `--cli` flag tells Scout to use cached Azure CLI credentials. **Operators must run `az login` before invoking** — Scout has no way to perform interactive auth. Subscription ID is optional; without it, Scout uses the default subscription from the CLI context.

## Target forms

| Target | Behavior |
|--------|----------|
| `aws:<account-id>` | Single AWS scan via Scout's `aws` provider |
| `gcp:<project-id>` | Single GCP scan via Scout's `gcp` provider — **requires `gcp_service_account_path`** |
| `azure:<subscription-id>` | Single Azure scan via Scout's `azure` provider |
| `k8s:<context>` | **Rejected** — Scout has K8s mode but Kubescape (WORK-153) is the dedicated cloud-family wrapper |
| `all` | Multi-cloud fan-out — runs Scout sequentially against every provider whose credentials are configured. Errors only when **no** provider has any credentials. |

## What gets checked

Scout Suite runs its full check catalog per provider. Highlights:

- **AWS** — IAM least-privilege, S3 public access, EC2 default SGs, CloudTrail logging, KMS rotation, RDS encryption
- **GCP** — IAM bindings, Cloud Storage public access, Compute Engine misconfigurations, GKE security
- **Azure** — RBAC drift, Storage account public blob access, NSG rules, Key Vault access policies

Each `level` rule with `flagged_items > 0` lands as a ScorchKit `Finding`.

## Finding shape

| Field | Value |
|-------|-------|
| `module_id` | `"scoutsuite-cloud"` |
| `severity` | `level` mapped: `danger` → High, `warning` → Medium, anything else → Low |
| `title` | `"Scout <service>: <rule_id>"` |
| `description` | Scout's rule `description` field |
| `affected_target` | `"cloud://<target-label>"` |
| `evidence` | `"provider:<x> | service:<y> | rule:<z> | flagged:<n>"` |
| `remediation` | `"Review Scout Suite check documentation for remediation steps."` |
| `owasp_category` | `"A05:2021 Security Misconfiguration"` |
| `cwe_id` | `1188` (Insecure Default) |
| `confidence` | `0.85` |

The `provider:<aws|gcp|azure>` evidence tag enables downstream filtering and per-provider report grouping for multi-cloud `All` scans.

## Comparison with the SAST `sast_tools::scoutsuite` wrapper

ScorchKit ships two Scout entry points, both shelling out to the same binary:

| | `sast_tools::scoutsuite` (SAST) | `cloud::scoutsuite` (Cloud) |
|---|---|---|
| Module id | `scoutsuite` | `scoutsuite-cloud` |
| Trait | `CodeModule` | `CloudModule` |
| Orchestrator | `CodeOrchestrator` (SAST) | `CloudOrchestrator` |
| Subcommand | `scorchkit code <path>` | `scorchkit cloud <target>` |
| CLI family gate | always compiled | `feature = "cloud"` |
| Providers | AWS only (hardcoded) | AWS / GCP / Azure (provider-aware) |
| Credentials | implicit (Scout reads AWS CLI env) | explicit `[cloud]` config + `SCORCHKIT_*` env vars |
| Provider tag in evidence | none | `provider:<x>` |
| CWE | none | 1188 |
| Subprocess strategy | `run_tool_lenient` | `run_tool_lenient` (15-min per-provider sub-timeout) |
| Multi-cloud `All` fan-out | no | yes |
| Introduced | WORK-114 batch | WORK-152 |

Operators with existing scan profiles invoking Scout via the SAST orchestrator are unaffected — the SAST wrapper stays in place.

## Multi-cloud `All` semantics

`CloudTarget::All` is the marquee feature of `scoutsuite-cloud`. Behavior:

1. Inspect `[cloud]` config; build provider list from configured credentials:
   - `aws_profile` set → include AWS
   - `gcp_service_account_path` set → include GCP
   - `azure_subscription_id` set → include Azure
2. If the resulting list is empty → error with remediation message naming all three credential fields.
3. Run Scout sequentially per provider into separate temp directories (concurrent execution would risk tripping cloud-provider API rate limits).
4. Merge findings; per-provider failures are logged at `warn` and skipped — only when **all** providers fail does the module return an error.
5. Each finding carries a `provider:<x>` evidence tag for downstream filtering and report grouping.

Wall-clock budget: up to 30 min total (15-min sub-timeout per provider via `run_tool_lenient`).

## Testing

`src/cloud/scoutsuite.rs` ships 16 unit tests:

- `select_providers` — 8 tests covering single-target paths and `All`-mode fan-out resolution
- Per-provider argv builder — 5 tests with golden vectors for AWS / GCP / Azure
- JSON parser — 2 tests (extraction with provider tag + flagged-items filter; empty/invalid input)
- Module trait surface — 1 test pinning id / category / providers / required_tool

Live smoke against real cloud accounts is deferred to WORK-154 normalization phase.

## Follow-up work

- **WORK-153** — Kubescape as `CloudModule` for K8s cluster posture
- **WORK-154** — Finding-shape normalization + per-check CWE / compliance mapping across cloud wrappers
- **v2.3+** — Concurrent multi-provider execution with adaptive rate-limit backoff (current sequential path is safe but slow)
- **v2.3+** — Env-var injection support in `subprocess::run_tool_lenient` to enable Scout's GCP `GOOGLE_APPLICATION_CREDENTIALS` env-var auth path as a sibling to `--service-account`
