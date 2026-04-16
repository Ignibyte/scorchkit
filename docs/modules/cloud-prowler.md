# `prowler-cloud` — AWS Cloud-Posture Audit (WORK-151)

First concrete `CloudModule` landed on the WORK-150 cloud foundation. Wraps the `prowler` binary for AWS-account posture audits — CIS AWS Foundations plus 400+ additional checks across IAM, S3, EC2, CloudTrail, KMS, VPC, and more.

## Quick start

```bash
# Install prowler (if you haven't already — already in `scorchkit doctor`)
pip install prowler

# Scan against the AWS CLI default profile
scorchkit cloud aws:123456789012

# Or scan whichever account the explicit profile resolves to
scorchkit cloud all --features cloud
```

## Configuration

The module reads AWS credentials from `[cloud]` in `config.toml`:

```toml
[cloud]
aws_profile = "production"
aws_region = "us-east-1"
aws_role_arn = "arn:aws:iam::123456789012:role/ScorchKitAuditor"
```

Any of these can be overridden per-invocation via env vars (env wins when set and non-empty; empty strings are treated as unset to accommodate CI patterns):

| Env var | Overrides |
|---------|-----------|
| `SCORCHKIT_AWS_PROFILE` | `aws_profile` |
| `SCORCHKIT_AWS_REGION` | `aws_region` |
| `SCORCHKIT_AWS_ROLE_ARN` | `aws_role_arn` |

**All three are optional.** When unset, Prowler falls back to whatever it finds in the AWS CLI environment (`~/.aws/credentials` default profile, `AWS_*` env vars, IMDSv2 on EC2).

## Target forms

| Target | Meaning |
|--------|---------|
| `aws:<account-id>` | Scan the given AWS account. The account ID is informational — Prowler discovers the active account from the resolved credentials. |
| `all` | Scan whichever account the configured `aws_profile` or `aws_role_arn` resolves to. **Requires at least one of those fields to be set** — otherwise the module errors with a clear remediation message rather than silently falling through to the AWS CLI default. |
| `gcp:<project>` | Rejected — use `scoutsuite` (WORK-152) |
| `azure:<sub>` | Rejected — use `scoutsuite` (WORK-152) |
| `k8s:<context>` | Rejected — use `kubescape` (WORK-153) |

## What gets checked

Prowler runs its full AWS check battery. Highlights:

- **IAM** — root-account MFA, access-key rotation, policy least-privilege, permission-boundary drift
- **S3** — public buckets, missing encryption, missing lifecycle, missing versioning, HTTPS-only policies
- **EC2 / VPC** — default security groups, open-to-world ingress, unattached EIPs, IMDSv1 enforcement
- **CloudTrail** — enabled, log-file validation, integrated with CloudWatch, multi-region
- **KMS** — key rotation, deletion protection
- **CIS AWS Foundations** — all benchmark checks mapped and run
- **PCI-DSS, HIPAA, GDPR, SOC2** — compliance-framework overlays (Prowler's `--compliance` system)

Each FAIL check lands as a ScorchKit `Finding` with `module_id = "prowler-cloud"`.

## Finding shape

| Field | Value |
|-------|-------|
| `module_id` | `"prowler-cloud"` |
| `severity` | Mapped from Prowler's `critical` / `high` / `medium` / `low` / `informational` |
| `title` | `"Prowler: <check title>"` |
| `description` | Prowler's `message` or `status_detail` + `(Service: <service>)` |
| `affected_target` | `"cloud://aws:<target>"` |
| `evidence` | `"provider:aws | service:<name> | severity:<str> | target:<label>"` |
| `remediation` | `"Review the Prowler check documentation for remediation steps."` |
| `owasp_category` | `"A05:2021 Security Misconfiguration"` |
| `cwe_id` | `1188` (Insecure Default) |
| `confidence` | `0.8` |

**Pass results (`status_id == 1`) are filtered out** — only FAIL / Unknown / Skipped entries surface as findings.

## Comparison with the DAST `tools::prowler` wrapper

ScorchKit ships two Prowler entry points, both shelling out to the same binary:

| | `tools::prowler` (DAST) | `cloud::prowler` (Cloud) |
|---|---|---|
| Module id | `prowler` | `prowler-cloud` |
| Trait | `ScanModule` | `CloudModule` |
| Orchestrator | `Orchestrator` (DAST) | `CloudOrchestrator` |
| Subcommand | `scorchkit run <url>` | `scorchkit cloud <target>` |
| CLI family gate | always compiled | `feature = "cloud"` |
| Credentials | whatever AWS CLI default picks up | explicit `[cloud]` config + `SCORCHKIT_AWS_*` env |
| Provider tag in evidence | none | `provider:aws` |
| CWE | none | 1188 |
| Subprocess strategy | strict `run_tool` | lenient `run_tool_lenient` (tolerates Prowler's exit 3 on FAIL) |
| Introduced | WORK-114 batch | WORK-151 |

Operators with existing scan profiles invoking Prowler via the DAST orchestrator are unaffected — the DAST wrapper stays in place. New operators targeting cloud posture audits should use `prowler-cloud` via `scorchkit cloud` or `scorchkit assess --cloud ...` for the proper credential-resolution pipeline and finding-shape tagging.

## Exit-code handling

Prowler 4.x returns exit 3 when any check FAILs (configurable via `output.exit_code_on_fail: true` — increasingly common in CI). `cloud::prowler` uses `run_tool_lenient` so those exits don't abort the scan. Only `ToolNotFound` (missing binary) and timeouts (15 min wall clock) propagate as errors.

## Testing

`src/cloud/prowler.rs` ships 14 unit tests covering:

- Argv builder — 6 happy paths (no-creds, profile, region, role-arn, all-three, empty-string-as-unset)
- Argv builder — 5 error paths (All-without-creds, GCP / Azure / K8s rejected, All-with-profile-ok)
- OCSF parser — 2 tests (array form with mixed PASS/FAIL and 5 severities, JSONL fallback)
- Module trait surface — 1 test pinning id / name / category / providers / required-tool

Live smoke against real AWS accounts is deferred to WORK-154 where finding-shape normalization stabilizes across cloud wrappers.

## Follow-up work

- **WORK-152** — Scoutsuite as `CloudModule` — GCP, Azure, and AWS/AliCloud/OCI wider coverage
- **WORK-153** — Kubescape as `CloudModule` — K8s cluster posture
- **WORK-154** — Finding-shape normalization + shared OCSF parser extraction + per-check CWE/compliance mapping
- **v2.2 Compliance arc** — CIS-benchmark scan profiles, audit-mode reporting, evidence-bundle export
