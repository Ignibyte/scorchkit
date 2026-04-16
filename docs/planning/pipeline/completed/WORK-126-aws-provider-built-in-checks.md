# Work Pipeline: AWS Provider — Built-in Cloud Checks (IAM / S3 / SG / CloudTrail)

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-15 |
| **Last Updated** | 2026-04-15 |
| **Last Command** | /complete |
| **Next Step** | Run `/commit` to ship |
| **Blocked** | No |
| **Forge Ticket** | #126 |
| **Forge Ticket ID** | 019d8ef5-7781-73fb-a7a0-ec257c5b1aae |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Work Spec
- **Title:** AWS Provider — Built-in Cloud Checks (IAM / S3 / SG / CloudTrail)
- **Type:** Feature
- **Scope:** Add 4 native-Rust AWS cloud modules using `aws-sdk-rust` that check IAM posture (root keys, MFA, password policy), S3 posture (public buckets, encryption, versioning, logging), security group exposure (0.0.0.0/0 ingress on sensitive ports), and CloudTrail health (multi-region, encryption, log validation). Uses standard AWS credential chain. Each module implements `CloudModule` with `CloudCategory::Iam` / `Storage` / `Network` / `Compliance` and `CloudProvider::Aws`. Produces per-check findings with `CloudEvidence` + `enrich_cloud_finding` (WORK-154).
- **Files Expected:** ~8-12 files (4 new cloud module files in `src/cloud/aws/`, `src/cloud/aws/mod.rs` submodule, Cargo.toml dep additions, cloud/mod.rs registration, tests)
- **Dependencies:**
  - `CloudModule` trait (WORK-150, shipped)
  - `CloudEvidence` + `enrich_cloud_finding` (WORK-154, shipped)
  - `CloudCredentials` with `aws_profile` / `aws_role_arn` / `aws_region` (WORK-150, shipped)
  - New Cargo deps: `aws-config`, `aws-sdk-iam`, `aws-sdk-s3`, `aws-sdk-ec2`, `aws-sdk-cloudtrail`
- **Risks:**
  - AWS SDK crates are large — increases compile time and binary size significantly
  - Credential resolution complexity (env, shared config, IMDS, SSO)
  - Tests cannot hit real AWS APIs without credentials — must use mocked/stubbed responses
  - AWS SDK version churn — pin to a specific release
- **Acceptance Criteria:**
  - 4 new `CloudModule` implementations registered in `cloud::register_modules()`
  - IAM checks: root access keys present, MFA on root, password policy strength
  - S3 checks: public access, encryption at rest, versioning, server access logging
  - Security group checks: 0.0.0.0/0 ingress on ports 22/3389/3306/5432/1433/27017
  - CloudTrail checks: multi-region trail, encryption at rest, log file validation
  - All findings use `CloudEvidence` builder + `enrich_cloud_finding` (per-service OWASP/CWE/compliance)
  - Credentials resolved from standard AWS chain (env → shared config → IMDS)
  - All tests pass with mocked AWS responses — no live AWS dependency
  - Zero clippy warnings, cargo fmt clean

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0, rustc 1.94.0, fmt 1.8.0, clippy 0.1.94 |
| Security tools | OK — semgrep 1.156.0, cargo-audit 0.22.1, cargo-deny 0.19.0, cargo-tarpaulin 0.35.2 |
| Hooks wired | OK — 2 PreToolUse + 6 Stop = 8 total |
| Config files | OK — .semgrep.yml, deny.toml, rustfmt.toml all present |
| gh CLI | OK — 2.87.3 |
| cargo check | OK — clean compilation |
| cargo test (cloud) | OK — 714 passed, 0 failed, 2 ignored |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- DL-004: After any context continuation, re-read pipeline documents
- DL-016: MUST call bootstrap -> recall before writing code
- DL-002: Phase gates are strict — no skipping ahead

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — `bootstrap` for project context, architecture decisions, active patterns
2. **Recall** — `recall(agent="{role}", phase={N}, component_types=[...])` for targeted failures and lessons
3. **Learn** — `learn(summary, topic, component_types)` to record what was discovered
4. **Search** — `search-architecture-docs` before writing code

These are enforced by `enforce-completion.sh`. Skipping them blocks the conversation from ending.

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Architecture

**Approach:**
4 built-in AWS cloud modules using `aws-sdk-rust`, behind a new `aws-native` feature flag (depends on `cloud` but separate to avoid bloating builds that only use external tool wrappers). Each module follows a **two-layer architecture**:

1. **Thin async `run()` layer** — builds `SdkConfig` from `CloudCredentials`, calls AWS SDK APIs, converts responses to intermediate types
2. **Pure check functions** — take intermediate types, return `Vec<Finding>` with `CloudEvidence` + `enrich_cloud_finding()` (WORK-154)

Intermediate types (`AwsIamSummary`, `S3BucketPosture`, `SecurityGroupRule`, `TrailStatus`) decouple the check logic from SDK-generated types, making tests constructible without mocking AWS HTTP. This is the same pattern as the existing tool wrappers (parse pre-built JSON → findings).

**Shared infrastructure** in `src/cloud/aws/mod.rs`:
- `build_aws_sdk_config(creds, target)` — bridges `CloudCredentials` → `aws_config::SdkConfig` (profile override, region override, role assumption via STS)
- `register_aws_modules()` → `Vec<Box<dyn CloudModule>>`
- Target validation: only `CloudTarget::Account(_)` and `CloudTarget::All` accepted (same as `prowler-cloud`)

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `Cargo.toml` | Modify | Add `aws-native` feature + 5 optional aws-sdk deps |
| 2 | `deny.toml` | Modify | Add AWS SDK license exceptions if needed (Apache-2.0 / MIT) |
| 3 | `src/cloud/aws/mod.rs` | Create | Shared `build_aws_sdk_config()`, intermediate types, `register_aws_modules()` |
| 4 | `src/cloud/aws/iam.rs` | Create | `IamCloudModule` — root keys, MFA, password policy |
| 5 | `src/cloud/aws/s3.rs` | Create | `S3CloudModule` — public access, encryption, versioning, logging |
| 6 | `src/cloud/aws/sg.rs` | Create | `SecurityGroupCloudModule` — 0.0.0.0/0 on sensitive ports |
| 7 | `src/cloud/aws/cloudtrail.rs` | Create | `CloudTrailCloudModule` — multi-region, encryption, log validation |
| 8 | `src/cloud/mod.rs` | Modify | Add `#[cfg(feature = "aws-native")] pub mod aws;` + update `register_modules()` |
| 9 | `src/lib.rs` | Possibly modify | Only if feature gate wiring needed at crate level |

**Type and Trait Changes:**

New intermediate types (all in `src/cloud/aws/mod.rs`):
```
AwsIamSummary { root_access_keys_present: bool, root_mfa_enabled: bool }
AwsPasswordPolicy { min_length: u32, require_symbols/numbers/upper/lower: bool, max_age_days: Option<u32> }
S3BucketPosture { name: String, public_access_blocked: bool, encryption_enabled: bool, versioning_enabled: bool, logging_enabled: bool }
SecurityGroupRule { group_id: String, group_name: String, port: u16, protocol: String, source_cidr: String }
TrailStatus { name: String, is_multi_region: bool, kms_key_id: Option<String>, log_file_validation: bool, is_logging: bool }
```

4 new `CloudModule` implementations:
- `IamCloudModule` — `CloudCategory::Iam`, `CloudProvider::Aws`
- `S3CloudModule` — `CloudCategory::Storage`, `CloudProvider::Aws`
- `SecurityGroupCloudModule` — `CloudCategory::Network`, `CloudProvider::Aws`
- `CloudTrailCloudModule` — `CloudCategory::Compliance`, `CloudProvider::Aws`

**Error Handling Strategy:**
- AWS SDK errors map to `ScorchError::Config` (credential/config issues) or `ScorchError::Tool` (API call failures)
- Individual check failures within a module are non-fatal — log at `warn`, continue with remaining checks
- `AccessDenied` from AWS → produce an Info finding ("Insufficient permissions to check X") rather than failing the module

**Architectural Decisions:**
- **Separate `aws-native` feature** — AWS SDK crates add ~200 generated types per service; not worth including for operators who only use Prowler/Scout tool wrappers
- **Intermediate types over SDK types in check functions** — SDK types have private fields and complex builders; our types are plain structs that tests construct directly
- **No STS AssumeRole in v1** — `aws_role_arn` from `CloudCredentials` is passed to the SDK config; the SDK handles the role assumption. Full cross-account fan-out is a follow-up
- **Sensitive ports list as a const** — `[22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5601, 8080, 8443]` (SSH, RDP, MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch, Kibana, HTTP alt, HTTPS alt)

**Testing Strategy:**
- Pure check functions tested with hand-crafted intermediate types
- Each module: happy path (findings produced), clean path (no findings), edge cases (empty lists, partial data)
- `build_aws_sdk_config` tested for correct region/profile passthrough
- No live AWS calls in tests — all testing via intermediate types
- Feature-gated: all tests behind `#[cfg(test)]` within `#[cfg(feature = "aws-native")]` modules

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_iam_root_keys_finding` | `src/cloud/aws/iam.rs` | Root access keys → Critical finding |
| 2 | `test_iam_root_mfa_missing` | `src/cloud/aws/iam.rs` | Missing root MFA → Critical finding |
| 3 | `test_iam_weak_password_policy` | `src/cloud/aws/iam.rs` | Weak policy → Medium finding |
| 4 | `test_iam_clean_account` | `src/cloud/aws/iam.rs` | Secure account → zero findings |
| 5 | `test_s3_public_bucket` | `src/cloud/aws/s3.rs` | Public access → Critical finding |
| 6 | `test_s3_no_encryption` | `src/cloud/aws/s3.rs` | Missing encryption → High finding |
| 7 | `test_s3_secure_bucket` | `src/cloud/aws/s3.rs` | Fully secured bucket → zero findings |
| 8 | `test_sg_open_ssh` | `src/cloud/aws/sg.rs` | 0.0.0.0/0 on port 22 → Critical finding |
| 9 | `test_sg_open_multiple_ports` | `src/cloud/aws/sg.rs` | Multiple open ports → multiple findings |
| 10 | `test_sg_restricted_rules_clean` | `src/cloud/aws/sg.rs` | Restricted CIDRs → zero findings |
| 11 | `test_cloudtrail_no_trail` | `src/cloud/aws/cloudtrail.rs` | No trails → Critical finding |
| 12 | `test_cloudtrail_not_encrypted` | `src/cloud/aws/cloudtrail.rs` | Missing KMS → High finding |
| 13 | `test_cloudtrail_healthy` | `src/cloud/aws/cloudtrail.rs` | Fully configured → zero findings |
| 14 | `test_register_aws_modules_count` | `src/cloud/aws/mod.rs` | 4 modules registered in lex order |
| 15 | `test_register_modules_includes_aws` | `src/cloud/mod.rs` | Total registry grows by 4 with aws-native |

### Deferred Items
- None

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1 (architecture decision recorded)
- **Failures:** 0
- **Component Types:** cloud, aws, engine

### Human Confirmed
- [ ] Design reviewed and confirmed

---

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Files Created
| File | Path |
|------|------|
| AWS module root | `src/cloud/aws/mod.rs` |
| IAM posture | `src/cloud/aws/iam.rs` |
| S3 posture | `src/cloud/aws/s3.rs` |
| Security groups | `src/cloud/aws/sg.rs` |
| CloudTrail posture | `src/cloud/aws/cloudtrail.rs` |

### Files Modified
| File | Change |
|------|--------|
| `Cargo.toml` | Added `aws-native` feature + 5 aws-sdk optional deps |
| `src/cloud/mod.rs` | Added `aws` submodule, updated `register_modules()` and registry test |

### Quality Gates
- **cargo fmt --check:** Pass
- **cargo clippy (aws-native):** Pass — 0 warnings
- **cargo test (aws-native):** Pass — 738 passed, 0 failed (+24 new)
- **cargo test (cloud):** Pass — 714 passed (unchanged)
- **cargo test (default):** Pass — 642 passed (unchanged)

### Notes
- AWS SDK API types use `Option<bool>` and `Option<i32>` extensively — accessed via `.field_name.unwrap_or(default)` pattern
- `aws_config::from_env()` deprecated in favor of `aws_config::defaults(BehaviorVersion::latest())`
- `AwsPasswordPolicy` and `S3BucketPosture` need `#[allow(clippy::struct_excessive_bools)]` with JUSTIFICATION — they mirror AWS API shape
- 3 fix iterations: SDK Option wrappers, deprecated from_env, clippy doc_markdown/borrows/bools

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** cloud, aws, engine

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Entry Verification (independently run)
- **cargo fmt --check:** Pass
- **cargo clippy (aws-native):** Pass — 0 warnings
- **cargo test (aws-native):** Pass — 738 passed, 0 failed, 2 ignored
- **```ignore check:** Pass — 0 found
- **#[ignore] check:** Pass — 0 in new files
- **#[allow] check:** Pass — 2 with JUSTIFICATION comments

### Code Review
- **Standards Compliance:** Pass
- **Workaround Detection:** Pass — no workarounds
- **Security Review (semgrep):** Pass — 0 findings across 5 new files

### Test Results
- **Cargo Test Count (aws-native):** 738 passed, 0 failed
- **Cargo Test Count (cloud):** 714 passed (unchanged)
- **Cargo Test Count (default):** 642 passed (unchanged)

### Regression Test Plan Compliance
All 15 planned tests implemented and passing.

### Knowledge Recorded
- **Lessons:** 0
- **Failures:** 0
- **Component Types:** cloud, aws, engine

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

- **Cargo Test Full Suite (aws-native):** Pass — 738 passed, 0 failed (identical to Phase 3+4)
- **Cargo Test Regressions:** None
- **Integration Tests:** Pass — 13 passed
- **Doctests:** Pass

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

- **Documentation Updated:** CHANGELOG.md, docs/architecture/cloud.md
- **Changelog Updated:** Yes
- **Pipeline Doc Archived:** Yes

### Self-Reflection
1. Did any phase use workarounds? No — `#[allow(clippy::struct_excessive_bools)]` is justified, not a workaround.
2. Was the implementation the cleanest version? Yes — two-layer architecture cleanly separates SDK calls from check logic.
3. Would a senior developer approve? Yes — intermediate types are clean, tests cover all paths, no unwrap in lib code.

### After-Action Review
- **Generation Trace Saved:** Yes
- **Lessons Recorded:** 2 (design + implementation)
- **Failures Recorded:** 0
- **Component Types Tagged:** cloud, aws, engine
