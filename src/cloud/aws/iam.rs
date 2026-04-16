//! AWS IAM posture checks — root access keys, MFA, password policy.
//!
//! Uses `aws-sdk-iam` to query the account summary and password
//! policy, then evaluates against CIS AWS Foundations Benchmark
//! best practices.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{build_aws_sdk_config, AwsIamSummary, AwsPasswordPolicy};

/// Built-in AWS IAM posture module.
///
/// Checks root account security (access keys, MFA) and password
/// policy strength without relying on external tools.
#[derive(Debug)]
pub struct IamCloudModule;

#[async_trait]
impl CloudModule for IamCloudModule {
    fn name(&self) -> &'static str {
        "AWS IAM Posture"
    }

    fn id(&self) -> &'static str {
        "aws-iam"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Iam
    }

    fn description(&self) -> &'static str {
        "Built-in AWS IAM checks: root access keys, MFA, password policy"
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Aws]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let sdk_config = build_aws_sdk_config(&ctx.target, ctx.credentials.as_deref()).await?;
        let client = aws_sdk_iam::Client::new(&sdk_config);
        let target_label = ctx.target.display_raw();

        let mut findings = Vec::new();

        // Account summary → root keys + MFA
        match fetch_iam_summary(&client).await {
            Ok(summary) => {
                findings.extend(check_iam_summary(&summary, &target_label));
            }
            Err(e) => {
                tracing::warn!("aws-iam: failed to fetch account summary: {e}");
                findings.push(permission_finding("GetAccountSummary", &target_label));
            }
        }

        // Password policy
        match fetch_password_policy(&client).await {
            Ok(Some(policy)) => {
                findings.extend(check_password_policy(&policy, &target_label));
            }
            Ok(None) => {
                let finding = Finding::new(
                    "aws-iam",
                    Severity::High,
                    "AWS IAM: No password policy configured",
                    "The AWS account has no custom password policy — defaults allow weak passwords",
                    format!("cloud://{target_label}"),
                )
                .with_evidence(
                    CloudEvidence::new(CloudProvider::Aws, "iam")
                        .with_check_id("iam-password-policy-missing")
                        .to_string(),
                )
                .with_remediation("Configure an IAM password policy with minimum length, complexity, and rotation requirements.")
                .with_confidence(0.95);
                findings.push(enrich_cloud_finding(finding, "iam"));
            }
            Err(e) => {
                tracing::warn!("aws-iam: failed to fetch password policy: {e}");
                findings.push(permission_finding("GetAccountPasswordPolicy", &target_label));
            }
        }

        Ok(findings)
    }
}

/// Fetch the IAM account summary and extract root-related fields.
async fn fetch_iam_summary(
    client: &aws_sdk_iam::Client,
) -> std::result::Result<AwsIamSummary, aws_sdk_iam::Error> {
    let resp = client.get_account_summary().send().await?;
    let map = resp.summary_map();
    let get_val = |key: aws_sdk_iam::types::SummaryKeyType| -> i32 {
        map.as_ref().and_then(|m| m.get(&key)).copied().unwrap_or(0)
    };
    Ok(AwsIamSummary {
        root_access_keys_present: get_val(
            aws_sdk_iam::types::SummaryKeyType::AccountAccessKeysPresent,
        ) > 0,
        root_mfa_enabled: get_val(aws_sdk_iam::types::SummaryKeyType::AccountMfaEnabled) > 0,
    })
}

/// Fetch the account password policy. Returns `Ok(None)` when no
/// custom policy is configured (AWS returns `NoSuchEntity`).
async fn fetch_password_policy(
    client: &aws_sdk_iam::Client,
) -> std::result::Result<Option<AwsPasswordPolicy>, aws_sdk_iam::Error> {
    match client.get_account_password_policy().send().await {
        Ok(resp) => {
            let Some(p) = resp.password_policy() else {
                return Ok(None);
            };
            let min_len = p.minimum_password_length.unwrap_or(0);
            let max_age = p.max_password_age.unwrap_or(0);
            Ok(Some(AwsPasswordPolicy {
                min_length: u32::try_from(min_len).unwrap_or(0),
                require_symbols: p.require_symbols,
                require_numbers: p.require_numbers,
                require_uppercase: p.require_uppercase_characters,
                require_lowercase: p.require_lowercase_characters,
                max_age_days: if max_age > 0 {
                    Some(u32::try_from(max_age).unwrap_or(0))
                } else {
                    None
                },
            }))
        }
        Err(e) => {
            let svc_err = e.into_service_error();
            if svc_err.is_no_such_entity_exception() {
                Ok(None)
            } else {
                Err(svc_err.into())
            }
        }
    }
}

/// Generate an Info-level "insufficient permissions" finding.
fn permission_finding(api_call: &str, target_label: &str) -> Finding {
    let finding = Finding::new(
        "aws-iam",
        Severity::Info,
        format!("AWS IAM: Insufficient permissions for {api_call}"),
        format!("The IAM credentials lack permission to call {api_call}. Grant iam:{api_call} to the scanning role."),
        format!("cloud://{target_label}"),
    )
    .with_evidence(
        CloudEvidence::new(CloudProvider::Aws, "iam")
            .with_check_id(format!("iam-permission-{}", api_call.to_lowercase()))
            .to_string(),
    )
    .with_confidence(0.5);
    enrich_cloud_finding(finding, "iam")
}

// ---------------------------------------------------------------
// Pure check functions — testable without AWS SDK
// ---------------------------------------------------------------

/// Check root account IAM summary for access keys and MFA.
#[must_use]
pub fn check_iam_summary(summary: &AwsIamSummary, target_label: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if summary.root_access_keys_present {
        let evidence =
            CloudEvidence::new(CloudProvider::Aws, "iam").with_check_id("iam-root-access-keys");
        let finding = Finding::new(
            "aws-iam",
            Severity::Critical,
            "AWS IAM: Root account has access keys",
            "Root access keys exist on the AWS account. Root keys provide unrestricted \
             access and should be deleted in favor of IAM roles.",
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation(
            "Delete root access keys and use IAM roles with least-privilege policies instead.",
        )
        .with_confidence(0.95);
        findings.push(enrich_cloud_finding(finding, "iam"));
    }

    if !summary.root_mfa_enabled {
        let evidence =
            CloudEvidence::new(CloudProvider::Aws, "iam").with_check_id("iam-root-mfa-disabled");
        let finding = Finding::new(
            "aws-iam",
            Severity::Critical,
            "AWS IAM: Root account MFA not enabled",
            "Multi-factor authentication is not enabled on the root account. \
             A compromised root password gives full account access.",
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation(
            "Enable MFA on the root account using a hardware security key or virtual MFA device.",
        )
        .with_confidence(0.95);
        findings.push(enrich_cloud_finding(finding, "iam"));
    }

    findings
}

/// Check password policy against CIS benchmarks.
#[must_use]
pub fn check_password_policy(policy: &AwsPasswordPolicy, target_label: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut weaknesses = Vec::new();

    if policy.min_length < 14 {
        weaknesses.push(format!("minimum length {} (recommend >=14)", policy.min_length));
    }
    if !policy.require_symbols {
        weaknesses.push("symbols not required".to_string());
    }
    if !policy.require_numbers {
        weaknesses.push("numbers not required".to_string());
    }
    if !policy.require_uppercase {
        weaknesses.push("uppercase not required".to_string());
    }
    if !policy.require_lowercase {
        weaknesses.push("lowercase not required".to_string());
    }
    if policy.max_age_days.is_none() {
        weaknesses.push("no password rotation".to_string());
    } else if policy.max_age_days.is_some_and(|d| d > 90) {
        weaknesses.push(format!(
            "rotation period {} days (recommend <=90)",
            policy.max_age_days.unwrap_or(0)
        ));
    }

    if !weaknesses.is_empty() {
        let evidence = CloudEvidence::new(CloudProvider::Aws, "iam")
            .with_check_id("iam-weak-password-policy")
            .with_detail("weaknesses", weaknesses.join("; "));
        let finding = Finding::new(
            "aws-iam",
            Severity::Medium,
            "AWS IAM: Weak password policy",
            format!("The IAM password policy has weaknesses: {}", weaknesses.join(", ")),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation(
            "Strengthen the password policy: minimum 14 chars, require all character types, \
             max 90-day rotation.",
        )
        .with_confidence(0.9);
        findings.push(enrich_cloud_finding(finding, "iam"));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Root access keys present → Critical finding.
    #[test]
    fn test_iam_root_keys_finding() {
        let summary = AwsIamSummary { root_access_keys_present: true, root_mfa_enabled: true };
        let findings = check_iam_summary(&summary, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("access keys"));
        assert!(findings[0].compliance.is_some());
    }

    /// Root MFA missing → Critical finding.
    #[test]
    fn test_iam_root_mfa_missing() {
        let summary = AwsIamSummary { root_access_keys_present: false, root_mfa_enabled: false };
        let findings = check_iam_summary(&summary, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("MFA"));
    }

    /// Weak password policy → Medium finding.
    #[test]
    fn test_iam_weak_password_policy() {
        let policy = AwsPasswordPolicy {
            min_length: 8,
            require_symbols: false,
            require_numbers: true,
            require_uppercase: true,
            require_lowercase: true,
            max_age_days: None,
        };
        let findings = check_password_policy(&policy, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("Weak password policy"));
    }

    /// Secure account → zero findings.
    #[test]
    fn test_iam_clean_account() {
        let summary = AwsIamSummary { root_access_keys_present: false, root_mfa_enabled: true };
        let findings = check_iam_summary(&summary, "aws:123456789012");
        assert!(findings.is_empty());

        let policy = AwsPasswordPolicy {
            min_length: 14,
            require_symbols: true,
            require_numbers: true,
            require_uppercase: true,
            require_lowercase: true,
            max_age_days: Some(90),
        };
        let findings = check_password_policy(&policy, "aws:123456789012");
        assert!(findings.is_empty());
    }

    /// Module metadata pins.
    #[test]
    fn test_iam_module_metadata() {
        let m = IamCloudModule;
        assert_eq!(m.id(), "aws-iam");
        assert_eq!(m.category(), CloudCategory::Iam);
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
        assert!(!m.requires_external_tool());
    }
}
