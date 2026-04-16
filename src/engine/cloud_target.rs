//! Target representation for cloud-posture scanning.
//!
//! Unlike [`super::target::Target`] (URL-centric, DAST) and
//! [`super::infra_target::InfraTarget`] (IP / CIDR / host / endpoint,
//! infra), cloud scanning operates on cloud accounts, projects,
//! subscriptions, and Kubernetes contexts. [`CloudTarget`] captures
//! each first-class form.
//!
//! ## Prefix-dispatched parser
//!
//! [`CloudTarget::parse`] uses explicit prefixes rather than shape
//! inference. Cloud identifiers don't have distinguishing syntactic
//! fingerprints — AWS 12-digit account numerics collide with port
//! numbers, GCP project IDs are hostname-shaped, Azure subscription
//! GUIDs are ambiguous. Requiring `aws:` / `gcp:` / `azure:` / `k8s:`
//! prefixes (or the literal `all`) sidesteps the ambiguity and
//! self-documents the operator's intent.

use super::error::{Result, ScorchError};

/// A target for a cloud-posture scan.
///
/// Accepted input forms (parsed by [`CloudTarget::parse`]):
///
/// - `aws:123456789012` — AWS 12-digit account ID
/// - `gcp:my-project` — GCP project ID
/// - `azure:abcd-ef01-...` — Azure subscription GUID
/// - `k8s:prod-cluster` — Kubernetes context name from kubeconfig
/// - `all` (case-insensitive) — scan every configured provider
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudTarget {
    /// AWS account (12-digit numeric ID or account alias).
    Account(String),
    /// GCP project (alphanumeric + dash/underscore).
    Project(String),
    /// Azure subscription ID (typically a GUID).
    Subscription(String),
    /// Kubernetes context name from kubeconfig.
    KubeContext(String),
    /// Aggregate target — the orchestrator fans modules out across
    /// every configured credential source.
    All,
}

impl CloudTarget {
    /// Parse a cloud target string using prefix dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`ScorchError::InvalidTarget`] when the input is empty,
    /// whitespace-only, or lacks a recognised prefix.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ScorchError::InvalidTarget {
                target: input.to_string(),
                reason: "empty cloud target".to_string(),
            });
        }
        if trimmed.eq_ignore_ascii_case("all") {
            return Ok(Self::All);
        }
        if let Some(rest) = trimmed.strip_prefix("aws:") {
            return Ok(Self::Account(rest.to_string()));
        }
        if let Some(rest) = trimmed.strip_prefix("gcp:") {
            return Ok(Self::Project(rest.to_string()));
        }
        if let Some(rest) = trimmed.strip_prefix("azure:") {
            return Ok(Self::Subscription(rest.to_string()));
        }
        if let Some(rest) = trimmed.strip_prefix("k8s:") {
            return Ok(Self::KubeContext(rest.to_string()));
        }
        Err(ScorchError::InvalidTarget {
            target: input.to_string(),
            reason: "expected prefix aws: / gcp: / azure: / k8s: or literal 'all'".to_string(),
        })
    }

    /// Human-readable representation. Round-trips [`CloudTarget::parse`]
    /// for every variant.
    #[must_use]
    pub fn display_raw(&self) -> String {
        match self {
            Self::Account(id) => format!("aws:{id}"),
            Self::Project(p) => format!("gcp:{p}"),
            Self::Subscription(s) => format!("azure:{s}"),
            Self::KubeContext(c) => format!("k8s:{c}"),
            Self::All => "all".to_string(),
        }
    }
}

impl std::fmt::Display for CloudTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_target_parse_aws() {
        let t = CloudTarget::parse("aws:123456789012").expect("parse");
        match t {
            CloudTarget::Account(id) => assert_eq!(id, "123456789012"),
            other => panic!("expected Account, got {other:?}"),
        }
    }

    #[test]
    fn test_cloud_target_parse_gcp_azure_k8s() {
        let gcp = CloudTarget::parse("gcp:my-project").expect("parse gcp");
        assert!(matches!(gcp, CloudTarget::Project(ref p) if p == "my-project"));

        let azure = CloudTarget::parse("azure:abcd-1234").expect("parse azure");
        assert!(matches!(azure, CloudTarget::Subscription(ref s) if s == "abcd-1234"));

        let k8s = CloudTarget::parse("k8s:prod-cluster").expect("parse k8s");
        assert!(matches!(k8s, CloudTarget::KubeContext(ref c) if c == "prod-cluster"));
    }

    #[test]
    fn test_cloud_target_parse_all_case_insensitive() {
        for s in ["all", "ALL", "All", "aLL"] {
            let t = CloudTarget::parse(s).expect("parse");
            assert_eq!(t, CloudTarget::All);
        }
    }

    #[test]
    fn test_cloud_target_parse_errors() {
        assert!(CloudTarget::parse("").is_err());
        assert!(CloudTarget::parse("   ").is_err());
        assert!(CloudTarget::parse("no-prefix").is_err());
        assert!(CloudTarget::parse("unknown:foo").is_err());
    }

    #[test]
    fn test_cloud_target_display_round_trip() {
        let cases = ["aws:123456789012", "gcp:my-project", "azure:abcd-1234", "k8s:prod-cluster"];
        for case in cases {
            let t = CloudTarget::parse(case).expect("parse");
            assert_eq!(t.display_raw(), case);
        }
        // `all` round-trips lowercase regardless of input casing.
        assert_eq!(CloudTarget::All.display_raw(), "all");
    }
}
