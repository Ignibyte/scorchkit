//! Enhanced scope management with CIDR, wildcard, and exact matching.
//!
//! Provides `ScopeRule` for defining what targets are in scope, and
//! `is_in_scope()` for checking URLs against a set of rules. Supports
//! exact domain matches, wildcard patterns (`*.example.com`), and
//! CIDR ranges (`192.168.1.0/24`).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A scope rule that determines whether a target is in scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ScopeRule {
    /// Exact domain or IP match (e.g., "example.com", "192.168.1.1").
    Exact(String),
    /// Wildcard domain match (e.g., "*.example.com" matches "sub.example.com").
    Wildcard(String),
    /// CIDR range match (e.g., "192.168.1.0/24").
    Cidr {
        /// Network address as a 32-bit integer.
        network: u32,
        /// Subnet mask as a 32-bit integer.
        mask: u32,
    },
    /// IPv6 CIDR range (e.g., `2001:db8::/32`).
    CidrV6 {
        /// Network address as a 128-bit integer.
        #[serde(with = "u128_decimal")]
        network: u128,
        /// Subnet mask as a 128-bit integer.
        #[serde(with = "u128_decimal")]
        mask: u128,
    },
    /// Canonical filesystem path prefix permitted for code scanning.
    PathPrefix(PathBuf),
    /// Exact cloud account, project, subscription, or Kubernetes target.
    Cloud(String),
}

mod u128_decimal {
    use std::fmt;

    use serde::de::Visitor;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct U128Visitor;

        impl Visitor<'_> for U128Visitor {
            type Value = u128;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a decimal u128 string or unsigned integer")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(u128::from(value))
            }

            fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(value)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(U128Visitor)
    }
}

impl ScopeRule {
    /// Parse a scope rule string, auto-detecting the type.
    ///
    /// - `*.example.com` → `Wildcard`
    /// - `192.168.1.0/24` → `Cidr`
    /// - Everything else → `Exact`
    ///
    /// Returns `None` if a CIDR range has an invalid IP or prefix length.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        let trimmed = input.trim();

        if let Some(suffix) = trimmed.strip_prefix("*.") {
            return Some(Self::Wildcard(suffix.to_lowercase()));
        }

        if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
            let prefix: u32 = prefix_str.parse().ok()?;
            if let Ok(addr) = ip_str.parse::<Ipv4Addr>() {
                if prefix > 32 {
                    return None;
                }
                let network = u32::from(addr);
                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                return Some(Self::Cidr { network: network & mask, mask });
            }
            if let Ok(addr) = ip_str.parse::<Ipv6Addr>() {
                if prefix > 128 {
                    return None;
                }
                let network = u128::from(addr);
                let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                return Some(Self::CidrV6 { network: network & mask, mask });
            }
            return None;
        }

        Some(Self::Exact(trimmed.to_lowercase()))
    }

    /// Check if a host (domain or IP) matches this scope rule.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();

        match self {
            Self::Exact(domain) => host_lower == *domain,
            Self::Wildcard(suffix) => {
                host_lower.ends_with(suffix)
                    && host_lower.len() > suffix.len()
                    && host_lower.as_bytes()[host_lower.len() - suffix.len() - 1] == b'.'
            }
            Self::Cidr { network, mask } => {
                host.parse::<Ipv4Addr>().is_ok_and(|addr| (u32::from(addr) & mask) == *network)
            }
            Self::CidrV6 { network, mask } => {
                host.parse::<Ipv6Addr>().is_ok_and(|addr| (u128::from(addr) & mask) == *network)
            }
            Self::PathPrefix(_) | Self::Cloud(_) => false,
        }
    }

    /// Build a filesystem scope rule from an existing directory or file.
    ///
    /// Canonicalization resolves symlinks before the rule is stored, preventing
    /// a path that appears to be under an allowed directory from escaping it.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the path does not exist or cannot be canonicalized.
    pub fn path_prefix(path: &Path) -> std::io::Result<Self> {
        path.canonicalize().map(Self::PathPrefix)
    }

    /// Build an exact cloud-resource scope rule.
    #[must_use]
    pub fn cloud(resource: impl Into<String>) -> Self {
        Self::Cloud(resource.into())
    }

    /// Check whether a code path is covered by this rule.
    #[must_use]
    pub fn matches_path(&self, path: &Path) -> bool {
        match self {
            Self::PathPrefix(prefix) => {
                path.canonicalize().is_ok_and(|canonical| canonical.starts_with(prefix))
            }
            _ => false,
        }
    }

    /// Check whether a cloud target is covered by this rule.
    #[must_use]
    pub fn matches_cloud(&self, resource: &str) -> bool {
        matches!(self, Self::Cloud(allowed) if allowed == resource)
    }

    /// Check a host, address, endpoint, or CIDR requested by an infrastructure scan.
    #[must_use]
    pub fn matches_network(&self, target: &str) -> bool {
        if self.matches(target) {
            return true;
        }

        if let Some((address, prefix)) = target.split_once('/') {
            if let (Ok(address), Ok(prefix)) = (address.parse::<Ipv4Addr>(), prefix.parse::<u32>())
            {
                return match self {
                    Self::Cidr { network, mask } if prefix <= 32 => {
                        prefix >= mask.count_ones() && (u32::from(address) & mask) == *network
                    }
                    _ => false,
                };
            }
            if let (Ok(address), Ok(prefix)) = (address.parse::<Ipv6Addr>(), prefix.parse::<u32>())
            {
                return match self {
                    Self::CidrV6 { network, mask } if prefix <= 128 => {
                        prefix >= mask.count_ones() && (u128::from(address) & mask) == *network
                    }
                    _ => false,
                };
            }
        }

        let host = extract_network_host(target);
        self.matches(host)
    }
}

/// Check if a URL's host is in scope according to the given rules.
///
/// Extracts the host from the URL and checks it against each rule.
/// Returns `true` if any rule matches, or if `rules` is empty (no
/// scope restrictions = everything in scope).
#[must_use]
pub fn is_in_scope(url: &str, rules: &[ScopeRule]) -> bool {
    if rules.is_empty() {
        return true;
    }

    let host = extract_host(url);
    rules.iter().any(|rule| rule.matches(host))
}

/// Extract the host portion from a URL string.
fn extract_host(url: &str) -> &str {
    let without_scheme =
        url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).unwrap_or(url);

    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
}

/// Remove endpoint syntax while preserving bare IPv6 addresses.
fn extract_network_host(target: &str) -> &str {
    if let Some(rest) = target.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    if target.matches(':').count() == 1 {
        return target.split(':').next().unwrap_or(target);
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify exact domain matching.
    #[test]
    fn test_scope_exact() {
        let rule = ScopeRule::parse("example.com").unwrap();
        assert!(rule.matches("example.com"));
        assert!(rule.matches("Example.Com"));
        assert!(!rule.matches("sub.example.com"));
        assert!(!rule.matches("notexample.com"));
    }

    /// Verify wildcard domain matching.
    #[test]
    fn test_scope_wildcard() {
        let rule = ScopeRule::parse("*.example.com").unwrap();
        assert!(rule.matches("sub.example.com"));
        assert!(rule.matches("deep.sub.example.com"));
        assert!(!rule.matches("example.com"));
        assert!(!rule.matches("notexample.com"));
    }

    /// Verify CIDR range matching.
    #[test]
    fn test_scope_cidr() {
        let rule = ScopeRule::parse("192.168.1.0/24").unwrap();
        assert!(rule.matches("192.168.1.1"));
        assert!(rule.matches("192.168.1.254"));
        assert!(!rule.matches("192.168.2.1"));
        assert!(!rule.matches("10.0.0.1"));
        // Non-IP hosts don't match CIDR
        assert!(!rule.matches("example.com"));
    }

    #[test]
    fn test_scope_ipv6_cidr() {
        let rule = ScopeRule::parse("2001:db8::/32").unwrap();
        assert!(rule.matches("2001:db8::1"));
        assert!(!rule.matches("2001:db9::1"));
        assert!(rule.matches_network("2001:db8:1::/48"));
        assert!(!rule.matches_network("2001:db8::/16"));
    }

    #[test]
    fn ipv6_scope_round_trips_through_json_without_numeric_loss() {
        let rule = ScopeRule::CidrV6 { network: 1, mask: u128::MAX };
        let encoded = serde_json::to_value(&rule).unwrap();
        assert_eq!(encoded["value"]["network"], "1");
        assert_eq!(encoded["value"]["mask"], u128::MAX.to_string());
        assert_eq!(serde_json::from_value::<ScopeRule>(encoded).unwrap(), rule);

        let legacy = serde_json::json!({
            "kind": "cidr_v6",
            "value": {"network": 1, "mask": 1}
        });
        assert_eq!(
            serde_json::from_value::<ScopeRule>(legacy).unwrap(),
            ScopeRule::CidrV6 { network: 1, mask: 1 }
        );

        let direct = u128_decimal::deserialize(serde::de::value::U128Deserializer::<
            serde::de::value::Error,
        >::new(u128::MAX))
        .expect("u128 visitor must preserve the complete value");
        assert_eq!(direct, u128::MAX);

        let invalid = serde_json::json!({
            "kind": "cidr_v6",
            "value": {"network": true, "mask": "1"}
        });
        let error = serde_json::from_value::<ScopeRule>(invalid)
            .expect_err("booleans are not valid u128 values")
            .to_string();
        assert!(error.contains("a decimal u128 string or unsigned integer"));
    }

    #[test]
    fn test_scope_network_cidr_cannot_expand_grant() {
        let rule = ScopeRule::parse("10.0.0.0/24").unwrap();
        assert!(rule.matches_network("10.0.0.128/25"));
        assert!(!rule.matches_network("10.0.0.0/16"));
        assert!(!rule.matches_network("10.0.0.1/33"));
        assert!(rule.matches_network("10.0.0.8:443"));
    }

    #[test]
    fn test_scope_cidr_prefix_boundaries() {
        assert!(ScopeRule::parse("192.0.2.1/32").is_some());
        assert!(ScopeRule::parse("192.0.2.1/33").is_none());
        assert!(ScopeRule::parse("2001:db8::1/128").is_some());
        assert!(ScopeRule::parse("2001:db8::1/129").is_none());

        let ipv6 = ScopeRule::parse("2001:db8::/32").unwrap();
        assert!(!ipv6.matches_network("2001:db8::1/129"));
    }

    #[test]
    fn test_scope_path_prefix_canonicalizes_paths() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("src");
        std::fs::create_dir(&child).unwrap();
        let rule = ScopeRule::path_prefix(root.path()).unwrap();
        assert!(rule.matches_path(&child));
        assert!(!rule.matches_path(std::path::Path::new("/")));
    }

    #[cfg(unix)]
    #[test]
    fn test_scope_path_prefix_blocks_symlink_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let link = root.path().join("escape");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        let rule = ScopeRule::path_prefix(root.path()).unwrap();
        assert!(!rule.matches_path(&link));
    }

    #[test]
    fn test_scope_cloud_exact() {
        let rule = ScopeRule::cloud("aws:123456789012");
        assert!(rule.matches_cloud("aws:123456789012"));
        assert!(!rule.matches_cloud("aws:999999999999"));
    }

    /// Verify out-of-scope rejection with `is_in_scope()`.
    #[test]
    fn test_scope_out_of_scope() {
        let rules = vec![
            ScopeRule::parse("example.com").unwrap(),
            ScopeRule::parse("*.example.com").unwrap(),
        ];
        assert!(is_in_scope("https://example.com/path", &rules));
        assert!(is_in_scope("https://api.example.com/v1", &rules));
        assert!(!is_in_scope("https://evil.com", &rules));

        // Empty rules = everything in scope
        assert!(is_in_scope("https://anything.com", &[]));
    }
}
