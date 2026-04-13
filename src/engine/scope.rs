//! Enhanced scope management with CIDR, wildcard, and exact matching.
//!
//! Provides `ScopeRule` for defining what targets are in scope, and
//! `is_in_scope()` for checking URLs against a set of rules. Supports
//! exact domain matches, wildcard patterns (`*.example.com`), and
//! CIDR ranges (`192.168.1.0/24`).

use std::net::Ipv4Addr;

/// A scope rule that determines whether a target is in scope.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            let addr: Ipv4Addr = ip_str.parse().ok()?;
            let prefix: u32 = prefix_str.parse().ok()?;
            if prefix > 32 {
                return None;
            }
            let network = u32::from(addr);
            let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            return Some(Self::Cidr { network: network & mask, mask });
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
        }
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

    /// Verify out-of-scope rejection with is_in_scope().
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
