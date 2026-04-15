//! Target representation for infrastructure scanning.
//!
//! Unlike [`super::target::Target`] (URL-centric, used by DAST / `ScanModule`)
//! and the path-based targets used by SAST / `CodeModule`, infra scanning
//! operates on hosts, IP addresses, and CIDR ranges. [`InfraTarget`] is the
//! sum type that captures all five useful shapes.

use std::net::IpAddr;

use ipnet::IpNet;

use super::error::{Result, ScorchError};

/// A target for an infra scan.
///
/// The [`InfraTarget::parse`] constructor accepts any of the following string
/// forms:
///
/// - Bare IPv4/IPv6 address — `"192.0.2.1"`, `"::1"`
/// - CIDR range — `"10.0.0.0/24"`, `"2001:db8::/32"`
/// - Hostname — `"example.com"` (DNS resolution is a future concern — see
///   [`InfraTarget::iter_ips`])
/// - Host:port endpoint — `"example.com:22"`, `"[2001:db8::1]:443"`
///
/// The [`InfraTarget::Multi`] variant exists so a discovery step can emit a
/// list of targets from an earlier probe. The parser never returns `Multi`
/// directly — callers build it explicitly.
#[derive(Debug, Clone)]
pub enum InfraTarget {
    /// A single IPv4 or IPv6 address.
    Ip(IpAddr),
    /// A CIDR range.
    Cidr(IpNet),
    /// A hostname that may resolve to one or more IPs.
    Host(String),
    /// A host-plus-port endpoint.
    Endpoint {
        /// The host portion (hostname or IP string).
        host: String,
        /// The TCP/UDP port.
        port: u16,
    },
    /// A composite of multiple targets (typically produced by a discovery step).
    Multi(Vec<Self>),
}

impl InfraTarget {
    /// Parse an infra target from a string.
    ///
    /// Tries the recognized forms in order: CIDR → bare IP → host:port → host.
    /// The first that succeeds wins.
    ///
    /// # Errors
    ///
    /// Returns [`ScorchError::InvalidTarget`] if the input is empty or does
    /// not match any recognised form.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ScorchError::InvalidTarget {
                target: input.to_string(),
                reason: "empty infra target".to_string(),
            });
        }

        // CIDR first — "/" disambiguates before IP parsing.
        if trimmed.contains('/') {
            if let Ok(net) = trimmed.parse::<IpNet>() {
                return Ok(Self::Cidr(net));
            }
        }

        // Bare IP (IPv4 or IPv6).
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }

        // Host:port endpoint — bracketed IPv6 form `[::1]:443` or plain
        // `host:port`. Only treat as endpoint if there's exactly one `:`
        // (avoids misparsing IPv6 literals).
        if let Some(endpoint) = parse_endpoint(trimmed) {
            return Ok(endpoint);
        }

        // Fallback — treat as hostname. Basic sanity: non-empty, contains
        // only host-like characters.
        if is_hostname_shape(trimmed) {
            return Ok(Self::Host(trimmed.to_string()));
        }

        Err(ScorchError::InvalidTarget {
            target: input.to_string(),
            reason: "not a recognised infra target form".to_string(),
        })
    }

    /// Flatten this target into its individual IP addresses.
    ///
    /// - [`InfraTarget::Ip`] and [`InfraTarget::Endpoint`] yield a single IP
    ///   (the latter only if `host` parses as an IP).
    /// - [`InfraTarget::Cidr`] uses [`ipnet::IpNet::hosts`] semantics, which
    ///   skips the network and broadcast addresses for IPv4 `/31` and larger.
    /// - [`InfraTarget::Host`] returns an empty iterator — DNS resolution is
    ///   an explicit step the caller must perform (see WORK-102+).
    /// - [`InfraTarget::Multi`] chains its children.
    #[must_use]
    pub fn iter_ips(&self) -> Box<dyn Iterator<Item = IpAddr> + '_> {
        match self {
            Self::Ip(ip) => Box::new(std::iter::once(*ip)),
            Self::Cidr(net) => Box::new(net.hosts()),
            Self::Endpoint { host, .. } => host.parse::<IpAddr>().map_or_else(
                |_| Box::new(std::iter::empty()) as Box<dyn Iterator<Item = IpAddr>>,
                |ip| Box::new(std::iter::once(ip)) as Box<dyn Iterator<Item = IpAddr>>,
            ),
            Self::Host(_) => Box::new(std::iter::empty()),
            Self::Multi(children) => Box::new(children.iter().flat_map(Self::iter_ips)),
        }
    }

    /// Human-readable representation. Round-trips [`InfraTarget::parse`] for
    /// every variant except `Multi`, which joins children with `", "`.
    #[must_use]
    pub fn display_raw(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Cidr(net) => net.to_string(),
            Self::Host(host) => host.clone(),
            Self::Endpoint { host, port } => {
                if host.contains(':') && !host.starts_with('[') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                }
            }
            Self::Multi(children) => {
                children.iter().map(Self::display_raw).collect::<Vec<_>>().join(", ")
            }
        }
    }
}

impl std::fmt::Display for InfraTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_raw())
    }
}

/// Parse a `host:port` endpoint, supporting bracketed IPv6 form.
fn parse_endpoint(s: &str) -> Option<InfraTarget> {
    // Bracketed form: [::1]:443
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            let host = &rest[..idx];
            let after = &rest[idx + 1..];
            let port_str = after.strip_prefix(':')?;
            let port: u16 = port_str.parse().ok()?;
            // Validate the host is an IPv6 literal.
            host.parse::<IpAddr>().ok()?;
            return Some(InfraTarget::Endpoint { host: host.to_string(), port });
        }
        return None;
    }

    // Plain form: host:port — require exactly one ':' to avoid IPv6 literals.
    let parts: Vec<&str> = s.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let port: u16 = parts[0].parse().ok()?;
    let host = parts[1];
    if host.is_empty() || host.contains(':') {
        // Multi-colon → IPv6 or malformed; reject.
        return None;
    }
    Some(InfraTarget::Endpoint { host: host.to_string(), port })
}

/// Loose sanity check for hostnames: non-empty, made of letters, digits,
/// dots, hyphens, and underscores.
fn is_hostname_shape(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        && !s.starts_with('-')
        && !s.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_infra_target_parse_ipv4() {
        let t = InfraTarget::parse("192.0.2.1").expect("parse");
        match t {
            InfraTarget::Ip(IpAddr::V4(v4)) => assert_eq!(v4, Ipv4Addr::new(192, 0, 2, 1)),
            other => panic!("expected Ip(v4), got {other:?}"),
        }
    }

    #[test]
    fn test_infra_target_parse_ipv6() {
        let t = InfraTarget::parse("::1").expect("parse");
        match t {
            InfraTarget::Ip(IpAddr::V6(v6)) => assert_eq!(v6, Ipv6Addr::LOCALHOST),
            other => panic!("expected Ip(v6), got {other:?}"),
        }
    }

    #[test]
    fn test_infra_target_parse_cidr_v4() {
        let t = InfraTarget::parse("10.0.0.0/24").expect("parse");
        assert!(matches!(t, InfraTarget::Cidr(_)));
    }

    #[test]
    fn test_infra_target_parse_cidr_v6() {
        let t = InfraTarget::parse("2001:db8::/32").expect("parse");
        assert!(matches!(t, InfraTarget::Cidr(_)));
    }

    #[test]
    fn test_infra_target_parse_host() {
        let t = InfraTarget::parse("example.com").expect("parse");
        match t {
            InfraTarget::Host(h) => assert_eq!(h, "example.com"),
            other => panic!("expected Host, got {other:?}"),
        }
    }

    #[test]
    fn test_infra_target_parse_endpoint_plain() {
        let t = InfraTarget::parse("example.com:22").expect("parse");
        match t {
            InfraTarget::Endpoint { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 22);
            }
            other => panic!("expected Endpoint, got {other:?}"),
        }
    }

    #[test]
    fn test_infra_target_parse_endpoint_ipv6_bracketed() {
        let t = InfraTarget::parse("[2001:db8::1]:443").expect("parse");
        match t {
            InfraTarget::Endpoint { host, port } => {
                assert_eq!(host, "2001:db8::1");
                assert_eq!(port, 443);
            }
            other => panic!("expected Endpoint, got {other:?}"),
        }
    }

    #[test]
    fn test_infra_target_parse_invalid() {
        assert!(InfraTarget::parse("").is_err());
        assert!(InfraTarget::parse("   ").is_err());
        assert!(InfraTarget::parse("bad host with spaces").is_err());
    }

    #[test]
    fn test_infra_target_cidr_expansion_count_v4() {
        let t = InfraTarget::parse("10.0.0.0/30").expect("parse");
        // IpNet::hosts skips network (.0) and broadcast (.3) — leaving 2 usable.
        let ips: Vec<_> = t.iter_ips().collect();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_infra_target_cidr_expansion_first_last_v4() {
        let t = InfraTarget::parse("10.0.0.0/30").expect("parse");
        let ips: Vec<IpAddr> = t.iter_ips().collect();
        assert_eq!(ips.first(), Some(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(ips.last(), Some(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn test_infra_target_multi_iter_chains_children() {
        let multi = InfraTarget::Multi(vec![
            InfraTarget::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            InfraTarget::Endpoint { host: "192.0.2.5".to_string(), port: 80 },
        ]);
        let ips: Vec<_> = multi.iter_ips().collect();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_infra_target_display_raw() {
        // Round-trip via parse → display.
        let cases = ["192.0.2.1", "::1", "10.0.0.0/24", "example.com", "example.com:22"];
        for case in cases {
            let t = InfraTarget::parse(case).expect("parse");
            assert_eq!(t.display_raw(), case);
        }
    }

    #[test]
    fn test_host_with_underscore() {
        // Some hostnames have underscores (SRV records, Docker containers).
        let t = InfraTarget::parse("my_service.internal").expect("parse");
        assert!(matches!(t, InfraTarget::Host(_)));
    }

    #[test]
    fn test_unbracketed_ipv6_with_trailing_port_parses_as_ipv6() {
        // `2001:db8::1:443` is a syntactically valid IPv6 address (the
        // trailing `:443` is the last group, not a port). The parser
        // correctly returns an `Ip` variant — IPv6 endpoints require
        // bracket notation `[...]:port`.
        let t = InfraTarget::parse("2001:db8::1:443").expect("parse");
        assert!(matches!(t, InfraTarget::Ip(IpAddr::V6(_))));
    }
}
