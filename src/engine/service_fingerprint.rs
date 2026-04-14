//! Service fingerprint data type and nmap XML parser.
//!
//! Extracted from the DAST `tools::nmap` wrapper so both DAST
//! ([`crate::engine::module_trait::ScanModule`]) and infra
//! ([`crate::engine::infra_module::InfraModule`]) code paths share a single
//! parser. Downstream CVE correlation (WORK-103) consumes fingerprints via
//! [`read_fingerprints`] after a port-scan module [`publish_fingerprints`]s
//! them to the shared-data store.

use serde::{Deserialize, Serialize};

use super::shared_data::SharedData;

/// Well-known `SharedData` key for published service fingerprints.
pub const SHARED_KEY_FINGERPRINTS: &str = "infra.service_fingerprints";

/// A single port's service fingerprint as extracted from an nmap run.
///
/// `product`, `version`, and `cpe` are optional because nmap's `-sV`
/// service detection can leave them blank on unknown services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    /// TCP/UDP port number.
    pub port: u16,
    /// Transport protocol (typically `"tcp"` or `"udp"`).
    pub protocol: String,
    /// Service name as reported by nmap (`"http"`, `"ssh"`, `"mysql"`, ...).
    pub service_name: String,
    /// Product name if detected (`"nginx"`, `"OpenSSH"`, `"MySQL"`).
    pub product: Option<String>,
    /// Version string if detected (`"1.18.0"`, `"8.9p1"`).
    pub version: Option<String>,
    /// CPE 2.3 identifier when a product + version pair is known.
    pub cpe: Option<String>,
}

/// Parse nmap XML output into a list of [`ServiceFingerprint`]s.
///
/// Only emits a fingerprint for ports whose `<state>` element says
/// `"open"`. Unknown / missing attributes default to empty strings or
/// `None`; callers that need richer classification apply it after this
/// pure parse step.
#[must_use]
pub fn parse_nmap_xml_fingerprints(xml: &str) -> Vec<ServiceFingerprint> {
    let mut out = Vec::new();

    for port_block in xml.split("<port ") {
        if !port_block.contains("state=\"open\"") {
            continue;
        }

        let port_id = extract_xml_attr(port_block, "portid").unwrap_or_default();
        let port: u16 = match port_id.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let protocol =
            extract_xml_attr(port_block, "protocol").unwrap_or_else(|| "tcp".to_string());
        let service_name =
            extract_xml_attr(port_block, "name").unwrap_or_else(|| "unknown".to_string());
        let product = extract_xml_attr(port_block, "product").filter(|s| !s.is_empty());
        let version = extract_xml_attr(port_block, "version").filter(|s| !s.is_empty());

        let cpe = match (&product, &version) {
            (Some(p), Some(v)) => Some(build_cpe(p, p, v)),
            _ => None,
        };

        out.push(ServiceFingerprint { port, protocol, service_name, product, version, cpe });
    }

    out
}

/// Build a CPE 2.3 identifier from vendor, product, and version components.
///
/// The format is `cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*`.
/// Empty components are replaced with `*`. Callers who only know the
/// product may pass it as both `vendor` and `product` (this is how nmap
/// output maps onto CPE — nmap reports the product name without a vendor).
#[must_use]
pub fn build_cpe(vendor: &str, product: &str, version: &str) -> String {
    let v = if vendor.trim().is_empty() { "*" } else { vendor };
    let p = if product.trim().is_empty() { "*" } else { product };
    let ver = if version.trim().is_empty() { "*" } else { version };
    format!("cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*")
}

/// Publish fingerprints to [`SharedData`] under [`SHARED_KEY_FINGERPRINTS`].
///
/// Each fingerprint is JSON-encoded into a single string because
/// `SharedData` stores `Vec<String>`. Callers read them back via
/// [`read_fingerprints`].
pub fn publish_fingerprints(shared: &SharedData, fingerprints: &[ServiceFingerprint]) {
    if fingerprints.is_empty() {
        return;
    }
    let encoded: Vec<String> =
        fingerprints.iter().filter_map(|fp| serde_json::to_string(fp).ok()).collect();
    shared.publish(SHARED_KEY_FINGERPRINTS, encoded);
}

/// Read and decode every fingerprint published under
/// [`SHARED_KEY_FINGERPRINTS`].
///
/// Silently drops entries that fail to deserialize — this is a best-effort
/// consumer; a malformed entry from one publisher shouldn't hide the rest.
#[must_use]
pub fn read_fingerprints(shared: &SharedData) -> Vec<ServiceFingerprint> {
    shared
        .get(SHARED_KEY_FINGERPRINTS)
        .into_iter()
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect()
}

/// Extract an XML attribute value from a fragment. Simplified; returns
/// `None` when the attribute is missing or the value quote is unbalanced.
fn extract_xml_attr(xml: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{attr_name}=\"");
    let start = xml.find(&pattern)? + pattern.len();
    let end = xml[start..].find('"')? + start;
    Some(xml[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_XML: &str = r#"<?xml version="1.0"?>
<nmaprun>
<host><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.30"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/><service name="abyss"/></port>
</ports></host>
</nmaprun>"#;

    #[test]
    fn test_parse_nmap_xml_fingerprints_multi_port() {
        let fps = parse_nmap_xml_fingerprints(SAMPLE_XML);
        assert_eq!(fps.len(), 3, "closed port should be skipped");

        assert_eq!(fps[0].port, 80);
        assert_eq!(fps[0].service_name, "http");
        assert_eq!(fps[0].product.as_deref(), Some("nginx"));
        assert_eq!(fps[0].version.as_deref(), Some("1.18.0"));
        assert!(fps[0].cpe.as_ref().unwrap().contains("nginx"));

        assert_eq!(fps[2].port, 3306);
        assert_eq!(fps[2].service_name, "mysql");
    }

    #[test]
    fn test_parse_nmap_xml_fingerprints_skips_closed() {
        let xml = r#"<port protocol="tcp" portid="22"><state state="closed"/></port>"#;
        assert!(parse_nmap_xml_fingerprints(xml).is_empty());
    }

    #[test]
    fn test_parse_nmap_xml_fingerprints_empty() {
        assert!(parse_nmap_xml_fingerprints("").is_empty());
        assert!(parse_nmap_xml_fingerprints("<not_nmap/>").is_empty());
    }

    #[test]
    fn test_parse_nmap_xml_fingerprints_missing_fields() {
        let xml = r#"<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>"#;
        let fps = parse_nmap_xml_fingerprints(xml);
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].port, 80);
        assert!(fps[0].product.is_none());
        assert!(fps[0].version.is_none());
        assert!(fps[0].cpe.is_none());
    }

    #[test]
    fn test_build_cpe_standard() {
        let cpe = build_cpe("nginx", "nginx", "1.18.0");
        assert_eq!(cpe, "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*");
    }

    #[test]
    fn test_build_cpe_different_vendor_product() {
        let cpe = build_cpe("apache", "httpd", "2.4.58");
        assert_eq!(cpe, "cpe:2.3:a:apache:httpd:2.4.58:*:*:*:*:*:*:*");
    }

    #[test]
    fn test_build_cpe_blanks_become_wildcards() {
        assert_eq!(build_cpe("", "", ""), "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*");
    }

    #[test]
    fn test_publish_and_read_fingerprints_round_trip() {
        let shared = SharedData::new();
        let input = vec![
            ServiceFingerprint {
                port: 443,
                protocol: "tcp".into(),
                service_name: "https".into(),
                product: Some("nginx".into()),
                version: Some("1.25.0".into()),
                cpe: Some(build_cpe("nginx", "nginx", "1.25.0")),
            },
            ServiceFingerprint {
                port: 22,
                protocol: "tcp".into(),
                service_name: "ssh".into(),
                product: Some("OpenSSH".into()),
                version: None,
                cpe: None,
            },
        ];
        publish_fingerprints(&shared, &input);
        let out = read_fingerprints(&shared);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].port, 443);
        assert_eq!(out[1].port, 22);
        assert!(out[1].version.is_none());
    }

    #[test]
    fn test_read_fingerprints_empty() {
        let shared = SharedData::new();
        assert!(read_fingerprints(&shared).is_empty());
    }

    #[test]
    fn test_publish_empty_is_noop() {
        let shared = SharedData::new();
        publish_fingerprints(&shared, &[]);
        assert!(read_fingerprints(&shared).is_empty());
    }
}
