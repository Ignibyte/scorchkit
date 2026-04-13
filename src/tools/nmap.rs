use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Port scanning and service detection via nmap.
#[derive(Debug)]
pub struct NmapModule;

#[async_trait]
impl ScanModule for NmapModule {
    fn name(&self) -> &'static str {
        "Nmap Port Scanner"
    }

    fn id(&self) -> &'static str {
        "nmap"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Port scanning and service detection via nmap"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("nmap")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());

        let output = subprocess::run_tool(
            "nmap",
            &["-sV", "--top-ports", "1000", "-oX", "-", target],
            Duration::from_secs(600),
        )
        .await?;

        Ok(parse_nmap_xml(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Parse nmap XML output into findings.
fn parse_nmap_xml(xml: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Parse <port> elements from the XML
    // Format: <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
    for port_block in xml.split("<port ") {
        if !port_block.contains("state=\"open\"") {
            continue;
        }

        let port_id = extract_xml_attr(port_block, "portid").unwrap_or_default();
        let protocol =
            extract_xml_attr(port_block, "protocol").unwrap_or_else(|| "tcp".to_string());
        let service_name =
            extract_xml_attr(port_block, "name").unwrap_or_else(|| "unknown".to_string());
        let product = extract_xml_attr(port_block, "product").unwrap_or_default();
        let version = extract_xml_attr(port_block, "version").unwrap_or_default();

        if port_id.is_empty() {
            continue;
        }

        let service_info = if !product.is_empty() && !version.is_empty() {
            format!("{product} {version}")
        } else if !product.is_empty() {
            product.clone()
        } else {
            service_name.clone()
        };

        // Determine severity based on port/service
        let severity = classify_port_severity(&port_id, &service_name);

        findings.push(
            Finding::new(
                "nmap",
                severity,
                format!("Open Port: {port_id}/{protocol} ({service_name})"),
                format!("Port {port_id}/{protocol} is open running {service_info}.",),
                target_url,
            )
            .with_evidence(format!(
                "Port: {port_id}/{protocol} | Service: {service_name} | Version: {service_info}"
            ))
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_confidence(0.9),
        );

        // Flag known outdated service versions
        if !version.is_empty() {
            if let Some(warning) = check_outdated_version(&service_name, &version) {
                findings.push(
                    Finding::new(
                        "nmap",
                        Severity::High,
                        format!("Outdated Service Version: {product} {version}"),
                        warning,
                        target_url,
                    )
                    .with_evidence(format!("Port {port_id}: {product} {version}"))
                    .with_remediation("Update to the latest stable version")
                    .with_owasp("A06:2021 Vulnerable and Outdated Components")
                    .with_cwe(1104)
                    .with_confidence(0.9),
                );
            }
        }
    }

    findings
}

fn classify_port_severity(port: &str, service: &str) -> Severity {
    let service_lower = service.to_lowercase();

    // Dangerous services exposed
    match service_lower.as_str() {
        "ftp" | "telnet" | "rsh" | "rlogin" | "rexec" => return Severity::High,
        "mysql" | "postgresql" | "mssql" | "oracle" | "redis" | "mongodb" | "memcached" => {
            return Severity::High;
        }
        "smb" | "netbios-ssn" | "microsoft-ds" => return Severity::Medium,
        _ => {}
    }

    // Common web ports are informational
    match port {
        "80" | "443" | "8080" | "8443" => Severity::Info,
        // SSH and other ports are worth noting
        _ => Severity::Low,
    }
}

fn check_outdated_version(service: &str, version: &str) -> Option<String> {
    let svc = service.to_lowercase();
    let ver = version.to_lowercase();

    // Very simplified - just flag obviously old major versions
    if svc.contains("apache") && (ver.starts_with("2.2.") || ver.starts_with("2.0.")) {
        return Some(format!(
            "Apache HTTP Server {version} is end-of-life and has known vulnerabilities."
        ));
    }
    if svc.contains("nginx") && ver.starts_with("1.1") && !ver.starts_with("1.2") {
        // nginx 1.1x is old
        if let Some(minor) = ver.strip_prefix("1.") {
            if let Ok(m) = minor.split('.').next().unwrap_or("0").parse::<u32>() {
                if m < 20 {
                    return Some(format!(
                        "Nginx {version} may have known vulnerabilities. Update to latest stable."
                    ));
                }
            }
        }
    }
    if svc.contains("openssh") {
        if let Some(major) = ver.split('.').next() {
            if let Ok(m) = major.parse::<u32>() {
                if m < 8 {
                    return Some(format!(
                        "OpenSSH {version} is outdated and may have known vulnerabilities."
                    ));
                }
            }
        }
    }

    None
}

/// Extract an XML attribute value (simplified parser).
fn extract_xml_attr(xml: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{attr_name}=\"");
    let start = xml.find(&pattern)? + pattern.len();
    let end = xml[start..].find('"')? + start;
    Some(xml[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for nmap XML output parser.

    /// Verify that `parse_nmap_xml` correctly extracts open ports and service
    /// information from well-formed nmap XML output.
    #[test]
    fn test_parse_nmap_xml() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.30"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/><service name="abyss"/></port>
</ports></host>
</nmaprun>"#;

        let findings = parse_nmap_xml(xml, "https://example.com");
        // 3 open ports (closed port excluded)
        assert_eq!(findings.len(), 3);
        assert!(findings[0].title.contains("80"));
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[2].title.contains("3306"));
        assert_eq!(findings[2].severity, Severity::High); // mysql
    }

    /// Verify that `parse_nmap_xml` handles empty input gracefully.
    #[test]
    fn test_parse_nmap_xml_empty() {
        let findings = parse_nmap_xml("", "https://example.com");
        assert!(findings.is_empty());
    }
}
