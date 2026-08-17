//! Compliance framework mapping for security findings.
//!
//! Maps OWASP Top 10 and CWE identifiers to compliance framework
//! controls across NIST 800-53, PCI-DSS 4.0, SOC2 TSC, and HIPAA.
//! Used by the `Finding` builder's `.with_compliance()` method.

/// Look up compliance framework controls for an OWASP category.
///
/// Returns a list of framework control references (e.g., "NIST AC-3",
/// "PCI-DSS 6.2.4") that map to the given OWASP Top 10 category ID.
#[must_use]
pub fn compliance_for_owasp(owasp_id: &str) -> Vec<&'static str> {
    // Extract the category code (e.g., "A01" from "A01:2021 Broken Access Control")
    let code = owasp_id.split(':').next().unwrap_or(owasp_id).trim();

    match code {
        "A01" => vec![
            "NIST AC-3 (Access Enforcement)",
            "NIST AC-6 (Least Privilege)",
            "PCI-DSS 7.2 (Access Control Systems)",
            "SOC2 CC6.1 (Logical Access Security)",
            "HIPAA §164.312(a)(1) (Access Control)",
        ],
        "A02" => vec![
            "NIST IA-5 (Authenticator Management)",
            "NIST SC-12 (Cryptographic Key Management)",
            "PCI-DSS 8.3 (Strong Cryptography for Authentication)",
            "SOC2 CC6.1 (Logical Access Security)",
            "HIPAA §164.312(d) (Person or Entity Authentication)",
        ],
        "A03" => vec![
            "NIST SI-10 (Information Input Validation)",
            "NIST SI-11 (Error Handling)",
            "PCI-DSS 6.2.4 (Software Engineering Techniques)",
            "SOC2 CC7.1 (System Change Management)",
            "HIPAA §164.312(c)(1) (Integrity Controls)",
        ],
        "A04" => vec![
            "NIST AC-4 (Information Flow Enforcement)",
            "NIST SC-7 (Boundary Protection)",
            "PCI-DSS 6.2.4 (Software Engineering Techniques)",
            "SOC2 CC6.1 (Logical Access Security)",
        ],
        "A05" => vec![
            "NIST CM-6 (Configuration Settings)",
            "NIST CM-7 (Least Functionality)",
            "PCI-DSS 2.2 (System Configuration Standards)",
            "SOC2 CC6.1 (Logical Access Security)",
            "HIPAA §164.312(a)(2)(iv) (Encryption and Decryption)",
        ],
        "A06" => vec![
            "NIST SI-2 (Flaw Remediation)",
            "NIST RA-5 (Vulnerability Monitoring and Scanning)",
            "PCI-DSS 6.3 (Vulnerability Management)",
            "SOC2 CC7.1 (System Change Management)",
            "HIPAA §164.308(a)(5)(ii)(B) (Protection from Malicious Software)",
        ],
        "A07" => vec![
            "NIST IA-2 (Identification and Authentication)",
            "NIST IA-5 (Authenticator Management)",
            "PCI-DSS 8.2 (User Identification)",
            "SOC2 CC6.1 (Logical Access Security)",
            "HIPAA §164.312(d) (Person or Entity Authentication)",
        ],
        "A08" => vec![
            "NIST SI-7 (Software and Information Integrity)",
            "NIST SA-10 (Developer Configuration Management)",
            "PCI-DSS 6.2.4 (Software Engineering Techniques)",
            "SOC2 CC8.1 (Change Control Process)",
        ],
        "A09" => vec![
            "NIST AU-2 (Event Logging)",
            "NIST AU-6 (Audit Record Review)",
            "PCI-DSS 10.2 (Audit Logs)",
            "SOC2 CC7.2 (Monitoring Activities)",
            "HIPAA §164.312(b) (Audit Controls)",
        ],
        "A10" => vec![
            "NIST SI-10 (Information Input Validation)",
            "NIST SC-8 (Transmission Confidentiality)",
            "PCI-DSS 6.2.4 (Software Engineering Techniques)",
            "SOC2 CC6.7 (Restriction of Data Transmission)",
        ],
        _ => Vec::new(),
    }
}

/// Look up compliance framework controls for a CWE ID.
///
/// Maps common CWE identifiers to the most relevant compliance controls.
/// Falls back to empty vec for unmapped CWEs.
#[must_use]
pub fn compliance_for_cwe(cwe_id: u32) -> Vec<&'static str> {
    match cwe_id {
        79 | 89 => vec!["NIST SI-10", "PCI-DSS 6.2.4", "SOC2 CC7.1"], // XSS, SQL Injection
        200 => vec!["NIST AC-3", "PCI-DSS 6.5.8", "HIPAA §164.312(a)(1)"], // Info Exposure
        287 => vec!["NIST IA-2", "PCI-DSS 8.2", "HIPAA §164.312(d)"], // Auth Bypass
        311 => vec!["NIST SC-28", "PCI-DSS 3.4", "HIPAA §164.312(a)(2)(iv)"], // Missing Encryption
        319 => vec!["NIST SC-8", "PCI-DSS 4.1", "HIPAA §164.312(e)(1)"], // Cleartext TX
        352 | 601 => vec!["NIST SI-10", "PCI-DSS 6.2.4"],             // CSRF, Open Redirect
        521 | 522 => vec!["NIST IA-5", "PCI-DSS 8.3"],                // Weak Password/Credentials
        798 => vec!["NIST IA-5", "PCI-DSS 8.6", "HIPAA §164.312(d)"], // Hardcoded Credentials
        918 => vec!["NIST AC-4", "PCI-DSS 6.2.4"],                    // SSRF
        1104 => vec!["NIST SI-2", "PCI-DSS 6.3", "SOC2 CC7.1"],       // Outdated Components
        // Cloud-specific CWEs (WORK-154)
        16 => vec!["NIST CM-6", "PCI-DSS 2.2", "SOC2 CC6.1"], // Configuration
        284 => vec!["NIST AC-3", "NIST AC-4", "PCI-DSS 7.2"], // Improper Access Control
        778 => vec!["NIST AU-2", "NIST AU-6", "PCI-DSS 10.2", "HIPAA §164.312(b)"], // Insufficient Logging
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify known OWASP category returns framework controls.
    #[test]
    fn test_compliance_owasp_lookup() {
        let controls = compliance_for_owasp("A01:2021 Broken Access Control");
        assert!(!controls.is_empty());
        assert!(controls.iter().any(|c| c.contains("NIST AC-3")));
        assert!(controls.iter().any(|c| c.contains("PCI-DSS")));
        assert!(controls.iter().any(|c| c.contains("HIPAA")));
    }

    /// Verify unknown OWASP category returns empty vec.
    #[test]
    fn test_compliance_unknown() {
        let controls = compliance_for_owasp("A99:2099 Unknown");
        assert!(controls.is_empty());
    }

    /// Verify CWE-based compliance lookup.
    #[test]
    fn test_compliance_cwe_lookup() {
        let controls = compliance_for_cwe(79); // XSS
        assert!(!controls.is_empty());
        assert!(controls.iter().any(|c| c.contains("NIST SI-10")));

        let controls = compliance_for_cwe(99999);
        assert!(controls.is_empty());
    }

    /// Verify cloud-specific CWE IDs (WORK-154) return controls.
    #[test]
    fn test_compliance_cwe_cloud_ids() {
        // CWE-16: Configuration
        let controls = compliance_for_cwe(16);
        assert!(!controls.is_empty());
        assert!(controls.iter().any(|c| c.contains("NIST CM-6")));

        // CWE-284: Improper Access Control
        let controls = compliance_for_cwe(284);
        assert!(!controls.is_empty());
        assert!(controls.iter().any(|c| c.contains("NIST AC-3")));

        // CWE-778: Insufficient Logging
        let controls = compliance_for_cwe(778);
        assert!(!controls.is_empty());
        assert!(controls.iter().any(|c| c.contains("NIST AU-2")));
        assert!(controls.iter().any(|c| c.contains("HIPAA")));
    }
}
