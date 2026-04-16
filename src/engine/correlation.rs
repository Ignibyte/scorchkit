//! Cross-family attack-chain correlation engine (WORK-136).
//!
//! Given a set of findings from DAST, SAST, Infra, and Cloud scans,
//! identifies compound attack paths where multiple vulnerabilities
//! combine to create a more severe exploit chain than any single
//! finding alone.
//!
//! ## Architecture
//!
//! - [`AttackChain`] — a sequence of findings forming an exploit path
//! - [`ChainStep`] — one finding within a chain, with role annotation
//! - [`CorrelationRule`] — trigger + filter for identifying a pattern
//! - [`correlate`] — applies all rules to a finding set
//!
//! ## Built-in rules
//!
//! 12+ rules covering: XSS→session hijack, SQLi→DB compromise,
//! SSRF→cloud credential theft, IDOR+data exposure, subdomain
//! takeover, exposed secrets, DAST+SAST cross-confirmation,
//! vulnerable deps+exploitable endpoints, IaC+runtime misconfig,
//! auth bypass, supply chain, and cloud misconfig chains.

use serde::{Deserialize, Serialize};

use super::finding::Finding;
use super::severity::Severity;

/// An attack chain linking multiple findings into a compound exploit path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    /// Descriptive name for the attack chain.
    pub name: String,
    /// Overall severity of the chain (typically the highest step).
    pub severity: Severity,
    /// Narrative describing the exploit path.
    pub description: String,
    /// Ordered steps in the chain.
    pub steps: Vec<ChainStep>,
    /// Recommended remediation priority.
    pub remediation_priority: String,
}

/// One step in an attack chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    /// The module that produced this finding.
    pub module_id: String,
    /// Finding title.
    pub title: String,
    /// Role in the chain (e.g. `"entry point"`, `"pivot"`, `"target"`).
    pub role: String,
}

/// A correlation rule definition.
struct Rule {
    name: &'static str,
    severity: Severity,
    description: &'static str,
    priority: &'static str,
    trigger: fn(&[&Finding]) -> bool,
    member_filter: fn(&Finding) -> bool,
}

/// Apply all built-in correlation rules to a set of findings.
///
/// Returns attack chains where the trigger condition is met.
/// Each chain includes only the findings that match the rule's
/// member filter.
#[must_use]
pub fn correlate(findings: &[Finding]) -> Vec<AttackChain> {
    let refs: Vec<&Finding> = findings.iter().collect();
    let rules = built_in_rules();

    rules
        .into_iter()
        .filter(|rule| (rule.trigger)(&refs))
        .map(|rule| {
            let steps: Vec<ChainStep> = findings
                .iter()
                .filter(|f| (rule.member_filter)(f))
                .map(|f| ChainStep {
                    module_id: f.module_id.clone(),
                    title: f.title.clone(),
                    role: classify_step_role(&f.module_id),
                })
                .collect();

            AttackChain {
                name: rule.name.to_string(),
                severity: rule.severity,
                description: rule.description.to_string(),
                steps,
                remediation_priority: rule.priority.to_string(),
            }
        })
        .collect()
}

/// Classify a finding's role in an attack chain based on its module.
fn classify_step_role(module_id: &str) -> String {
    if module_id.contains("recon")
        || module_id == "headers"
        || module_id == "tech"
        || module_id == "discovery"
    {
        "reconnaissance".to_string()
    } else if module_id.contains("cloud")
        || module_id.starts_with("aws-")
        || module_id.starts_with("gcp-")
        || module_id.starts_with("azure-")
    {
        "cloud exposure".to_string()
    } else if is_sast(module_id) {
        "code weakness".to_string()
    } else {
        "exploit vector".to_string()
    }
}

/// Check if a module is a SAST scanner.
fn is_sast(module_id: &str) -> bool {
    matches!(
        module_id,
        "semgrep"
            | "osv-scanner"
            | "gitleaks"
            | "bandit"
            | "gosec"
            | "checkov"
            | "grype"
            | "hadolint"
            | "eslint-security"
            | "phpstan"
            | "dep-audit"
            | "snyk-test"
            | "snyk-code"
    )
}

/// Check if a finding's title contains a case-insensitive pattern.
fn title_has(finding: &Finding, pattern: &str) -> bool {
    finding.title.to_lowercase().contains(pattern)
}

/// All built-in correlation rules.
// JUSTIFICATION: 14 rule struct definitions with trigger/filter closures —
// splitting would scatter cohesive rule definitions across multiple functions.
// has_sast/has_dast are intentionally similarly named — they represent the two
// halves of cross-domain correlation.
#[allow(clippy::too_many_lines, clippy::similar_names)]
fn built_in_rules() -> Vec<Rule> {
    vec![
        // --- Web application chains ---
        Rule {
            name: "Session Hijacking via XSS + Weak CSP",
            severity: Severity::High,
            description: "XSS combined with missing/weak CSP enables session token theft.",
            priority: "immediate",
            trigger: |fs| {
                let has_xss = fs.iter().any(|f| {
                    f.module_id == "xss" || f.module_id == "dalfox" || title_has(f, "xss")
                });
                let has_csp = fs
                    .iter()
                    .any(|f| title_has(f, "csp") || title_has(f, "content-security-policy"));
                has_xss && has_csp
            },
            member_filter: |f| {
                f.module_id == "xss"
                    || f.module_id == "dalfox"
                    || title_has(f, "xss")
                    || title_has(f, "csp")
            },
        },
        Rule {
            name: "Database Compromise via SQLi + Open DB Port",
            severity: Severity::Critical,
            description: "SQL injection + exposed database port = direct DB compromise path.",
            priority: "immediate",
            trigger: |fs| {
                let has_sqli = fs.iter().any(|f| {
                    f.module_id == "injection"
                        || f.module_id == "sqlmap"
                        || title_has(f, "sql injection")
                });
                let has_port = fs
                    .iter()
                    .any(|f| title_has(f, "3306") || title_has(f, "5432") || title_has(f, "1433"));
                has_sqli && has_port
            },
            member_filter: |f| {
                title_has(f, "sql")
                    || title_has(f, "injection")
                    || title_has(f, "3306")
                    || title_has(f, "5432")
                    || title_has(f, "1433")
            },
        },
        Rule {
            name: "Cloud Credential Theft via SSRF",
            severity: Severity::Critical,
            description: "SSRF + cloud metadata access = IAM credential theft and cloud pivot.",
            priority: "immediate",
            trigger: |fs| {
                let has_ssrf = fs.iter().any(|f| f.module_id == "ssrf" || title_has(f, "ssrf"));
                let has_cloud = fs.iter().any(|f| {
                    title_has(f, "metadata") || title_has(f, "cloud") || title_has(f, "169.254")
                });
                has_ssrf && has_cloud
            },
            member_filter: |f| {
                title_has(f, "ssrf")
                    || title_has(f, "metadata")
                    || title_has(f, "cloud")
                    || title_has(f, "169.254")
            },
        },
        Rule {
            name: "Data Breach via IDOR + Data Exposure",
            severity: Severity::High,
            description:
                "IDOR + sensitive data exposure = unauthorized access to other users' data.",
            priority: "high",
            trigger: |fs| {
                let has_idor = fs.iter().any(|f| title_has(f, "idor"));
                let has_data =
                    fs.iter().any(|f| title_has(f, "sensitive") || title_has(f, "data exposure"));
                has_idor && has_data
            },
            member_filter: |f| {
                title_has(f, "idor") || title_has(f, "sensitive") || title_has(f, "data exposure")
            },
        },
        // --- DAST + SAST cross-domain ---
        Rule {
            name: "Confirmed SQLi: Code + Runtime",
            severity: Severity::Critical,
            description:
                "SQL injection in source code AND exploitable at runtime — confirmed true positive.",
            priority: "immediate",
            trigger: |fs| {
                let has_dast =
                    fs.iter().any(|f| f.module_id == "injection" || f.module_id == "sqlmap");
                let has_sast = fs.iter().any(|f| is_sast(&f.module_id) && title_has(f, "sql"));
                has_dast && has_sast
            },
            member_filter: |f| {
                title_has(f, "sql") || f.module_id == "injection" || f.module_id == "sqlmap"
            },
        },
        Rule {
            name: "Hardcoded Secrets + Runtime Exposure",
            severity: Severity::Critical,
            description: "Secrets in code (SAST) AND exposed at runtime (DAST) — confirmed leak.",
            priority: "immediate",
            trigger: |fs| {
                let has_sast = fs.iter().any(|f| {
                    f.module_id == "gitleaks" || (is_sast(&f.module_id) && title_has(f, "secret"))
                });
                let has_dast = fs.iter().any(|f| {
                    f.module_id == "sensitive"
                        || (!is_sast(&f.module_id) && title_has(f, "exposed"))
                });
                has_sast && has_dast
            },
            member_filter: |f| {
                title_has(f, "secret")
                    || title_has(f, "credential")
                    || title_has(f, "exposed")
                    || f.module_id == "gitleaks"
                    || f.module_id == "sensitive"
            },
        },
        Rule {
            name: "Vulnerable Dependency + Exploitable Endpoint",
            severity: Severity::High,
            description: "Known-vulnerable dependency (SAST) + exploitable web endpoint (DAST).",
            priority: "high",
            trigger: |fs| {
                let has_dep = fs.iter().any(|f| {
                    f.module_id == "dep-audit"
                        || f.module_id == "osv-scanner"
                        || f.module_id == "grype"
                });
                let has_exploit = fs.iter().any(|f| {
                    !is_sast(&f.module_id)
                        && (f.module_id == "injection"
                            || f.module_id == "xss"
                            || f.module_id == "ssrf")
                });
                has_dep && has_exploit
            },
            member_filter: |f| {
                f.module_id == "dep-audit"
                    || f.module_id == "osv-scanner"
                    || title_has(f, "CVE")
                    || f.module_id == "injection"
                    || f.module_id == "xss"
                    || f.module_id == "ssrf"
            },
        },
        Rule {
            name: "Auth Bypass: Code Weakness + Runtime Exploit",
            severity: Severity::Critical,
            description: "Auth weakness in source + auth bypass at runtime — confirmed.",
            priority: "immediate",
            trigger: |fs| {
                let has_sast = fs.iter().any(|f| {
                    is_sast(&f.module_id) && (title_has(f, "auth") || title_has(f, "jwt"))
                });
                let has_dast = fs.iter().any(|f| {
                    f.module_id == "auth" || f.module_id == "jwt" || f.module_id == "idor"
                });
                has_sast && has_dast
            },
            member_filter: |f| {
                title_has(f, "auth")
                    || title_has(f, "jwt")
                    || title_has(f, "session")
                    || f.module_id == "idor"
            },
        },
        // --- Cloud-specific chains ---
        Rule {
            name: "Cloud IAM Escalation Path",
            severity: Severity::Critical,
            description:
                "Over-privileged IAM + exposed cloud service = privilege escalation to cloud admin.",
            priority: "immediate",
            trigger: |fs| {
                let has_iam = fs.iter().any(|f| {
                    title_has(f, "access key")
                        || title_has(f, "owner")
                        || title_has(f, "privilege escalation")
                        || title_has(f, "user-managed key")
                });
                let has_exposure = fs.iter().any(|f| {
                    title_has(f, "public access")
                        || title_has(f, "0.0.0.0/0")
                        || title_has(f, "open to")
                });
                has_iam && has_exposure
            },
            member_filter: |f| {
                title_has(f, "iam")
                    || title_has(f, "root")
                    || title_has(f, "owner")
                    || title_has(f, "public access")
                    || title_has(f, "0.0.0.0")
            },
        },
        Rule {
            name: "Cloud Data Exfiltration Path",
            severity: Severity::Critical,
            description: "Public storage + missing encryption = data exfiltration risk.",
            priority: "immediate",
            trigger: |fs| {
                let has_public =
                    fs.iter().any(|f| title_has(f, "public access") || title_has(f, "public blob"));
                let has_no_encrypt = fs.iter().any(|f| {
                    title_has(f, "not encrypted")
                        || title_has(f, "no cmek")
                        || title_has(f, "no encryption")
                });
                has_public && has_no_encrypt
            },
            member_filter: |f| {
                title_has(f, "public")
                    || title_has(f, "encrypt")
                    || title_has(f, "cmek")
                    || title_has(f, "storage")
                    || title_has(f, "s3")
                    || title_has(f, "gcs")
            },
        },
        Rule {
            name: "Network Perimeter Breach via Open Ports + Weak Auth",
            severity: Severity::Critical,
            description:
                "Management ports open to internet + weak authentication = remote compromise.",
            priority: "immediate",
            trigger: |fs| {
                let has_open_port = fs.iter().any(|f| {
                    title_has(f, "open to")
                        || title_has(f, "0.0.0.0/0")
                        || title_has(f, "ssh") && title_has(f, "open")
                });
                let has_weak_auth = fs.iter().any(|f| {
                    title_has(f, "mfa")
                        || title_has(f, "password policy")
                        || title_has(f, "default credential")
                });
                has_open_port && has_weak_auth
            },
            member_filter: |f| {
                title_has(f, "open")
                    || title_has(f, "ssh")
                    || title_has(f, "rdp")
                    || title_has(f, "mfa")
                    || title_has(f, "password")
                    || title_has(f, "credential")
            },
        },
        Rule {
            name: "Logging Blind Spot + Active Attack Surface",
            severity: Severity::High,
            description:
                "Disabled audit logging + exploitable vulnerabilities = attacks go undetected.",
            priority: "high",
            trigger: |fs| {
                let has_no_logging = fs.iter().any(|f| {
                    title_has(f, "logging disabled")
                        || title_has(f, "no trail")
                        || title_has(f, "not logging")
                        || title_has(f, "audit")
                });
                let has_vuln = fs
                    .iter()
                    .any(|f| f.severity == Severity::High || f.severity == Severity::Critical);
                has_no_logging && has_vuln
            },
            member_filter: |f| {
                title_has(f, "logging")
                    || title_has(f, "trail")
                    || title_has(f, "audit")
                    || f.severity == Severity::Critical
            },
        },
        // --- Subdomain + secrets ---
        Rule {
            name: "Subdomain Takeover Phishing Platform",
            severity: Severity::High,
            description:
                "Dangling DNS records enable subdomain takeover for phishing on a trusted domain.",
            priority: "high",
            trigger: |fs| {
                fs.iter().any(|f| title_has(f, "subdomain takeover") || title_has(f, "dangling"))
            },
            member_filter: |f| {
                title_has(f, "subdomain")
                    || title_has(f, "dangling")
                    || title_has(f, "takeover")
                    || title_has(f, "cname")
            },
        },
        Rule {
            name: "Exposed Secrets Pipeline",
            severity: Severity::Critical,
            description:
                "Secrets detected in code, config, or runtime — credential compromise risk.",
            priority: "immediate",
            trigger: |fs| {
                fs.iter().any(|f| {
                    f.module_id == "trufflehog"
                        || f.module_id == "gitleaks"
                        || title_has(f, "secret")
                        || title_has(f, "api key")
                })
            },
            member_filter: |f| {
                title_has(f, "secret")
                    || title_has(f, "api key")
                    || title_has(f, "credential")
                    || title_has(f, "token")
                    || f.module_id == "trufflehog"
                    || f.module_id == "gitleaks"
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(module_id: &str, title: &str, severity: Severity) -> Finding {
        Finding::new(module_id, severity, title, "desc", "target")
    }

    /// XSS + CSP → session hijacking chain.
    #[test]
    fn test_correlate_xss_csp_chain() {
        let findings = vec![
            finding("xss", "Reflected XSS in search", Severity::High),
            finding("headers", "Missing CSP Header", Severity::Medium),
        ];
        let chains = correlate(&findings);
        assert!(chains.iter().any(|c| c.name.contains("Session Hijacking")));
    }

    /// SQLi + open DB port → database compromise chain.
    #[test]
    fn test_correlate_sqli_db_port_chain() {
        let findings = vec![
            finding("injection", "SQL Injection in login", Severity::Critical),
            finding("tcp-probe", "Open port 3306 (MySQL)", Severity::Info),
        ];
        let chains = correlate(&findings);
        assert!(chains.iter().any(|c| c.name.contains("Database Compromise")));
    }

    /// Cloud IAM + exposure → escalation chain.
    #[test]
    fn test_correlate_cloud_iam_escalation() {
        let findings = vec![
            finding("aws-iam", "AWS IAM: Root account has access keys", Severity::Critical),
            finding("aws-sg", "AWS SG: SSH (22) open to 0.0.0.0/0 in sg-123", Severity::Critical),
        ];
        let chains = correlate(&findings);
        assert!(chains.iter().any(|c| c.name.contains("IAM Escalation")));
    }

    /// Public storage + no encryption → data exfiltration chain.
    #[test]
    fn test_correlate_cloud_data_exfil() {
        let findings = vec![
            finding(
                "aws-s3",
                "AWS S3: Bucket 'data' public access not blocked",
                Severity::Critical,
            ),
            finding("aws-s3", "AWS S3: Bucket 'data' not encrypted", Severity::High),
        ];
        let chains = correlate(&findings);
        assert!(chains.iter().any(|c| c.name.contains("Data Exfiltration")));
    }

    /// No matching patterns → zero chains.
    #[test]
    fn test_correlate_no_matches() {
        let findings = vec![finding("headers", "Missing X-Frame-Options", Severity::Low)];
        let chains = correlate(&findings);
        assert!(chains.is_empty());
    }

    /// Chain steps have role annotations.
    #[test]
    fn test_chain_step_roles() {
        let findings = vec![
            finding("xss", "Reflected XSS", Severity::High),
            finding("headers", "Missing CSP", Severity::Medium),
        ];
        let chains = correlate(&findings);
        let chain = chains.iter().find(|c| c.name.contains("Session")).expect("chain");
        assert!(!chain.steps.is_empty());
        assert!(chain.steps.iter().any(|s| !s.role.is_empty()));
    }

    /// `AttackChain` serializes to JSON.
    #[test]
    fn test_attack_chain_serialization() {
        let chain = AttackChain {
            name: "Test Chain".into(),
            severity: Severity::High,
            description: "Test".into(),
            steps: vec![ChainStep {
                module_id: "xss".into(),
                title: "XSS".into(),
                role: "exploit".into(),
            }],
            remediation_priority: "high".into(),
        };
        let json = serde_json::to_string(&chain).expect("serialize");
        assert!(json.contains("Test Chain"));
    }

    /// Exposed secrets trigger.
    #[test]
    fn test_correlate_exposed_secrets() {
        let findings =
            vec![finding("trufflehog", "AWS Secret Key found in repo", Severity::Critical)];
        let chains = correlate(&findings);
        assert!(chains.iter().any(|c| c.name.contains("Exposed Secrets")));
    }

    /// 14 built-in rules exist.
    #[test]
    fn test_built_in_rule_count() {
        assert!(built_in_rules().len() >= 14);
    }
}
