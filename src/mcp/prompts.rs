//! MCP prompt templates for pentest workflows.
//!
//! Provides structured prompt templates that give Claude starting points
//! for common security assessment workflows. Exposed via the MCP prompts
//! capability (`list_prompts`, `get_prompt`).

use rmcp::model::{GetPromptResult, Prompt, PromptArgument, PromptMessage, PromptMessageRole};

use super::server::ScorchKitServer;

/// All available prompt template definitions.
const PROMPTS: &[PromptDef] = &[
    PromptDef {
        name: "full-web-assessment",
        description: "Run a complete web application security assessment against a target",
        args: &[ArgDef {
            name: "target",
            description: "Target URL to assess (e.g., https://example.com)",
            required: true,
        }],
    },
    PromptDef {
        name: "investigate-finding",
        description: "Deep dive into a specific security finding with reproduction steps",
        args: &[ArgDef {
            name: "finding_id",
            description: "Finding UUID to investigate (from project_findings)",
            required: true,
        }],
    },
    PromptDef {
        name: "remediation-plan",
        description: "Generate a prioritized remediation plan for a project's findings",
        args: &[ArgDef {
            name: "project",
            description: "Project name or UUID to generate remediation plan for",
            required: true,
        }],
    },
    PromptDef {
        name: "compare-scans",
        description: "Analyze what changed between two scans of the same target",
        args: &[ArgDef {
            name: "project",
            description: "Project name or UUID containing the scans",
            required: true,
        }],
    },
    PromptDef {
        name: "executive-summary",
        description: "Generate a client-ready executive summary of a project's security posture",
        args: &[ArgDef {
            name: "project",
            description: "Project name or UUID to summarize",
            required: true,
        }],
    },
];

/// Internal prompt template definition (compile-time constant).
struct PromptDef {
    name: &'static str,
    description: &'static str,
    args: &'static [ArgDef],
}

/// Internal argument definition (compile-time constant).
struct ArgDef {
    name: &'static str,
    description: &'static str,
    required: bool,
}

impl ScorchKitServer {
    /// List all available prompt templates.
    #[must_use]
    pub fn do_list_prompts() -> Vec<Prompt> {
        PROMPTS
            .iter()
            .map(|p| {
                let arguments: Vec<PromptArgument> = p
                    .args
                    .iter()
                    .map(|a| {
                        PromptArgument::new(a.name)
                            .with_description(a.description)
                            .with_required(a.required)
                    })
                    .collect();

                Prompt::new(
                    p.name,
                    Some(p.description),
                    if arguments.is_empty() { None } else { Some(arguments) },
                )
            })
            .collect()
    }

    /// Get a specific prompt by name, substituting arguments into messages.
    ///
    /// # Errors
    ///
    /// Returns an error if the prompt name is unknown or a required argument
    /// is missing.
    pub fn do_get_prompt(
        name: &str,
        arguments: &std::collections::HashMap<String, String>,
    ) -> Result<GetPromptResult, String> {
        match name {
            "full-web-assessment" => {
                let target = arguments.get("target").ok_or("Missing required argument: target")?;
                Ok(build_full_assessment_prompt(target))
            }
            "investigate-finding" => {
                let finding_id =
                    arguments.get("finding_id").ok_or("Missing required argument: finding_id")?;
                Ok(build_investigate_prompt(finding_id))
            }
            "remediation-plan" => {
                let project =
                    arguments.get("project").ok_or("Missing required argument: project")?;
                Ok(build_remediation_prompt(project))
            }
            "compare-scans" => {
                let project =
                    arguments.get("project").ok_or("Missing required argument: project")?;
                Ok(build_compare_prompt(project))
            }
            "executive-summary" => {
                let project =
                    arguments.get("project").ok_or("Missing required argument: project")?;
                Ok(build_executive_prompt(project))
            }
            _ => Err(format!("Unknown prompt: {name}")),
        }
    }
}

/// Build the full web assessment workflow prompt.
fn build_full_assessment_prompt(target: &str) -> GetPromptResult {
    GetPromptResult::new(vec![
        PromptMessage::new_text(
            PromptMessageRole::User,
            format!(
                "Run a complete web application security assessment against {target}. \
                 Follow the standard pentest methodology: \
                 1) Create a project to track results \
                 2) Run target_intelligence for recon \
                 3) Use plan_scan to get AI-recommended modules \
                 4) Execute auto_scan with recommended profile \
                 5) Analyze findings with analyze_findings \
                 6) Correlate findings into attack chains \
                 7) Generate an executive summary"
            ),
        ),
        PromptMessage::new_text(
            PromptMessageRole::Assistant,
            format!(
                "I'll run a comprehensive security assessment against {target}. \
                 Let me start by creating a project and running reconnaissance."
            ),
        ),
    ])
    .with_description(format!("Full web assessment against {target}"))
}

/// Build the finding investigation prompt.
fn build_investigate_prompt(finding_id: &str) -> GetPromptResult {
    GetPromptResult::new(vec![
        PromptMessage::new_text(
            PromptMessageRole::User,
            format!(
                "Investigate finding {finding_id} in depth. I need: \
                 1) Full finding details from finding_show \
                 2) Explanation of the vulnerability and its impact \
                 3) Step-by-step reproduction instructions \
                 4) Proof-of-concept if applicable \
                 5) Specific remediation with code examples"
            ),
        ),
        PromptMessage::new_text(
            PromptMessageRole::Assistant,
            format!(
                "I'll investigate finding {finding_id} thoroughly. \
                 Let me start by retrieving the full details."
            ),
        ),
    ])
    .with_description(format!("Deep investigation of finding {finding_id}"))
}

/// Build the remediation plan prompt.
fn build_remediation_prompt(project: &str) -> GetPromptResult {
    GetPromptResult::new(vec![
        PromptMessage::new_text(
            PromptMessageRole::User,
            format!(
                "Generate a prioritized remediation plan for project '{project}'. \
                 List all findings from project_findings, then: \
                 1) Group by severity and exploitability \
                 2) Identify quick wins (low effort, high impact) \
                 3) Create a phased remediation timeline \
                 4) Include specific fix steps with code examples \
                 5) Estimate effort for each fix"
            ),
        ),
        PromptMessage::new_text(
            PromptMessageRole::Assistant,
            format!(
                "I'll create a prioritized remediation plan for '{project}'. \
                 Let me pull the findings and analyze them."
            ),
        ),
    ])
    .with_description(format!("Remediation plan for project {project}"))
}

/// Build the scan comparison prompt.
fn build_compare_prompt(project: &str) -> GetPromptResult {
    GetPromptResult::new(vec![
        PromptMessage::new_text(
            PromptMessageRole::User,
            format!(
                "Compare the most recent scans for project '{project}'. \
                 Use project_show to find scan IDs, then: \
                 1) Identify new findings since the previous scan \
                 2) Identify resolved findings (present before, gone now) \
                 3) Identify persistent findings (present in both) \
                 4) Assess trend direction (improving/declining) \
                 5) Highlight any severity escalations"
            ),
        ),
        PromptMessage::new_text(
            PromptMessageRole::Assistant,
            format!(
                "I'll compare the recent scans for '{project}'. \
                 Let me retrieve the scan history and findings."
            ),
        ),
    ])
    .with_description(format!("Scan comparison for project {project}"))
}

/// Build the executive summary prompt.
fn build_executive_prompt(project: &str) -> GetPromptResult {
    GetPromptResult::new(vec![
        PromptMessage::new_text(
            PromptMessageRole::User,
            format!(
                "Generate a client-ready executive summary for project '{project}'. \
                 Use project_status for posture metrics and project_findings for details. \
                 The summary should include: \
                 1) Overall risk rating (Critical/High/Medium/Low) \
                 2) Key statistics (total findings by severity) \
                 3) Top 3-5 most critical issues with business impact \
                 4) Positive findings (what's done well) \
                 5) Strategic recommendations \
                 Format for a non-technical audience."
            ),
        ),
        PromptMessage::new_text(
            PromptMessageRole::Assistant,
            format!(
                "I'll generate an executive summary for '{project}'. \
                 Let me gather the security posture data."
            ),
        ),
    ])
    .with_description(format!("Executive summary for project {project}"))
}

/// Correlate findings into attack chains using rule-based pattern matching.
///
/// Examines findings for known vulnerability combinations that create
/// compound attack paths. Returns a JSON array of attack chains.
#[must_use]
pub fn correlate_attack_chains(findings: &[CorrelationFinding]) -> Vec<AttackChain> {
    let rules = correlation_rules();
    rules
        .into_iter()
        .filter(|rule| (rule.trigger)(findings))
        .map(|rule| AttackChain {
            name: rule.name.to_string(),
            severity: rule.severity.to_string(),
            narrative: rule.narrative.to_string(),
            findings: findings
                .iter()
                .filter(|f| (rule.member_filter)(f))
                .map(|f| f.id.clone())
                .collect(),
            remediation_priority: rule.priority.to_string(),
        })
        .collect()
}

/// A correlation rule definition.
struct CorrelationRule {
    name: &'static str,
    severity: &'static str,
    narrative: &'static str,
    priority: &'static str,
    trigger: fn(&[CorrelationFinding]) -> bool,
    member_filter: fn(&CorrelationFinding) -> bool,
}

/// Return all correlation rules.
// JUSTIFICATION: This is a data function containing 6 rule struct definitions
// with trigger/filter closures — splitting would scatter cohesive rule definitions.
#[allow(clippy::too_many_lines)]
fn correlation_rules() -> Vec<CorrelationRule> {
    vec![
        CorrelationRule {
            name: "Session Hijacking via XSS",
            severity: "high",
            narrative: "Cross-site scripting combined with missing or weak Content Security \
                        Policy enables session token theft via injected JavaScript.",
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
                    || title_has(f, "httponly")
                    || title_has(f, "cookie")
            },
        },
        CorrelationRule {
            name: "Database Compromise via SQL Injection",
            severity: "critical",
            narrative: "SQL injection combined with exposed database ports creates a direct \
                        path to database compromise, data theft, and potential RCE.",
            priority: "immediate",
            trigger: |fs| {
                let has_sqli = fs.iter().any(|f| {
                    f.module_id == "injection"
                        || f.module_id == "sqlmap"
                        || title_has(f, "sql injection")
                });
                let has_port = fs.iter().any(|f| title_has(f, "open port"));
                has_sqli && has_port
            },
            member_filter: |f| {
                f.module_id == "injection"
                    || f.module_id == "sqlmap"
                    || title_has(f, "sql")
                    || (title_has(f, "open port")
                        && (f.title.contains("3306")
                            || f.title.contains("5432")
                            || f.title.contains("1433")))
            },
        },
        CorrelationRule {
            name: "Cloud Credential Theft via SSRF",
            severity: "critical",
            narrative: "SSRF combined with accessible cloud metadata endpoints enables theft \
                        of IAM credentials and pivot to cloud infrastructure.",
            priority: "immediate",
            trigger: |fs| {
                let has_ssrf = fs.iter().any(|f| f.module_id == "ssrf" || title_has(f, "ssrf"));
                let has_cloud =
                    fs.iter().any(|f| title_has(f, "metadata") || title_has(f, "cloud"));
                has_ssrf && has_cloud
            },
            member_filter: |f| {
                title_has(f, "ssrf")
                    || title_has(f, "metadata")
                    || title_has(f, "cloud")
                    || title_has(f, "169.254")
            },
        },
        CorrelationRule {
            name: "Data Breach via IDOR",
            severity: "high",
            narrative: "IDOR combined with sensitive data exposure enables unauthorized access \
                        to other users' data via enumerable object references.",
            priority: "high",
            trigger: |fs| {
                let has_idor = fs.iter().any(|f| title_has(f, "idor"));
                let has_data =
                    fs.iter().any(|f| title_has(f, "sensitive") || title_has(f, "data exposure"));
                has_idor && has_data
            },
            member_filter: |f| {
                title_has(f, "idor")
                    || title_has(f, "sensitive")
                    || title_has(f, "data exposure")
                    || title_has(f, "authorization")
            },
        },
        CorrelationRule {
            name: "Phishing Platform via Subdomain Takeover",
            severity: "high",
            narrative: "Dangling DNS records enable subdomain takeover, allowing attackers to \
                        host malicious content on a trusted subdomain.",
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
        CorrelationRule {
            name: "Credential Compromise via Exposed Secrets",
            severity: "critical",
            narrative: "Exposed secrets in source code or config files enable unauthorized \
                        access to services and lateral movement.",
            priority: "immediate",
            trigger: |fs| {
                fs.iter().any(|f| {
                    f.module_id == "trufflehog"
                        || title_has(f, "secret")
                        || title_has(f, "api key")
                        || title_has(f, "credential")
                })
            },
            member_filter: |f| {
                f.module_id == "trufflehog"
                    || title_has(f, "secret")
                    || title_has(f, "api key")
                    || title_has(f, "credential")
                    || title_has(f, "token")
            },
        },
    ]
}

/// Check if a finding's title contains a case-insensitive pattern.
fn title_has(finding: &CorrelationFinding, pattern: &str) -> bool {
    finding.title.to_lowercase().contains(pattern)
}

/// Simplified finding representation for correlation analysis.
#[derive(Debug, Clone)]
pub struct CorrelationFinding {
    /// Finding identifier.
    pub id: String,
    /// Module that produced the finding.
    pub module_id: String,
    /// Finding title.
    pub title: String,
    /// Finding severity.
    pub severity: String,
}

/// An attack chain linking related findings into a narrative.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackChain {
    /// Descriptive name for the attack chain.
    pub name: String,
    /// Escalated severity for the chain (may be higher than individual findings).
    pub severity: String,
    /// Human-readable narrative explaining the attack path.
    pub narrative: String,
    /// Finding IDs that contribute to this chain.
    pub findings: Vec<String>,
    /// Remediation urgency: "immediate", "high", "medium", "low".
    pub remediation_priority: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that all 5 prompt templates are listed.
    #[test]
    fn test_list_prompts() {
        let prompts = ScorchKitServer::do_list_prompts();
        assert_eq!(prompts.len(), 5);
        assert!(prompts.iter().any(|p| p.name == "full-web-assessment"));
        assert!(prompts.iter().any(|p| p.name == "investigate-finding"));
        assert!(prompts.iter().any(|p| p.name == "remediation-plan"));
        assert!(prompts.iter().any(|p| p.name == "compare-scans"));
        assert!(prompts.iter().any(|p| p.name == "executive-summary"));
    }

    /// Verify prompt retrieval returns valid messages.
    #[test]
    fn test_get_prompt() {
        let mut args = std::collections::HashMap::new();
        args.insert("target".to_string(), "https://example.com".to_string());

        let result = ScorchKitServer::do_get_prompt("full-web-assessment", &args);
        assert!(result.is_ok());
        let prompt = result.unwrap();
        assert_eq!(prompt.messages.len(), 2);
    }

    /// Verify unknown prompt returns error.
    #[test]
    fn test_get_prompt_unknown() {
        let args = std::collections::HashMap::new();
        let result = ScorchKitServer::do_get_prompt("nonexistent", &args);
        assert!(result.is_err());
    }

    /// Verify missing required argument returns error.
    #[test]
    fn test_get_prompt_missing_arg() {
        let args = std::collections::HashMap::new();
        let result = ScorchKitServer::do_get_prompt("full-web-assessment", &args);
        assert!(result.is_err());
    }

    /// Verify attack chain correlation with XSS + CSP findings.
    #[test]
    fn test_correlate_xss_chain() {
        let findings = vec![
            CorrelationFinding {
                id: "f1".to_string(),
                module_id: "xss".to_string(),
                title: "Reflected XSS in search".to_string(),
                severity: "high".to_string(),
            },
            CorrelationFinding {
                id: "f2".to_string(),
                module_id: "csp".to_string(),
                title: "Missing CSP Header".to_string(),
                severity: "medium".to_string(),
            },
        ];

        let chains = correlate_attack_chains(&findings);
        assert!(!chains.is_empty());
        assert!(chains.iter().any(|c| c.name.contains("Session Hijacking")));
    }

    /// Verify no chains produced for unrelated findings.
    #[test]
    fn test_correlate_no_chains() {
        let findings = vec![CorrelationFinding {
            id: "f1".to_string(),
            module_id: "ssl".to_string(),
            title: "SSL Certificate Valid".to_string(),
            severity: "info".to_string(),
        }];

        let chains = correlate_attack_chains(&findings);
        assert!(chains.is_empty());
    }

    /// Verify SQL injection + open database port triggers the "Database
    /// Compromise via SQL Injection" attack chain with critical severity.
    #[test]
    fn test_correlate_sqli_chain() {
        // Arrange
        let findings = vec![
            CorrelationFinding {
                id: "f1".to_string(),
                module_id: "injection".to_string(),
                title: "SQL Injection in login form".to_string(),
                severity: "high".to_string(),
            },
            CorrelationFinding {
                id: "f2".to_string(),
                module_id: "nmap".to_string(),
                title: "Open port 3306 (MySQL)".to_string(),
                severity: "info".to_string(),
            },
        ];

        // Act
        let chains = correlate_attack_chains(&findings);

        // Assert
        assert!(!chains.is_empty(), "should produce at least one chain");
        let sqli_chain = chains
            .iter()
            .find(|c| c.name.contains("Database Compromise"))
            .expect("should contain Database Compromise chain");
        assert_eq!(sqli_chain.severity, "critical");
        assert_eq!(sqli_chain.remediation_priority, "immediate");
        assert!(sqli_chain.findings.contains(&"f1".to_string()));
        assert!(sqli_chain.findings.contains(&"f2".to_string()));
    }

    /// Verify SSRF + cloud metadata findings trigger the "Cloud Credential
    /// Theft via SSRF" attack chain with critical severity.
    #[test]
    fn test_correlate_ssrf_chain() {
        // Arrange
        let findings = vec![
            CorrelationFinding {
                id: "f1".to_string(),
                module_id: "ssrf".to_string(),
                title: "SSRF via URL parameter".to_string(),
                severity: "high".to_string(),
            },
            CorrelationFinding {
                id: "f2".to_string(),
                module_id: "headers".to_string(),
                title: "Cloud metadata endpoint accessible".to_string(),
                severity: "medium".to_string(),
            },
        ];

        // Act
        let chains = correlate_attack_chains(&findings);

        // Assert
        assert!(!chains.is_empty(), "should produce at least one chain");
        let ssrf_chain = chains
            .iter()
            .find(|c| c.name.contains("Cloud Credential Theft"))
            .expect("should contain Cloud Credential Theft chain");
        assert_eq!(ssrf_chain.severity, "critical");
        assert_eq!(ssrf_chain.remediation_priority, "immediate");
        assert!(ssrf_chain.findings.contains(&"f1".to_string()));
        assert!(ssrf_chain.findings.contains(&"f2".to_string()));
    }

    /// Verify IDOR + sensitive data exposure findings trigger the "Data
    /// Breach via IDOR" attack chain with high severity.
    #[test]
    fn test_correlate_idor_chain() {
        // Arrange
        let findings = vec![
            CorrelationFinding {
                id: "f1".to_string(),
                module_id: "idor".to_string(),
                title: "IDOR on user profile endpoint".to_string(),
                severity: "high".to_string(),
            },
            CorrelationFinding {
                id: "f2".to_string(),
                module_id: "sensitive".to_string(),
                title: "Sensitive data exposure in API response".to_string(),
                severity: "medium".to_string(),
            },
        ];

        // Act
        let chains = correlate_attack_chains(&findings);

        // Assert
        assert!(!chains.is_empty(), "should produce at least one chain");
        let idor_chain = chains
            .iter()
            .find(|c| c.name.contains("Data Breach via IDOR"))
            .expect("should contain Data Breach via IDOR chain");
        assert_eq!(idor_chain.severity, "high");
        assert_eq!(idor_chain.remediation_priority, "high");
        assert!(idor_chain.findings.contains(&"f1".to_string()));
        assert!(idor_chain.findings.contains(&"f2".to_string()));
    }

    /// Verify exposed secrets trigger the "Credential Compromise via
    /// Exposed Secrets" attack chain with critical severity.
    #[test]
    fn test_correlate_credential_chain() {
        // Arrange
        let findings = vec![
            CorrelationFinding {
                id: "f1".to_string(),
                module_id: "trufflehog".to_string(),
                title: "Exposed API key in source code".to_string(),
                severity: "critical".to_string(),
            },
            CorrelationFinding {
                id: "f2".to_string(),
                module_id: "sensitive".to_string(),
                title: "Hardcoded credential in config".to_string(),
                severity: "high".to_string(),
            },
        ];

        // Act
        let chains = correlate_attack_chains(&findings);

        // Assert
        assert!(!chains.is_empty(), "should produce at least one chain");
        let cred_chain = chains
            .iter()
            .find(|c| c.name.contains("Credential Compromise"))
            .expect("should contain Credential Compromise chain");
        assert_eq!(cred_chain.severity, "critical");
        assert_eq!(cred_chain.remediation_priority, "immediate");
        assert!(cred_chain.findings.contains(&"f1".to_string()));
        assert!(cred_chain.findings.contains(&"f2".to_string()));
    }
}
