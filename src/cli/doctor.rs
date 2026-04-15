//! Doctor command — validates external tool installation and health.
//!
//! Basic mode (`doctor`) checks binary presence via `which`.
//! Deep mode (`doctor --deep`) additionally validates versions,
//! checks minimum version requirements, and runs tool-specific
//! health checks like nuclei template freshness.

use std::process::Command;
use std::time::Duration;

use colored::Colorize;

use crate::engine::error::Result;

/// Declarative specification for an external tool.
struct ToolSpec {
    binary: &'static str,
    name: &'static str,
    category: &'static str,
    version_flag: Option<&'static str>,
    min_version: Option<&'static str>,
    remediation: &'static str,
}

/// Result of checking a single tool.
struct ToolCheckResult {
    name: &'static str,
    category: &'static str,
    installed: bool,
    path: Option<String>,
    version: Option<String>,
    version_ok: Option<bool>,
    min_version: Option<&'static str>,
    remediation: &'static str,
    deep_notes: Vec<DeepNote>,
}

/// A note from a deep check — warn or info level.
enum DeepNote {
    Warn(String),
    Info(String),
}

/// Parsed version for numeric comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version(Vec<u32>);

impl Version {
    /// Parse a version string like "7.94.1" into numeric segments.
    /// Returns `None` if the string contains no numeric segments.
    fn parse(s: &str) -> Option<Self> {
        let segments: Vec<u32> = s.split('.').filter_map(|seg| seg.parse().ok()).collect();
        if segments.is_empty() {
            None
        } else {
            Some(Self(segments))
        }
    }

    /// Compare two versions numerically. Missing segments are treated as 0.
    /// Returns true if `self >= other`.
    fn is_at_least(&self, other: &Self) -> bool {
        let max_len = self.0.len().max(other.0.len());
        for i in 0..max_len {
            let a = self.0.get(i).copied().unwrap_or(0);
            let b = other.0.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                std::cmp::Ordering::Greater => return true,
                std::cmp::Ordering::Less => return false,
                std::cmp::Ordering::Equal => {}
            }
        }
        true // equal
    }
}

/// Extract the first version-like string (digits separated by dots) from text.
///
/// Scans for patterns like "7.94", "3.2.0", "1.7". Returns the first match
/// with at least one dot separator.
fn extract_version(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Find start of a digit sequence
        if chars[i].is_ascii_digit() {
            let start = i;
            let mut has_dot = false;

            // Consume digits and dots
            while i < len && (chars[i].is_ascii_digit() || chars[i] == '.') {
                if chars[i] == '.' {
                    has_dot = true;
                }
                i += 1;
            }

            if has_dot {
                let candidate: String = chars[start..i].iter().collect();
                // Trim trailing dots
                let trimmed = candidate.trim_end_matches('.');
                if trimmed.contains('.') {
                    return Some(trimmed.to_string());
                }
            }
        } else {
            i += 1;
        }
    }

    None
}

/// Check if a tool binary is available in PATH.
#[must_use]
pub fn is_tool_available(tool: &str) -> bool {
    Command::new("which").arg(tool).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Get the full path of a tool binary.
fn which_path(tool: &str) -> Option<String> {
    Command::new("which").arg(tool).output().ok().and_then(|o| {
        if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else {
            None
        }
    })
}

/// Run a tool with a version flag and extract the version string.
fn get_tool_version(binary: &str, version_flag: &str) -> Option<String> {
    let output = Command::new(binary)
        .arg(version_flag)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()
        .and_then(|child| child.wait_with_output().ok())?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Try stdout first, then stderr (some tools print version to stderr)
    extract_version(&stdout).or_else(|| extract_version(&stderr))
}

/// Check nuclei template freshness by examining the templates directory.
fn check_nuclei_templates() -> DeepNote {
    let home = std::env::var("HOME").unwrap_or_default();
    let paths = [
        format!("{home}/nuclei-templates"),
        format!("{home}/.local/nuclei-templates"),
        format!("{home}/.config/nuclei/templates"),
    ];

    for path in &paths {
        let dir = std::path::Path::new(path);
        if dir.exists() {
            if let Ok(metadata) = std::fs::metadata(dir) {
                if let Ok(modified) = metadata.modified() {
                    let age = modified.elapsed().unwrap_or(Duration::from_secs(0));
                    let days = age.as_secs() / 86400;
                    if days > 30 {
                        return DeepNote::Warn(format!(
                            "Templates last updated {days} days ago. Run: nuclei -ut"
                        ));
                    }
                    return DeepNote::Info(format!("Templates updated {days} days ago"));
                }
            }
        }
    }

    DeepNote::Warn("Templates directory not found. Run: nuclei -ut".to_string())
}

/// All external tools that `ScorchKit` can use.
#[allow(clippy::too_many_lines)] // Declarative data table — splitting would reduce readability.
fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            binary: "nmap",
            name: "Nmap",
            category: "Network",
            version_flag: Some("--version"),
            min_version: Some("7.80"),
            remediation: "Install: apt install nmap",
        },
        ToolSpec {
            binary: "nikto",
            name: "Nikto",
            category: "Web Scanner",
            version_flag: Some("-Version"),
            min_version: Some("2.1.6"),
            remediation: "Install: apt install nikto",
        },
        ToolSpec {
            binary: "nuclei",
            name: "Nuclei",
            category: "Web Scanner",
            version_flag: Some("-version"),
            min_version: Some("3.0.0"),
            remediation: "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        ToolSpec {
            binary: "zap.sh",
            name: "OWASP ZAP",
            category: "Web Scanner",
            version_flag: Some("-version"),
            min_version: Some("2.14.0"),
            remediation: "Install: see https://www.zaproxy.org/download/",
        },
        ToolSpec {
            binary: "wpscan",
            name: "WPScan",
            category: "CMS Scanner",
            version_flag: Some("--version"),
            min_version: Some("3.8.0"),
            remediation: "Install: gem install wpscan",
        },
        ToolSpec {
            binary: "droopescan",
            name: "Droopescan",
            category: "CMS Scanner",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pip install droopescan",
        },
        ToolSpec {
            binary: "sqlmap",
            name: "SQLMap",
            category: "Injection",
            version_flag: Some("--version"),
            min_version: Some("1.7"),
            remediation: "Install: apt install sqlmap",
        },
        ToolSpec {
            binary: "dalfox",
            name: "Dalfox",
            category: "XSS",
            version_flag: Some("version"),
            min_version: Some("2.8.0"),
            remediation: "Install: go install github.com/hahwul/dalfox/v2@latest",
        },
        ToolSpec {
            binary: "feroxbuster",
            name: "Feroxbuster",
            category: "Discovery",
            version_flag: Some("--version"),
            min_version: Some("2.0.0"),
            remediation: "Install: cargo install feroxbuster",
        },
        ToolSpec {
            binary: "ffuf",
            name: "ffuf",
            category: "Fuzzer",
            version_flag: Some("-V"),
            min_version: Some("2.0.0"),
            remediation: "Install: go install github.com/ffuf/ffuf/v2@latest",
        },
        ToolSpec {
            binary: "arjun",
            name: "Arjun",
            category: "Param Discovery",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pip install arjun",
        },
        ToolSpec {
            binary: "cewl",
            name: "CeWL",
            category: "Wordlist",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: gem install cewl",
        },
        ToolSpec {
            binary: "sslyze",
            name: "SSLyze",
            category: "TLS/SSL",
            version_flag: Some("--version"),
            min_version: Some("5.0.0"),
            remediation: "Install: pip install sslyze",
        },
        ToolSpec {
            binary: "testssl.sh",
            name: "testssl.sh",
            category: "TLS/SSL",
            version_flag: Some("--version"),
            min_version: Some("3.0"),
            remediation: "Install: git clone https://github.com/drwetter/testssl.sh",
        },
        ToolSpec {
            binary: "amass",
            name: "Amass",
            category: "Subdomain",
            version_flag: Some("-version"),
            min_version: Some("4.0.0"),
            remediation: "Install: go install github.com/owasp-amass/amass/v4/...@master",
        },
        ToolSpec {
            binary: "subfinder",
            name: "Subfinder",
            category: "Subdomain",
            version_flag: Some("-version"),
            min_version: Some("2.6.0"),
            remediation: "Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        },
        ToolSpec {
            binary: "httpx",
            name: "httpx",
            category: "HTTP Probe",
            version_flag: Some("-version"),
            min_version: Some("1.3.0"),
            remediation: "Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
        ToolSpec {
            binary: "theHarvester",
            name: "theHarvester",
            category: "OSINT",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pip install theHarvester",
        },
        ToolSpec {
            binary: "wafw00f",
            name: "wafw00f",
            category: "WAF Detection",
            version_flag: Some("--version"),
            min_version: Some("2.0.0"),
            remediation: "Install: pip install wafw00f",
        },
        ToolSpec {
            binary: "hydra",
            name: "Hydra",
            category: "Credentials",
            version_flag: Some("-V"),
            min_version: Some("9.0"),
            remediation: "Install: apt install hydra",
        },
        ToolSpec {
            binary: "msfconsole",
            name: "Metasploit",
            category: "Exploit",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: see https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html",
        },
        ToolSpec {
            binary: "claude",
            name: "Claude Code",
            category: "AI Analysis",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: npm install -g @anthropic-ai/claude-code",
        },
        ToolSpec {
            binary: "interactsh-client",
            name: "Interactsh",
            category: "OOB Callbacks",
            version_flag: Some("-version"),
            min_version: Some("1.1.0"),
            remediation: "Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        },
        ToolSpec {
            binary: "katana",
            name: "Katana",
            category: "Crawling",
            version_flag: Some("-version"),
            min_version: Some("1.0.0"),
            remediation: "Install: go install github.com/projectdiscovery/katana/cmd/katana@latest",
        },
        ToolSpec {
            binary: "gau",
            name: "gau",
            category: "URL Discovery",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: go install github.com/lc/gau/v2/cmd/gau@latest",
        },
        ToolSpec {
            binary: "paramspider",
            name: "ParamSpider",
            category: "Param Discovery",
            version_flag: None,
            min_version: None,
            remediation: "Install: pip install paramspider",
        },
        ToolSpec {
            binary: "trufflehog",
            name: "TruffleHog",
            category: "Secrets",
            version_flag: Some("--version"),
            min_version: Some("3.0.0"),
            remediation: "Install: go install github.com/trufflesecurity/trufflehog/v3@latest",
        },
        ToolSpec {
            binary: "prowler",
            name: "Prowler",
            category: "Cloud Security",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pip install prowler",
        },
        ToolSpec {
            binary: "trivy",
            name: "Trivy",
            category: "Container Security",
            version_flag: Some("--version"),
            min_version: Some("0.50.0"),
            remediation: "Install: see https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
        },
        ToolSpec {
            binary: "dnsx",
            name: "dnsx",
            category: "DNS",
            version_flag: Some("-version"),
            min_version: Some("1.1.0"),
            remediation: "Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        },
        ToolSpec {
            binary: "gobuster",
            name: "Gobuster",
            category: "Discovery",
            version_flag: Some("version"),
            min_version: Some("3.0.0"),
            remediation: "Install: go install github.com/OJ/gobuster/v3@latest",
        },
        ToolSpec {
            binary: "dnsrecon",
            name: "DNSRecon",
            category: "DNS",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pip install dnsrecon",
        },
        ToolSpec {
            binary: "enum4linux",
            name: "enum4linux",
            category: "SMB Enum",
            version_flag: None,
            min_version: None,
            remediation: "Install: apt install enum4linux",
        },
        ToolSpec {
            binary: "semgrep",
            name: "Semgrep",
            category: "SAST",
            version_flag: Some("--version"),
            min_version: Some("1.0.0"),
            remediation: "Install: pip install semgrep",
        },
        ToolSpec {
            binary: "osv-scanner",
            name: "OSV-Scanner",
            category: "SCA",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
        },
        ToolSpec {
            binary: "gitleaks",
            name: "Gitleaks",
            category: "Secrets",
            version_flag: Some("version"),
            min_version: Some("8.0.0"),
            remediation: "Install: go install github.com/gitleaks/gitleaks/v8@latest",
        },
        // WORK-111: network/infra tool batch
        ToolSpec {
            binary: "masscan",
            name: "masscan",
            category: "Network",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: apt install masscan (Debian/Ubuntu) or build from \
                          https://github.com/robertdavidgraham/masscan",
        },
        ToolSpec {
            binary: "naabu",
            name: "naabu",
            category: "Network",
            version_flag: Some("-version"),
            min_version: None,
            remediation: "Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        },
        ToolSpec {
            binary: "smbmap",
            name: "smbmap",
            category: "Network",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pipx install smbmap (or pip install smbmap)",
        },
        ToolSpec {
            binary: "nxc",
            name: "NetExec (nxc)",
            category: "Network",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pipx install git+https://github.com/Pennyw0rth/NetExec",
        },
        ToolSpec {
            binary: "kerbrute",
            name: "kerbrute",
            category: "Network",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: go install github.com/ropnop/kerbrute@latest",
        },
        ToolSpec {
            binary: "ssh-audit",
            name: "ssh-audit",
            category: "Network",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pipx install ssh-audit (or pip install ssh-audit)",
        },
        ToolSpec {
            binary: "onesixtyone",
            name: "onesixtyone",
            category: "Network",
            version_flag: None,
            min_version: None,
            remediation: "Install: apt install onesixtyone (Debian/Ubuntu) or build from \
                          https://github.com/trailofbits/onesixtyone",
        },
        // WORK-107: Vespasian API endpoint discovery
        ToolSpec {
            binary: "vespasian",
            name: "Vespasian",
            category: "API Discovery",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: go install github.com/praetorian-inc/vespasian/cmd/vespasian@latest",
        },
        // WORK-113: SAST expansion batch
        ToolSpec {
            binary: "cargo-audit",
            name: "cargo-audit",
            category: "SCA",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: cargo install cargo-audit",
        },
        ToolSpec {
            binary: "cargo-deny",
            name: "cargo-deny",
            category: "SCA",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: cargo install cargo-deny",
        },
        ToolSpec {
            binary: "tflint",
            name: "tflint",
            category: "IaC",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: brew install tflint or curl-pipe-bash from \
                          https://github.com/terraform-linters/tflint",
        },
        ToolSpec {
            binary: "kics",
            name: "KICS",
            category: "IaC",
            version_flag: Some("version"),
            min_version: None,
            remediation: "Install: brew install kics or download from \
                          https://github.com/Checkmarx/kics/releases",
        },
        ToolSpec {
            binary: "slither",
            name: "slither",
            category: "SAST",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pipx install slither-analyzer",
        },
        ToolSpec {
            binary: "brakeman",
            name: "brakeman",
            category: "SAST",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: gem install brakeman",
        },
        // WORK-112: DAST polish tool batch
        ToolSpec {
            binary: "commix",
            name: "commix",
            category: "Web",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pipx install commix or git clone \
                          https://github.com/commixproject/commix",
        },
        ToolSpec {
            binary: "xsstrike",
            name: "XSStrike",
            category: "Web",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pipx install xsstrike or git clone \
                          https://github.com/s0md3v/XSStrike",
        },
        ToolSpec {
            binary: "whatweb",
            name: "WhatWeb",
            category: "Recon",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: apt install whatweb (Debian/Ubuntu) or git clone \
                          https://github.com/urbanadventurer/WhatWeb",
        },
        ToolSpec {
            binary: "wapiti",
            name: "Wapiti",
            category: "Web",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pipx install wapiti3",
        },
        ToolSpec {
            binary: "linkfinder",
            name: "LinkFinder",
            category: "Recon",
            version_flag: Some("--help"),
            min_version: None,
            remediation: "Install: pipx install linkfinder or git clone \
                          https://github.com/GerbenJavado/LinkFinder",
        },
        ToolSpec {
            binary: "eyewitness",
            name: "EyeWitness",
            category: "Recon",
            version_flag: Some("--help"),
            min_version: None,
            remediation: "Install: apt install eyewitness or git clone \
                          https://github.com/RedSiege/EyeWitness",
        },
        // WORK-114: container/cloud tool batch
        ToolSpec {
            binary: "dockle",
            name: "dockle",
            category: "Container",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: brew install goodwithtech/r/dockle or download from \
                          https://github.com/goodwithtech/dockle/releases",
        },
        ToolSpec {
            binary: "kubescape",
            name: "kubescape",
            category: "Cloud",
            version_flag: Some("version"),
            min_version: None,
            remediation: "Install: curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash",
        },
        ToolSpec {
            binary: "scout",
            name: "Scout Suite",
            category: "Cloud",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: pipx install scoutsuite",
        },
    ]
}

/// Check a single tool and return the result.
fn check_tool(spec: &ToolSpec, deep: bool) -> ToolCheckResult {
    let installed = is_tool_available(spec.binary);
    let path = if installed { which_path(spec.binary) } else { None };

    let mut version = None;
    let mut version_ok = None;
    let mut deep_notes = Vec::new();

    if deep && installed {
        // Extract version
        if let Some(flag) = spec.version_flag {
            version = get_tool_version(spec.binary, flag);

            // Compare against minimum
            if let (Some(ref ver_str), Some(min_str)) = (&version, spec.min_version) {
                if let (Some(ver), Some(min)) = (Version::parse(ver_str), Version::parse(min_str)) {
                    version_ok = Some(ver.is_at_least(&min));
                }
            }
        }

        // Nuclei-specific: template freshness
        if spec.binary == "nuclei" {
            deep_notes.push(check_nuclei_templates());
        }
    }

    ToolCheckResult {
        name: spec.name,
        category: spec.category,
        installed,
        path,
        version,
        version_ok,
        min_version: spec.min_version,
        remediation: spec.remediation,
        deep_notes,
    }
}

/// Run the doctor command.
///
/// In basic mode, checks binary presence for all known tools.
/// In deep mode, additionally validates versions and runs health checks.
///
/// # Errors
///
/// Returns an error if terminal output fails.
pub fn run_doctor(deep: bool) -> Result<()> {
    println!();
    if deep {
        println!("{}", "ScorchKit Doctor (deep)".bold().underline());
    } else {
        println!("{}", "ScorchKit Doctor".bold().underline());
    }
    println!();

    let specs = tool_specs();
    let results: Vec<ToolCheckResult> = specs.iter().map(|spec| check_tool(spec, deep)).collect();

    let mut installed_count = 0u32;
    let mut missing_count = 0u32;
    let mut version_pass = 0u32;
    let mut version_fail = 0u32;
    let mut warn_count = 0u32;

    for result in &results {
        if result.installed {
            installed_count += 1;
            print_installed_tool(result, deep);
        } else {
            missing_count += 1;
            print_missing_tool(result, deep);
        }

        // Count version results
        match result.version_ok {
            Some(true) => version_pass += 1,
            Some(false) => version_fail += 1,
            None => {}
        }

        // Count and print deep notes
        for note in &result.deep_notes {
            match note {
                DeepNote::Warn(msg) => {
                    warn_count += 1;
                    println!("     {} {}", "WARN".yellow().bold(), msg);
                }
                DeepNote::Info(msg) => {
                    println!("     {} {}", "info".dimmed(), msg.dimmed());
                }
            }
        }
    }

    // Summary
    println!();
    let total = installed_count + missing_count;
    println!("  {}/{} tools installed", installed_count.to_string().green().bold(), total);

    if deep {
        let checked = version_pass + version_fail;
        if checked > 0 {
            println!(
                "  {}/{} version checks passed",
                version_pass.to_string().green().bold(),
                checked
            );
        }
        if version_fail > 0 {
            println!(
                "  {} {}",
                version_fail.to_string().red().bold(),
                "version(s) below minimum".red()
            );
        }
        if warn_count > 0 {
            println!("  {} warning(s)", warn_count.to_string().yellow().bold());
        }
    }

    if missing_count > 0 {
        println!("  See {} for install instructions", "docs/tools-checklist.md".cyan());
    }

    println!();
    Ok(())
}

/// Print a line for an installed tool.
fn print_installed_tool(result: &ToolCheckResult, deep: bool) {
    let path_str = result.path.as_deref().unwrap_or("");

    if deep {
        let version_str = result.version.as_deref().unwrap_or("-");
        let version_note = match (result.version_ok, result.min_version) {
            (Some(true), Some(min)) => format!("(>= {min})").green().to_string(),
            (Some(false), Some(min)) => format!("(need >= {min})").red().to_string(),
            _ => String::new(),
        };

        let status = match result.version_ok {
            Some(false) => "FAIL".red().bold().to_string(),
            _ => "OK".green().bold().to_string(),
        };

        println!(
            "  {:<4} {:<20} {:<18} {:<8} {:<16} {}",
            status,
            result.name,
            result.category.dimmed(),
            version_str,
            version_note,
            path_str.dimmed()
        );
    } else {
        println!(
            "  {} {:<20} {:<16} {}",
            "OK".green().bold(),
            result.name,
            result.category.dimmed(),
            path_str.dimmed()
        );
    }
}

/// Print a line for a missing tool.
fn print_missing_tool(result: &ToolCheckResult, deep: bool) {
    if deep {
        println!("  {:<4} {:<20} {}", "--".red(), result.name, result.category.dimmed());
        println!("     {} {}", "hint".dimmed(), result.remediation.dimmed());
    } else {
        println!("  {} {:<20} {}", "--".red(), result.name, result.category.dimmed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parse() {
        let v = Version::parse("7.94.1").expect("should parse");
        assert_eq!(v.0, vec![7, 94, 1]);

        let v = Version::parse("3.0.0").expect("should parse");
        assert_eq!(v.0, vec![3, 0, 0]);

        let v = Version::parse("1.7").expect("should parse");
        assert_eq!(v.0, vec![1, 7]);
    }

    #[test]
    fn test_version_compare() {
        let v794 = Version::parse("7.94").expect("parse");
        let v780 = Version::parse("7.80").expect("parse");
        let v300 = Version::parse("3.0.0").expect("parse");
        let v310 = Version::parse("3.1.0").expect("parse");

        assert!(v794.is_at_least(&v780), "7.94 >= 7.80");
        assert!(!v780.is_at_least(&v794), "7.80 < 7.94");
        assert!(!v300.is_at_least(&v310), "3.0.0 < 3.1.0");
        assert!(v310.is_at_least(&v300), "3.1.0 >= 3.0.0");

        // Equal
        let v2 = Version::parse("2.0.0").expect("parse");
        let v2b = Version::parse("2.0.0").expect("parse");
        assert!(v2.is_at_least(&v2b), "equal versions");
    }

    #[test]
    fn test_version_compare_unequal_length() {
        let v794 = Version::parse("7.94").expect("parse");
        let v7941 = Version::parse("7.94.1").expect("parse");
        let v2 = Version::parse("2").expect("parse");
        let v200 = Version::parse("2.0.0").expect("parse");

        // 7.94 < 7.94.1 (missing segment = 0, so 7.94.0 < 7.94.1)
        assert!(!v794.is_at_least(&v7941));
        assert!(v7941.is_at_least(&v794));

        // 2 == 2.0.0
        assert!(v2.is_at_least(&v200));
        assert!(v200.is_at_least(&v2));
    }

    #[test]
    fn test_extract_version_from_nmap_output() {
        let output = "Nmap version 7.94SVN ( https://nmap.org )";
        let version = extract_version(output).expect("should extract");
        assert_eq!(version, "7.94");
    }

    #[test]
    fn test_extract_version_from_nuclei_output() {
        let output = "Current Version: v3.2.0";
        let version = extract_version(output).expect("should extract");
        assert_eq!(version, "3.2.0");
    }

    #[test]
    fn test_extract_version_from_noisy_output() {
        let output = "Some tool\nCopyright 2024\nVersion: 1.2.3-beta\nLicense: MIT";
        let version = extract_version(output).expect("should extract");
        assert_eq!(version, "1.2.3");

        // Output with only a single number (no dot)
        let no_version = "No version here just 42";
        assert!(extract_version(no_version).is_none());
    }

    #[test]
    fn test_tool_specs_complete() {
        let specs = tool_specs();

        // All specs have non-empty remediation hints
        for spec in &specs {
            assert!(!spec.remediation.is_empty(), "Tool {} has empty remediation", spec.name);
            assert!(!spec.name.is_empty(), "Tool has empty name");
            assert!(!spec.binary.is_empty(), "Tool {} has empty binary", spec.name);
            assert!(!spec.category.is_empty(), "Tool {} has empty category", spec.name);
        }

        // Should have at least the original 22 tools plus new additions
        assert!(specs.len() >= 22, "Expected at least 22 tools, got {}", specs.len());
    }

    #[test]
    fn test_version_parse_edge_cases() {
        // Empty string
        assert!(Version::parse("").is_none());

        // Single number (valid — some tools use single-segment versions)
        let v = Version::parse("42").expect("should parse single number");
        assert_eq!(v.0, vec![42]);

        // Non-numeric
        assert!(Version::parse("abc").is_none());
        assert!(Version::parse("...").is_none());

        // Version with trailing garbage
        let v = Version::parse("1.2.3").expect("should parse");
        assert_eq!(v.0, vec![1, 2, 3]);
    }
}
