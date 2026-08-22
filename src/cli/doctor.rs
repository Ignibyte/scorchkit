//! Doctor command — validates external tool installation and health.
//!
//! Basic mode (`doctor`) checks binary presence via `which`.
//! Deep mode (`doctor --deep`) additionally validates versions,
//! checks minimum version requirements, and runs tool-specific
//! tool-specific runtime health checks.

use std::{fmt::Write, time::Duration};

use colored::Colorize;

use crate::engine::error::Result;
use crate::runner::subprocess::{
    resolve_tool_path, SystemToolExecutor, ToolExecutor, ToolInvocation,
};

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
#[derive(Debug)]
struct ToolCheckResult {
    name: &'static str,
    category: &'static str,
    installed: bool,
    path: Option<String>,
    version: Option<String>,
    version_ok: Option<bool>,
    min_version: Option<&'static str>,
    exact_version: bool,
    remediation: &'static str,
    deep_notes: Vec<DeepNote>,
}

/// A note from a deep check — warn or info level.
#[derive(Debug, PartialEq, Eq)]
enum DeepNote {
    Warn(String),
    Info(String),
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DeepCheckPlan {
    version_flag: Option<&'static str>,
    check_nuclei_templates: bool,
    check_zap_runtime: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DoctorSummary {
    installed: usize,
    missing: usize,
    version_pass: usize,
    version_fail: usize,
    warnings: usize,
}

impl DoctorSummary {
    fn from_results(results: &[ToolCheckResult]) -> Self {
        Self {
            installed: results.iter().filter(|result| result.installed).count(),
            missing: results.iter().filter(|result| !result.installed).count(),
            version_pass: results.iter().filter(|result| result.version_ok == Some(true)).count(),
            version_fail: results.iter().filter(|result| result.version_ok == Some(false)).count(),
            warnings: results
                .iter()
                .flat_map(|result| &result.deep_notes)
                .filter(|note| matches!(note, DeepNote::Warn(_)))
                .count(),
        }
    }

    const fn total(&self) -> usize {
        self.installed + self.missing
    }

    const fn version_checked(&self) -> usize {
        self.version_pass + self.version_fail
    }
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

fn requires_exact_version(binary: &str) -> bool {
    matches!(binary, "nuclei" | "zap.sh" | "syft" | "osv-scanner" | "grype" | "trivy")
}

fn version_satisfies(binary: &str, detected: &Version, required: &Version) -> bool {
    if requires_exact_version(binary) {
        detected == required
    } else {
        detected.is_at_least(required)
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
    crate::runner::subprocess::is_tool_available(tool)
}

/// Get the full path of a tool binary.
fn which_path(tool: &str) -> Option<String> {
    resolve_tool_path(tool).ok().map(|path| path.display().to_string())
}

/// Run a tool with a version flag and extract the version string.
async fn get_tool_version(binary: &str, version_flag: &str) -> Option<String> {
    let args = if binary == "zap.sh" {
        vec!["-host", "127.0.0.1", "-port", "0", version_flag]
    } else {
        vec![version_flag]
    };
    let output = SystemToolExecutor
        .execute(ToolInvocation::lenient(binary, &args, Duration::from_secs(15)))
        .await
        .ok()?;

    // Try stdout first, then stderr (some tools print version to stderr)
    if binary == "zap.sh" {
        standalone_zap_version(&format!("{}\n{}", output.stdout, output.stderr))
    } else {
        extract_version(&output.stdout).or_else(|| extract_version(&output.stderr))
    }
}

fn standalone_zap_version(output: &str) -> Option<String> {
    let mut versions = output.lines().map(str::trim).filter(|line| {
        let mut components = line.split('.');
        let valid = (0..3).all(|_| {
            components.next().is_some_and(|component| {
                !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
            })
        });
        valid && components.next().is_none()
    });
    let version = versions.next()?.to_string();
    versions.next().is_none().then_some(version)
}

/// Explain the trusted Nuclei input boundary without inspecting ambient templates.
fn check_nuclei_templates() -> DeepNote {
    DeepNote::Info(
        "Ambient Nuclei templates are disabled; scans require an explicit trusted collection manifest"
            .to_string(),
    )
}

fn deep_check_plan(spec: &ToolSpec, deep: bool, installed: bool) -> DeepCheckPlan {
    if deep && installed {
        DeepCheckPlan {
            version_flag: spec.version_flag,
            check_nuclei_templates: spec.binary == "nuclei",
            check_zap_runtime: spec.binary == "zap.sh",
        }
    } else {
        DeepCheckPlan::default()
    }
}

fn check_zap_runtime() -> Vec<DeepNote> {
    let Ok(executable) = resolve_tool_path("zap.sh") else {
        return vec![DeepNote::Warn("Cannot resolve the ZAP executable".to_string())];
    };
    let Some(root) = executable.parent() else {
        return vec![DeepNote::Warn("Cannot resolve the ZAP install root".to_string())];
    };
    let plugin_dir = root.join("plugin");
    let Ok(entries) = std::fs::read_dir(&plugin_dir) else {
        return vec![DeepNote::Warn(format!(
            "ZAP plugin directory is unavailable: {}",
            plugin_dir.display()
        ))];
    };
    let files: Vec<_> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(std::fs::FileType::is_file)
                .and_then(|_| entry.file_name().into_string().ok())
        })
        .collect();
    let required = [
        "authhelper-",
        "automation-",
        "client-",
        "graphql-",
        "openapi-",
        "reports-",
        "selenium-",
        "spider-",
        "webdriverlinux-",
    ];
    let missing: Vec<_> = required
        .into_iter()
        .filter(|prefix| {
            !files.iter().any(|name| {
                name.starts_with(prefix)
                    && std::path::Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("zap"))
            })
        })
        .collect();
    if !missing.is_empty() {
        return vec![DeepNote::Warn(format!(
            "ZAP runtime is missing required add-ons: {}",
            missing.join(", ")
        ))];
    }
    let auth_archive =
        files.iter().find(|name| name.starts_with("authhelper-")).map(|name| plugin_dir.join(name));
    let reports_archive =
        files.iter().find(|name| name.starts_with("reports-")).map(|name| plugin_dir.join(name));
    let templates_present = auth_archive
        .is_some_and(|path| zip_contains(&path, "reports/auth-report-json/template.yaml"))
        && reports_archive
            .is_some_and(|path| zip_contains(&path, "reports/traditional-json-plus/template.yaml"));
    if !templates_present {
        return vec![DeepNote::Warn(
            "ZAP runtime is missing the required auth-report-json or traditional-json-plus template"
                .to_string(),
        )];
    }
    vec![DeepNote::Info(
        "Required application DAST add-ons and report templates are installed".to_string(),
    )]
}

fn zip_contains(path: &std::path::Path, entry: &str) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return false;
    };
    let contains_entry = archive.by_name(entry).is_ok();
    contains_entry
}

/// All external tools that `ScorchKit` can use.
#[allow(clippy::too_many_lines)] // JUSTIFICATION: declarative table; splitting reduces readability.
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
            min_version: Some("3.11.1"),
            remediation: "Install the checksum-verified official Nuclei 3.11.1 release",
        },
        ToolSpec {
            binary: "zap.sh",
            name: "OWASP ZAP",
            category: "Web Scanner",
            version_flag: Some("-version"),
            min_version: Some("2.17.0"),
            remediation: "Install the checksum-verified official ZAP 2.17.0 Linux archive",
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
            binary: "codex",
            name: "Codex CLI",
            category: "AI Analysis (preferred)",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: npm install -g @openai/codex",
        },
        ToolSpec {
            binary: "claude",
            name: "Claude CLI",
            category: "AI Analysis (compatibility)",
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
            category: "Application Supply Chain",
            version_flag: Some("--version"),
            min_version: Some("0.74.0"),
            remediation: "Install the pinned native Trivy 0.74.0 release asset; do not use a Docker socket wrapper",
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
            binary: "codeql",
            name: "CodeQL CLI bundle",
            category: "Deep SAST",
            version_flag: Some("version"),
            min_version: None,
            remediation: "Install the complete CodeQL CLI bundle from GitHub and review its license",
        },
        ToolSpec {
            binary: "psalm",
            name: "Psalm",
            category: "PHP Taint Analysis",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: composer require --dev vimeo/psalm",
        },
        ToolSpec {
            binary: "phpstan",
            name: "PHPStan",
            category: "PHP Correctness",
            version_flag: Some("--version"),
            min_version: None,
            remediation: "Install: composer require --dev phpstan/phpstan",
        },
        ToolSpec {
            binary: "osv-scanner",
            name: "OSV-Scanner",
            category: "Application Supply Chain",
            version_flag: Some("--version"),
            min_version: Some("2.3.8"),
            remediation: "Install the pinned OSV-Scanner 2.3.8 release asset",
        },
        ToolSpec {
            binary: "syft",
            name: "Syft",
            category: "Application Supply Chain",
            version_flag: Some("--version"),
            min_version: Some("1.50.0"),
            remediation: "Install the pinned Syft 1.50.0 release asset",
        },
        ToolSpec {
            binary: "grype",
            name: "Grype",
            category: "Application Supply Chain",
            version_flag: Some("--version"),
            min_version: Some("0.116.1"),
            remediation: "Install the pinned Grype 0.116.1 release asset",
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
async fn check_tool(spec: &ToolSpec, deep: bool) -> ToolCheckResult {
    let installed = is_tool_available(spec.binary);
    let path = if installed { which_path(spec.binary) } else { None };
    let plan = deep_check_plan(spec, deep, installed);

    let mut version = None;
    let mut version_ok = None;
    let mut deep_notes = Vec::new();

    if let Some(flag) = plan.version_flag {
        version = get_tool_version(spec.binary, flag).await;

        if let (Some(ref ver_str), Some(min_str)) = (&version, spec.min_version) {
            if let (Some(ver), Some(min)) = (Version::parse(ver_str), Version::parse(min_str)) {
                version_ok = Some(version_satisfies(spec.binary, &ver, &min));
            }
        }
    }

    if plan.check_nuclei_templates {
        deep_notes.push(check_nuclei_templates());
    }
    if plan.check_zap_runtime {
        deep_notes.extend(check_zap_runtime());
    }

    ToolCheckResult {
        name: spec.name,
        category: spec.category,
        installed,
        path,
        version,
        version_ok,
        min_version: spec.min_version,
        exact_version: requires_exact_version(spec.binary),
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
pub async fn run_doctor(deep: bool) -> Result<()> {
    println!();
    if deep {
        println!("{}", "ScorchKit Doctor (deep)".bold().underline());
    } else {
        println!("{}", "ScorchKit Doctor".bold().underline());
    }
    println!();

    let specs = tool_specs();
    let mut results = Vec::with_capacity(specs.len());
    for spec in &specs {
        results.push(check_tool(spec, deep).await);
    }

    for result in &results {
        print!("{}", render_tool_result(result, deep));
    }

    print!("{}", render_doctor_summary(&DoctorSummary::from_results(&results), deep));
    Ok(())
}

fn render_tool_result(result: &ToolCheckResult, deep: bool) -> String {
    let mut output = String::new();
    let path = crate::report::terminal::escape_terminal_text(result.path.as_deref().unwrap_or(""));

    if result.installed {
        if deep {
            let version = crate::report::terminal::escape_terminal_text(
                result.version.as_deref().unwrap_or("-"),
            );
            let version_note = match (result.version_ok, result.min_version, result.exact_version) {
                (Some(true), Some(required), true) => format!("(= {required})").green().to_string(),
                (Some(false), Some(required), true) => {
                    format!("(need = {required})").red().to_string()
                }
                (Some(true), Some(required), false) => {
                    format!("(>= {required})").green().to_string()
                }
                (Some(false), Some(required), false) => {
                    format!("(need >= {required})").red().to_string()
                }
                _ => String::new(),
            };
            let status = match result.version_ok {
                Some(false) => "FAIL".red().bold().to_string(),
                _ => "OK".green().bold().to_string(),
            };
            let _ = writeln!(
                output,
                "  {status:<4} {:<20} {:<18} {version:<8} {version_note:<16} {}",
                result.name,
                result.category.dimmed(),
                path.dimmed()
            );
        } else {
            let _ = writeln!(
                output,
                "  {} {:<20} {:<16} {}",
                "OK".green().bold(),
                result.name,
                result.category.dimmed(),
                path.dimmed()
            );
        }
    } else if deep {
        let _ = writeln!(
            output,
            "  {:<4} {:<20} {}",
            "--".red(),
            result.name,
            result.category.dimmed()
        );
        let _ = writeln!(output, "     {} {}", "hint".dimmed(), result.remediation.dimmed());
    } else {
        let _ =
            writeln!(output, "  {} {:<20} {}", "--".red(), result.name, result.category.dimmed());
    }

    for note in &result.deep_notes {
        match note {
            DeepNote::Warn(message) => {
                let message = crate::report::terminal::escape_terminal_text(message);
                let _ = writeln!(output, "     {} {message}", "WARN".yellow().bold());
            }
            DeepNote::Info(message) => {
                let message = crate::report::terminal::escape_terminal_text(message);
                let _ = writeln!(output, "     {} {}", "info".dimmed(), message.dimmed());
            }
        }
    }

    output
}

fn render_doctor_summary(summary: &DoctorSummary, deep: bool) -> String {
    let mut output = String::from("\n");
    let installed =
        format!("{}/{} tools installed", summary.installed, summary.total()).green().bold();
    let _ = writeln!(output, "  {installed}");

    if deep {
        let checked = summary.version_checked();
        if checked > 0 {
            let passed = format!("{}/{} version checks passed", summary.version_pass, checked)
                .green()
                .bold();
            let _ = writeln!(output, "  {passed}");
        }
        if summary.version_fail > 0 {
            let below = format!("{} version(s) below minimum", summary.version_fail).red().bold();
            let _ = writeln!(output, "  {below}");
        }
        if summary.warnings > 0 {
            let warnings = format!("{} warning(s)", summary.warnings).yellow().bold();
            let _ = writeln!(output, "  {warnings}");
        }
    }

    if summary.missing > 0 {
        let _ =
            writeln!(output, "  See {} for install instructions", "docs/tools-checklist.md".cyan());
    }
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    struct PathGuard(Option<std::ffi::OsString>);

    #[cfg(unix)]
    impl Drop for PathGuard {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                std::env::set_var("PATH", path);
            } else {
                std::env::remove_var("PATH");
            }
        }
    }

    #[cfg(unix)]
    fn zap_runtime_fixture(auth_template: bool, reports_template: bool) -> tempfile::TempDir {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temporary ZAP runtime");
        let executable = root.path().join("zap.sh");
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("write ZAP launcher");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("make ZAP launcher executable");
        let plugin = root.path().join("plugin");
        std::fs::create_dir(&plugin).expect("create plugin directory");

        for prefix in [
            "authhelper-",
            "automation-",
            "client-",
            "graphql-",
            "openapi-",
            "reports-",
            "selenium-",
            "spider-",
            "webdriverlinux-",
        ] {
            let path = plugin.join(format!("{prefix}fixture.zap"));
            let file = std::fs::File::create(path).expect("create add-on archive");
            let mut archive = zip::ZipWriter::new(file);
            let entry = match prefix {
                "authhelper-" if auth_template => Some("reports/auth-report-json/template.yaml"),
                "reports-" if reports_template => {
                    Some("reports/traditional-json-plus/template.yaml")
                }
                _ => None,
            };
            if let Some(entry) = entry {
                archive
                    .start_file(entry, zip::write::SimpleFileOptions::default())
                    .expect("start add-on entry");
                archive.write_all(b"fixture").expect("write add-on entry");
            }
            archive.finish().expect("finish add-on archive");
        }
        root
    }

    #[cfg(unix)]
    fn with_path<T>(path: &std::path::Path, test: impl FnOnce() -> T) -> T {
        let _guard = PathGuard(std::env::var_os("PATH"));
        std::env::set_var("PATH", path);
        test()
    }

    fn tool_spec(binary: &'static str) -> ToolSpec {
        ToolSpec {
            binary,
            name: "Fixture Tool",
            category: "Fixture",
            version_flag: Some("--version"),
            min_version: Some("3.0.0"),
            remediation: "Install the fixture tool",
        }
    }

    fn tool_result(
        installed: bool,
        version: Option<&str>,
        version_ok: Option<bool>,
        notes: Vec<DeepNote>,
    ) -> ToolCheckResult {
        ToolCheckResult {
            name: "Fixture Tool",
            category: "Fixture",
            installed,
            path: installed.then(|| "/opt/fixture\u{1b}".to_string()),
            version: version.map(str::to_string),
            version_ok,
            min_version: Some("3.0.0"),
            exact_version: false,
            remediation: "Install the fixture tool",
            deep_notes: notes,
        }
    }

    #[test]
    fn nuclei_health_note_rejects_ambient_template_ownership() {
        assert_eq!(
            check_nuclei_templates(),
            DeepNote::Info(
                "Ambient Nuclei templates are disabled; scans require an explicit trusted collection manifest"
                    .to_string()
            )
        );
    }

    #[test]
    fn reviewed_runtime_tools_require_exact_pinned_versions() {
        for binary in ["nuclei", "zap.sh", "syft", "osv-scanner", "grype", "trivy"] {
            assert!(requires_exact_version(binary), "{binary} must remain exact-pinned");
        }
        assert!(!requires_exact_version("nmap"));

        let pinned = Version::parse("0.74.0").expect("pinned version");
        let newer = Version::parse("0.75.0").expect("newer version");
        assert!(version_satisfies("trivy", &pinned, &pinned));
        assert!(!version_satisfies("trivy", &newer, &pinned));
        assert!(version_satisfies("nmap", &newer, &pinned));
    }

    #[test]
    fn deep_check_plan_requires_deep_mode_and_an_installed_tool() {
        let ordinary = tool_spec("nmap");
        assert_eq!(deep_check_plan(&ordinary, false, true), DeepCheckPlan::default());
        assert_eq!(deep_check_plan(&ordinary, true, false), DeepCheckPlan::default());
        assert_eq!(
            deep_check_plan(&ordinary, true, true),
            DeepCheckPlan {
                version_flag: Some("--version"),
                check_nuclei_templates: false,
                check_zap_runtime: false,
            }
        );

        let nuclei = tool_spec("nuclei");
        assert_eq!(
            deep_check_plan(&nuclei, true, true),
            DeepCheckPlan {
                version_flag: Some("--version"),
                check_nuclei_templates: true,
                check_zap_runtime: false,
            }
        );

        let zap = tool_spec("zap.sh");
        assert_eq!(
            deep_check_plan(&zap, true, true),
            DeepCheckPlan {
                version_flag: Some("--version"),
                check_nuclei_templates: false,
                check_zap_runtime: true,
            }
        );

        let mut no_version = tool_spec("fixture");
        no_version.version_flag = None;
        assert_eq!(
            deep_check_plan(&no_version, true, true),
            DeepCheckPlan {
                version_flag: None,
                check_nuclei_templates: false,
                check_zap_runtime: false,
            }
        );
    }

    #[test]
    fn zap_version_extraction_ignores_launcher_and_java_versions() {
        let output = "Found Java version 21.0.11\nAvailable memory: 32000 MB\n2.17.0\n";
        assert_eq!(standalone_zap_version(output).as_deref(), Some("2.17.0"));
        assert_eq!(standalone_zap_version("2.17.0\n2.16.0\n"), None);
    }

    #[cfg(unix)]
    #[test]
    fn zap_runtime_check_requires_every_addon_and_both_report_templates() {
        let _environment =
            crate::TEST_ENVIRONMENT_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let complete = zap_runtime_fixture(true, true);
        let notes = with_path(complete.path(), check_zap_runtime);
        assert_eq!(
            notes,
            [DeepNote::Info(
                "Required application DAST add-ons and report templates are installed".to_string()
            )]
        );

        let wrong_extension = zap_runtime_fixture(true, true);
        let plugin = wrong_extension.path().join("plugin");
        std::fs::rename(
            plugin.join("authhelper-fixture.zap"),
            plugin.join("authhelper-fixture.txt"),
        )
        .expect("replace authhelper extension");
        let notes = with_path(wrong_extension.path(), check_zap_runtime);
        assert!(matches!(
            notes.as_slice(),
            [DeepNote::Warn(message)] if message.contains("missing required add-ons: authhelper-")
        ));

        let one_template = zap_runtime_fixture(true, false);
        let notes = with_path(one_template.path(), check_zap_runtime);
        assert_eq!(
            notes,
            [DeepNote::Warn(
                "ZAP runtime is missing the required auth-report-json or traditional-json-plus template"
                    .to_string()
            )]
        );
    }

    #[cfg(unix)]
    #[test]
    fn zap_runtime_check_reports_an_unresolved_launcher() {
        let _environment =
            crate::TEST_ENVIRONMENT_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let empty = tempfile::tempdir().expect("empty path");
        let notes = with_path(empty.path(), check_zap_runtime);
        assert_eq!(notes, [DeepNote::Warn("Cannot resolve the ZAP executable".to_string())]);
    }

    #[test]
    fn zip_entry_probe_distinguishes_present_missing_and_invalid_archives() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let archive_path = directory.path().join("fixture.zap");
        let file = std::fs::File::create(&archive_path).expect("create archive");
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("present/template.yaml", zip::write::SimpleFileOptions::default())
            .expect("start entry");
        archive.write_all(b"fixture").expect("write entry");
        archive.finish().expect("finish archive");

        assert!(zip_contains(&archive_path, "present/template.yaml"));
        assert!(!zip_contains(&archive_path, "missing/template.yaml"));
        assert!(!zip_contains(&directory.path().join("missing.zap"), "anything"));
        let invalid = directory.path().join("invalid.zap");
        std::fs::write(&invalid, b"not a zip").expect("write invalid archive");
        assert!(!zip_contains(&invalid, "anything"));
    }

    #[test]
    fn doctor_summary_counts_asymmetric_result_states() {
        let results = vec![
            tool_result(true, Some("3.2.0"), Some(true), vec![DeepNote::Info("fresh".into())]),
            tool_result(true, Some("2.9.0"), Some(false), vec![DeepNote::Warn("old".into())]),
            tool_result(true, None, None, Vec::new()),
            tool_result(false, None, None, Vec::new()),
        ];
        let summary = DoctorSummary::from_results(&results);
        assert_eq!(
            summary,
            DoctorSummary {
                installed: 3,
                missing: 1,
                version_pass: 1,
                version_fail: 1,
                warnings: 1,
            }
        );
        assert_eq!(summary.total(), 4);
        assert_eq!(summary.version_checked(), 2);
        assert_eq!(DoctorSummary::from_results(&[]), DoctorSummary::default());
    }

    #[test]
    fn tool_result_rendering_covers_installed_missing_and_deep_states() {
        let passed = render_tool_result(
            &tool_result(
                true,
                Some("3.2.0\u{1b}"),
                Some(true),
                vec![DeepNote::Info("fresh\u{1b}".into())],
            ),
            true,
        );
        for expected in ["OK", "Fixture Tool", "3.2.0\\u{1b}", ">= 3.0.0", "fresh\\u{1b}"] {
            assert!(passed.contains(expected), "deep pass omitted {expected:?}: {passed:?}");
        }
        assert!(passed.contains("/opt/fixture\\u{1b}"));

        let failed =
            render_tool_result(&tool_result(true, Some("2.9.0"), Some(false), Vec::new()), true);
        assert!(failed.contains("FAIL"));
        assert!(failed.contains("need >= 3.0.0"));

        let unknown = render_tool_result(&tool_result(true, None, None, Vec::new()), true);
        assert!(unknown.contains("OK"));
        assert!(unknown.contains('-'));

        let missing_basic = render_tool_result(&tool_result(false, None, None, Vec::new()), false);
        assert!(missing_basic.contains("--"));
        assert!(!missing_basic.contains("hint"));

        let missing_deep = render_tool_result(
            &tool_result(false, None, None, vec![DeepNote::Warn("missing detail".into())]),
            true,
        );
        assert!(missing_deep.contains("hint"));
        assert!(missing_deep.contains("Install the fixture tool"));
        assert!(missing_deep.contains("WARN"));

        let mut exact = tool_result(true, Some("3.0.0"), Some(true), Vec::new());
        exact.exact_version = true;
        let rendered = render_tool_result(&exact, true);
        assert!(rendered.contains("= 3.0.0"));
        assert!(!rendered.contains(">= 3.0.0"));
    }

    #[test]
    fn doctor_summary_rendering_pins_all_optional_sections() {
        let summary = DoctorSummary {
            installed: 3,
            missing: 1,
            version_pass: 1,
            version_fail: 1,
            warnings: 2,
        };
        let basic = render_doctor_summary(&summary, false);
        assert!(basic.contains("3/4 tools installed"));
        assert!(basic.contains("install instructions"));
        assert!(!basic.contains("version checks"));

        let deep = render_doctor_summary(&summary, true);
        for expected in [
            "3/4 tools installed",
            "1/2 version checks passed",
            "1 version(s) below minimum",
            "2 warning(s)",
            "install instructions",
        ] {
            assert!(deep.contains(expected), "doctor summary omitted {expected:?}: {deep:?}");
        }

        let zero = render_doctor_summary(&DoctorSummary::default(), true);
        assert!(zero.contains("0/0 tools installed"));
        assert!(!zero.contains("version checks"));
        assert!(!zero.contains("below minimum"));
        assert!(!zero.contains("warning(s)"));
        assert!(!zero.contains("install instructions"));
    }

    #[test]
    fn test_tool_availability_checks_real_path_state() {
        assert!(is_tool_available("sh"));
        assert!(!is_tool_available("scorchkit-tool-that-does-not-exist-6f298d8d"));
    }

    #[test]
    fn tool_path_resolution_returns_the_real_executable_and_rejects_missing_tools() {
        let shell = which_path("sh").expect("the supported host must provide sh");
        let shell_path = std::path::Path::new(&shell);
        assert!(shell_path.is_absolute(), "tool path was not absolute: {shell}");
        assert!(shell_path.is_file(), "tool path was not a file: {shell}");
        assert_eq!(which_path("scorchkit-tool-that-does-not-exist-6f298d8d"), None);
    }

    #[test]
    fn version_probe_observes_tool_output_and_execution_failure() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("version-probe runtime");
        let _environment =
            crate::TEST_ENVIRONMENT_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        runtime.block_on(async {
            assert_eq!(get_tool_version("printf", "7.8.9").await.as_deref(), Some("7.8.9"));
            assert_eq!(
                get_tool_version("printf", "fixture version 7.8.9").await.as_deref(),
                Some("7.8.9")
            );
            assert_eq!(
                get_tool_version("scorchkit-tool-that-does-not-exist-6f298d8d", "--version").await,
                None
            );
        });
    }

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
