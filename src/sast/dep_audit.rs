//! Built-in dependency auditor for structural lockfile analysis.
//!
//! Parses lockfiles (`Cargo.lock`, `package-lock.json`, `requirements.txt`,
//! `go.sum`) and detects dependency health issues without requiring external
//! tools or advisory databases. Complements OSV-Scanner and Grype with
//! lightweight, portable structural checks.

use std::collections::HashMap;
use std::path::Path;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

/// Known lockfile names and their parser identifiers.
const LOCKFILES: &[(&str, &str)] = &[
    ("Cargo.lock", "cargo"),
    ("package-lock.json", "npm"),
    ("requirements.txt", "pip"),
    ("go.sum", "go"),
];

/// Historically compromised or sabotaged packages.
///
/// Each entry is (ecosystem, `package_name`, description).
const RISKY_PACKAGES: &[(&str, &str, &str)] = &[
    ("npm", "event-stream", "Compromised in 2018 — cryptocurrency wallet theft via flatmap-stream"),
    ("npm", "ua-parser-js", "Compromised in 2021 — cryptominer and password stealer injection"),
    ("npm", "coa", "Compromised in 2021 — malicious code injected via hijacked maintainer account"),
    ("npm", "rc", "Compromised in 2021 — malicious code injected alongside coa"),
    ("npm", "colors", "Sabotaged in 2022 — infinite loop added by maintainer in protest"),
    ("npm", "faker", "Sabotaged in 2022 — all functionality removed by maintainer"),
    (
        "npm",
        "node-ipc",
        "Sabotaged in 2022 — protestware that overwrites files on Russian/Belarusian IPs",
    ),
    ("npm", "peacenotwar", "Protestware distributed via node-ipc dependency"),
    ("pip", "ctx", "Typosquat 2022 — stole environment variables"),
    ("pip", "colourama", "Typosquat of colorama — credential stealer"),
    ("pip", "python-dateutil", "Typosquat of python-dateutil — credential stealer"),
];

/// An intermediate dependency parsed from a lockfile.
struct ParsedDependency {
    name: String,
    version: String,
    source: String,
    ecosystem: String,
    pinned: bool,
}

/// Built-in dependency auditor — structural lockfile analysis.
#[derive(Debug)]
pub struct DepAuditModule;

#[async_trait]
impl CodeModule for DepAuditModule {
    fn name(&self) -> &'static str {
        "Dependency Auditor"
    }
    fn id(&self) -> &'static str {
        "dep-audit"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sca
    }
    fn description(&self) -> &'static str {
        "Built-in dependency health checks: duplicates, unpinned deps, known-risky packages"
    }
    fn requires_external_tool(&self) -> bool {
        false
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let mut all_deps: Vec<ParsedDependency> = Vec::new();

        for &(filename, ecosystem) in LOCKFILES {
            let lockfile_path = ctx.path.join(filename);
            if lockfile_path.exists() {
                let deps = parse_lockfile(&lockfile_path, ecosystem);
                all_deps.extend(deps);
            }
        }

        if all_deps.is_empty() {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        findings.extend(detect_duplicate_versions(&all_deps));
        findings.extend(detect_unpinned_deps(&all_deps));
        findings.extend(detect_risky_packages(&all_deps));

        Ok(findings)
    }
}

/// Parse a lockfile into a list of dependencies.
///
/// Dispatches to the appropriate parser based on ecosystem identifier.
/// Returns an empty list on any parse error (graceful degradation).
fn parse_lockfile(path: &Path, ecosystem: &str) -> Vec<ParsedDependency> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let source = path.display().to_string();

    match ecosystem {
        "cargo" => parse_cargo_lock(&content, &source),
        "npm" => parse_package_lock_json(&content, &source),
        "pip" => parse_requirements_txt(&content, &source),
        "go" => parse_go_sum(&content, &source),
        _ => Vec::new(),
    }
}

/// Parse `Cargo.lock` TOML format.
///
/// Extracts `[[package]]` entries with `name` and `version` fields.
fn parse_cargo_lock(content: &str, source: &str) -> Vec<ParsedDependency> {
    let Ok(doc) = content.parse::<toml::Value>() else {
        return Vec::new();
    };

    let Some(packages) = doc.get("package").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?.to_string();
            let version = pkg.get("version")?.as_str()?.to_string();
            Some(ParsedDependency {
                name,
                version,
                source: source.to_string(),
                ecosystem: "cargo".to_string(),
                pinned: true, // Cargo.lock always pins exact versions
            })
        })
        .collect()
}

/// Parse `package-lock.json` npm lockfile.
///
/// Supports both v2/v3 (`packages` map) and v1 (`dependencies` map) formats.
fn parse_package_lock_json(content: &str, source: &str) -> Vec<ParsedDependency> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };

    // Try v2/v3 format first (packages map)
    if let Some(packages) = root.get("packages").and_then(|v| v.as_object()) {
        return packages
            .iter()
            .filter(|(key, _)| !key.is_empty()) // Skip root "" entry
            .filter_map(|(key, val)| {
                let name = key.strip_prefix("node_modules/").unwrap_or(key);
                let version = val.get("version")?.as_str()?.to_string();
                Some(ParsedDependency {
                    name: name.to_string(),
                    version,
                    source: source.to_string(),
                    ecosystem: "npm".to_string(),
                    pinned: true, // package-lock.json pins exact versions
                })
            })
            .collect();
    }

    // Fall back to v1 format (dependencies map)
    let Some(deps) = root.get("dependencies").and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    deps.iter()
        .filter_map(|(name, val)| {
            let version = val.get("version")?.as_str()?.to_string();
            Some(ParsedDependency {
                name: name.clone(),
                version,
                source: source.to_string(),
                ecosystem: "npm".to_string(),
                pinned: true,
            })
        })
        .collect()
}

/// Parse `requirements.txt` pip format.
///
/// Handles `pkg==version` (pinned), `pkg>=version` (unpinned),
/// `pkg~=version` (compatible), and bare `pkg` (fully unpinned).
/// Skips comments (`#`) and blank lines.
fn parse_requirements_txt(content: &str, source: &str) -> Vec<ParsedDependency> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('-'))
        .filter_map(|line| {
            // Strip inline comments
            let line = line.split('#').next().unwrap_or(line).trim();
            if line.is_empty() {
                return None;
            }

            // Try to split on version specifiers
            let (name, version, pinned) = if let Some((n, v)) = line.split_once("==") {
                (n.trim(), v.trim().to_string(), true)
            } else if let Some((n, v)) = line.split_once(">=") {
                (n.trim(), format!(">={v}"), false)
            } else if let Some((n, v)) = line.split_once("~=") {
                (n.trim(), format!("~={v}"), false)
            } else if let Some((n, v)) = line.split_once("<=") {
                (n.trim(), format!("<={v}"), false)
            } else if let Some((n, v)) = line.split_once('>') {
                (n.trim(), format!(">{v}"), false)
            } else if let Some((n, v)) = line.split_once('<') {
                (n.trim(), format!("<{v}"), false)
            } else if let Some((n, v)) = line.split_once("!=") {
                (n.trim(), format!("!={v}"), false)
            } else {
                // Bare package name — no version at all
                (line, String::new(), false)
            };

            if name.is_empty() {
                return None;
            }

            Some(ParsedDependency {
                name: name.to_string(),
                version,
                source: source.to_string(),
                ecosystem: "pip".to_string(),
                pinned,
            })
        })
        .collect()
}

/// Parse `go.sum` checksum database format.
///
/// Each line is `module version h1:hash`. Extracts unique module+version pairs
/// (go.sum often has duplicate lines for `/go.mod` variants).
fn parse_go_sum(content: &str, source: &str) -> Vec<ParsedDependency> {
    let mut seen: HashMap<(String, String), bool> = HashMap::new();

    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let module = parts.next()?;
            let version_raw = parts.next()?;

            // Strip /go.mod suffix from version if present
            let version = version_raw.strip_suffix("/go.mod").unwrap_or(version_raw);

            let key = (module.to_string(), version.to_string());
            if seen.contains_key(&key) {
                return None;
            }
            seen.insert(key, true);

            Some(ParsedDependency {
                name: module.to_string(),
                version: version.to_string(),
                source: source.to_string(),
                ecosystem: "go".to_string(),
                pinned: true, // go.sum always pins exact versions
            })
        })
        .collect()
}

/// Detect packages with multiple different versions installed.
///
/// Multiple versions of the same package can indicate supply chain risk,
/// dependency confusion, or unnecessary bloat.
fn detect_duplicate_versions(deps: &[ParsedDependency]) -> Vec<Finding> {
    let mut by_name: HashMap<(&str, &str), Vec<&str>> = HashMap::new();
    for dep in deps {
        by_name.entry((&dep.ecosystem, &dep.name)).or_default().push(&dep.version);
    }

    by_name
        .iter()
        .filter(|(_, versions)| {
            let mut unique: Vec<&str> = (*versions).clone();
            unique.sort_unstable();
            unique.dedup();
            unique.len() > 1
        })
        .map(|((ecosystem, name), versions)| {
            let mut unique: Vec<&str> = versions.clone();
            unique.sort_unstable();
            unique.dedup();
            let source = deps
                .iter()
                .find(|d| d.name == *name && d.ecosystem == *ecosystem)
                .map_or("unknown", |d| d.source.as_str());

            Finding::new(
                "dep-audit",
                Severity::Medium,
                format!("Duplicate versions of {name}"),
                format!(
                    "{name} has {} different versions installed: {}",
                    unique.len(),
                    unique.join(", ")
                ),
                source,
            )
            .with_evidence(format!("Ecosystem: {ecosystem} | Versions: {}", unique.join(", ")))
            .with_remediation(format!(
                "Consolidate {name} to a single version to reduce supply chain attack surface."
            ))
            .with_owasp("A06:2021 Vulnerable and Outdated Components")
            .with_cwe(1104)
            .with_confidence(0.7)
        })
        .collect()
}

/// Detect unpinned dependencies in requirements.txt.
///
/// Unpinned dependencies (`>=`, `~=`, or bare package names) can lead to
/// non-reproducible builds and accidental inclusion of compromised versions.
fn detect_unpinned_deps(deps: &[ParsedDependency]) -> Vec<Finding> {
    deps.iter()
        .filter(|dep| !dep.pinned)
        .map(|dep| {
            let version_info = if dep.version.is_empty() {
                "no version specified".to_string()
            } else {
                format!("version range: {}", dep.version)
            };

            Finding::new(
                "dep-audit",
                Severity::Medium,
                format!("Unpinned dependency: {}", dep.name),
                format!(
                    "{} is not pinned to an exact version ({version_info}). \
                     This can lead to non-reproducible builds.",
                    dep.name
                ),
                &dep.source,
            )
            .with_evidence(format!(
                "Ecosystem: {} | Package: {} | {}",
                dep.ecosystem, dep.name, version_info
            ))
            .with_remediation(format!(
                "Pin {} to an exact version (e.g., {}==<version>) for reproducible builds.",
                dep.name, dep.name
            ))
            .with_owasp("A08:2021 Software and Data Integrity Failures")
            .with_cwe(829)
            .with_confidence(0.8)
        })
        .collect()
}

/// Detect known-risky or historically compromised packages.
///
/// Checks against a curated list of packages that were compromised,
/// sabotaged, or identified as typosquats.
fn detect_risky_packages(deps: &[ParsedDependency]) -> Vec<Finding> {
    deps.iter()
        .filter_map(|dep| {
            let risky = RISKY_PACKAGES.iter().find(|(eco, name, _)| {
                *eco == dep.ecosystem && dep.name.eq_ignore_ascii_case(name)
            })?;

            Some(
                Finding::new(
                    "dep-audit",
                    Severity::High,
                    format!("Known-risky package: {}", dep.name),
                    format!("{} ({}) is a known-risky package: {}", dep.name, dep.version, risky.2),
                    &dep.source,
                )
                .with_evidence(format!(
                    "Ecosystem: {} | Package: {}@{} | Risk: {}",
                    dep.ecosystem, dep.name, dep.version, risky.2
                ))
                .with_remediation(format!(
                    "Remove or replace {} with a trusted alternative. \
                     Verify the package has not been compromised in your installed version.",
                    dep.name
                ))
                .with_owasp("A08:2021 Software and Data Integrity Failures")
                .with_cwe(506)
                .with_confidence(0.85),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify `Cargo.lock` TOML parsing extracts package name and version
    /// from `[[package]]` entries.
    #[test]
    fn test_parse_cargo_lock() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.36.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "scorchkit"
version = "1.0.0"
"#;
        let deps = parse_cargo_lock(content, "Cargo.lock");
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.197");
        assert_eq!(deps[1].name, "tokio");
        assert!(deps[0].pinned);
    }

    /// Verify `package-lock.json` v2/v3 format parsing extracts
    /// package names (stripping `node_modules/` prefix) and versions.
    #[test]
    fn test_parse_package_lock_json() {
        let content = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/lodash": {"version": "4.17.21"}
            }
        }"#;
        let deps = parse_package_lock_json(content, "package-lock.json");
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "express");
        assert_eq!(deps[0].version, "4.18.2");
        assert_eq!(deps[1].name, "lodash");
    }

    /// Verify `requirements.txt` parsing handles pinned (`==`),
    /// unpinned (`>=`, `~=`), and bare package names correctly.
    #[test]
    fn test_parse_requirements_txt() {
        let content = "# Dependencies\n\
                        django==4.2.1\n\
                        requests>=2.28.0\n\
                        flask~=2.3\n\
                        numpy\n\
                        # This is a comment\n\
                        \n\
                        celery==5.3.1  # task queue\n";
        let deps = parse_requirements_txt(content, "requirements.txt");
        assert_eq!(deps.len(), 5);

        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[0].version, "4.2.1");
        assert!(deps[0].pinned);

        assert_eq!(deps[1].name, "requests");
        assert_eq!(deps[1].version, ">=2.28.0");
        assert!(!deps[1].pinned);

        assert_eq!(deps[2].name, "flask");
        assert!(!deps[2].pinned);

        assert_eq!(deps[3].name, "numpy");
        assert!(deps[3].version.is_empty());
        assert!(!deps[3].pinned);

        assert_eq!(deps[4].name, "celery");
        assert!(deps[4].pinned);
    }

    /// Verify `go.sum` parsing extracts module names and versions,
    /// deduplicating `/go.mod` variant entries.
    #[test]
    fn test_parse_go_sum() {
        let content = "golang.org/x/net v0.15.0 h1:abc123=\n\
                        golang.org/x/net v0.15.0/go.mod h1:def456=\n\
                        golang.org/x/text v0.13.0 h1:ghi789=\n\
                        github.com/gin-gonic/gin v1.9.1 h1:jkl012=\n";
        let deps = parse_go_sum(content, "go.sum");
        assert_eq!(deps.len(), 3); // net deduplicated
        assert_eq!(deps[0].name, "golang.org/x/net");
        assert_eq!(deps[0].version, "v0.15.0");
        assert_eq!(deps[1].name, "golang.org/x/text");
        assert_eq!(deps[2].name, "github.com/gin-gonic/gin");
    }

    /// Verify duplicate version detection flags packages with
    /// multiple different versions.
    #[test]
    fn test_detect_duplicate_versions() {
        let deps = vec![
            ParsedDependency {
                name: "serde".to_string(),
                version: "1.0.197".to_string(),
                source: "Cargo.lock".to_string(),
                ecosystem: "cargo".to_string(),
                pinned: true,
            },
            ParsedDependency {
                name: "serde".to_string(),
                version: "1.0.180".to_string(),
                source: "Cargo.lock".to_string(),
                ecosystem: "cargo".to_string(),
                pinned: true,
            },
            ParsedDependency {
                name: "tokio".to_string(),
                version: "1.36.0".to_string(),
                source: "Cargo.lock".to_string(),
                ecosystem: "cargo".to_string(),
                pinned: true,
            },
        ];

        let findings = detect_duplicate_versions(&deps);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("serde"));
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0]
            .evidence
            .as_ref()
            .is_some_and(|e| e.contains("1.0.180") && e.contains("1.0.197")));
    }

    /// Verify unpinned dependency detection flags `>=`, `~=`, and
    /// bare package names in requirements.txt.
    #[test]
    fn test_detect_unpinned_deps() {
        let deps = vec![
            ParsedDependency {
                name: "django".to_string(),
                version: "4.2.1".to_string(),
                source: "requirements.txt".to_string(),
                ecosystem: "pip".to_string(),
                pinned: true,
            },
            ParsedDependency {
                name: "requests".to_string(),
                version: ">=2.28.0".to_string(),
                source: "requirements.txt".to_string(),
                ecosystem: "pip".to_string(),
                pinned: false,
            },
            ParsedDependency {
                name: "numpy".to_string(),
                version: String::new(),
                source: "requirements.txt".to_string(),
                ecosystem: "pip".to_string(),
                pinned: false,
            },
        ];

        let findings = detect_unpinned_deps(&deps);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("requests"));
        assert!(findings[1].title.contains("numpy"));
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].cwe_id, Some(829));
    }

    /// Verify known-risky package detection flags historically
    /// compromised packages by ecosystem and name.
    #[test]
    fn test_detect_risky_packages() {
        let deps = vec![
            ParsedDependency {
                name: "express".to_string(),
                version: "4.18.2".to_string(),
                source: "package-lock.json".to_string(),
                ecosystem: "npm".to_string(),
                pinned: true,
            },
            ParsedDependency {
                name: "event-stream".to_string(),
                version: "3.3.6".to_string(),
                source: "package-lock.json".to_string(),
                ecosystem: "npm".to_string(),
                pinned: true,
            },
            ParsedDependency {
                name: "colors".to_string(),
                version: "1.4.0".to_string(),
                source: "package-lock.json".to_string(),
                ecosystem: "npm".to_string(),
                pinned: true,
            },
        ];

        let findings = detect_risky_packages(&deps);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("event-stream"));
        assert!(findings[1].title.contains("colors"));
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe_id, Some(506));
    }

    /// Verify all parsers handle empty and invalid input gracefully.
    #[test]
    fn test_empty_and_invalid_input() {
        // Empty input
        assert!(parse_cargo_lock("", "test").is_empty());
        assert!(parse_package_lock_json("", "test").is_empty());
        assert!(parse_requirements_txt("", "test").is_empty());
        assert!(parse_go_sum("", "test").is_empty());

        // Invalid input
        assert!(parse_cargo_lock("not toml {{{", "test").is_empty());
        assert!(parse_package_lock_json("not json", "test").is_empty());

        // Comments-only requirements.txt
        assert!(parse_requirements_txt("# just a comment\n\n", "test").is_empty());

        // No duplicates in single-version list
        let single = vec![ParsedDependency {
            name: "serde".to_string(),
            version: "1.0.197".to_string(),
            source: "test".to_string(),
            ecosystem: "cargo".to_string(),
            pinned: true,
        }];
        assert!(detect_duplicate_versions(&single).is_empty());

        // No findings for pinned deps
        assert!(detect_unpinned_deps(&single).is_empty());

        // No findings for safe packages
        assert!(detect_risky_packages(&single).is_empty());
    }
}
