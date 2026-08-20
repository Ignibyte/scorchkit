//! Strict offline adapters for application supply-chain tools.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess::ToolInvocation;
use scorchkit_core::{
    AdvisoryIdentity, DependencyEvidenceKind, PackageIdentity, SupplyChainObservation,
    SupplyChainTarget, SupplyChainTargetKind,
};

use super::schema::normalize_supplied_purl;

const TOOL_TIMEOUT: Duration = Duration::from_mins(5);

/// Typed result from one strict vulnerability report parser.
#[derive(Debug, Default)]
pub struct SupplyChainToolReport {
    pub findings: Vec<Finding>,
    pub observations: Vec<SupplyChainObservation>,
}

pub(super) fn version_output_matches(stdout: &str, stderr: &str, expected_version: &str) -> bool {
    stdout
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .chain(stderr.split(|character: char| !character.is_ascii_digit() && character != '.'))
        .any(|candidate| candidate == expected_version)
}

/// Minimal owned Syft configuration. No user/project config is discovered.
#[must_use]
pub fn syft_config() -> String {
    "log:\n  quiet: true\ncheck-for-app-update: false\nenrich: []\n".to_string()
}

/// Minimal owned OSV configuration. All behavior is fixed on the command line.
#[must_use]
pub fn osv_config() -> String {
    "{}\n".to_string()
}

/// Owned Grype configuration bound to one immutable provider snapshot.
pub fn grype_config(cache_directory: &Path, maximum_age_seconds: u64) -> Result<String> {
    serde_yaml::to_string(&serde_json::json!({
        "check-for-app-update": false,
        "fail-on-severity": "",
        "db": {
            "cache-dir": cache_directory,
            "auto-update": false,
            "validate-by-hash-on-start": true,
            "validate-age": true,
            "max-allowed-built-age": format!("{maximum_age_seconds}s"),
            "require-update-check": false
        }
    }))
    .map_err(|error| ScorchError::Config(format!("failed to render Grype config: {error}")))
}

/// Owned Trivy configuration. Network- and update-related behavior is repeated on the CLI.
pub fn trivy_config(cache_directory: &Path) -> Result<String> {
    serde_yaml::to_string(&serde_json::json!({
        "cache-dir": cache_directory,
        "disable-telemetry": true,
        "skip-version-check": true,
        "offline-scan": true,
        "scanners": ["vuln"]
    }))
    .map_err(|error| ScorchError::Config(format!("failed to render Trivy config: {error}")))
}

/// Build the one allowed Syft producer invocation for an explicit local target.
pub fn syft_invocation(
    program: &str,
    target: &SupplyChainTarget,
    config_path: &Path,
    workspace: &Path,
    output_limit_bytes: usize,
) -> Result<ToolInvocation> {
    let source = match target.kind {
        SupplyChainTargetKind::SourceDirectory | SupplyChainTargetKind::DirectoryArtifact => {
            format!("dir:{}", target.canonical_path.display())
        }
        SupplyChainTargetKind::FileArtifact => {
            format!("file:{}", target.canonical_path.display())
        }
        SupplyChainTargetKind::OciArchive => {
            format!("oci-archive:{}", target.canonical_path.display())
        }
        SupplyChainTargetKind::OciLayout => {
            format!("oci-dir:{}", target.canonical_path.display())
        }
        SupplyChainTargetKind::CycloneDxSbom => {
            return Err(ScorchError::Config(
                "Syft must not recatalog an existing CycloneDX SBOM".to_string(),
            ));
        }
    };
    let invocation = ToolInvocation::strict_owned(
        program,
        vec![
            "--config".to_string(),
            config_path.display().to_string(),
            "--quiet".to_string(),
            "scan".to_string(),
            source,
            "--output".to_string(),
            "cyclonedx-json@1.6".to_string(),
        ],
        TOOL_TIMEOUT,
    );
    Ok(isolated_invocation(invocation, workspace, output_limit_bytes))
}

/// Build an OSV v2 source invocation for only the explicitly discovered lockfiles.
// JUSTIFICATION: The invocation contract keeps each policy-owned path, limit, and executable
// explicit so callers cannot accidentally merge distinct trust boundaries into one option bag.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn osv_invocation(
    program: &str,
    lockfiles: &[PathBuf],
    config_path: &Path,
    database_cache: &Path,
    workspace: &Path,
    output_limit_bytes: usize,
) -> ToolInvocation {
    let mut args = vec![
        "scan".to_string(),
        "source".to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--verbosity".to_string(),
        "error".to_string(),
        "--offline".to_string(),
        "--offline-vulnerabilities".to_string(),
        "--no-resolve".to_string(),
        "--all-packages".to_string(),
        "--config".to_string(),
        config_path.display().to_string(),
    ];
    for lockfile in lockfiles {
        args.push("--lockfile".to_string());
        args.push(lockfile.display().to_string());
    }
    let invocation = ToolInvocation::accepting_owned(program, args, TOOL_TIMEOUT, &[0, 1])
        .with_environment(
            "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY",
            database_cache.display().to_string(),
        );
    isolated_invocation(invocation, workspace, output_limit_bytes)
}

/// Build a Grype invocation that consumes the exact verified `CycloneDX` document.
// JUSTIFICATION: The invocation contract keeps each policy-owned path, limit, and executable
// explicit so callers cannot accidentally merge distinct trust boundaries into one option bag.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn grype_invocation(
    program: &str,
    sbom_path: &Path,
    config_path: &Path,
    workspace: &Path,
    output_limit_bytes: usize,
) -> ToolInvocation {
    let invocation = ToolInvocation::strict_owned(
        program,
        vec![
            format!("sbom:{}", sbom_path.display()),
            "--config".to_string(),
            config_path.display().to_string(),
            "--output".to_string(),
            "json".to_string(),
            "--quiet".to_string(),
        ],
        TOOL_TIMEOUT,
    );
    isolated_invocation(invocation, workspace, output_limit_bytes)
}

/// Build a native Trivy SBOM invocation with every update/network source disabled.
// JUSTIFICATION: The invocation contract keeps each policy-owned path, limit, and executable
// explicit so callers cannot accidentally merge distinct trust boundaries into one option bag.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn trivy_invocation(
    program: &str,
    sbom_path: &Path,
    config_path: &Path,
    cache_path: &Path,
    ignore_file: &Path,
    workspace: &Path,
    output_limit_bytes: usize,
) -> ToolInvocation {
    let invocation = ToolInvocation::strict_owned(
        program,
        vec![
            "--config".to_string(),
            config_path.display().to_string(),
            "--cache-dir".to_string(),
            cache_path.display().to_string(),
            "--disable-telemetry".to_string(),
            "--skip-version-check".to_string(),
            "--no-progress".to_string(),
            "sbom".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--scanners".to_string(),
            "vuln".to_string(),
            "--ignorefile".to_string(),
            ignore_file.display().to_string(),
            "--skip-db-update".to_string(),
            "--skip-java-db-update".to_string(),
            "--skip-vex-repo-update".to_string(),
            "--offline-scan".to_string(),
            "--exit-code".to_string(),
            "0".to_string(),
            sbom_path.display().to_string(),
        ],
        TOOL_TIMEOUT,
    );
    isolated_invocation(invocation, workspace, output_limit_bytes)
}

fn isolated_invocation(
    invocation: ToolInvocation,
    workspace: &Path,
    output_limit_bytes: usize,
) -> ToolInvocation {
    invocation
        .with_clean_environment()
        .with_environment("HOME", workspace.join("home").display().to_string())
        .with_environment("XDG_CACHE_HOME", workspace.join("cache").display().to_string())
        .with_environment("XDG_CONFIG_HOME", workspace.join("config").display().to_string())
        .with_environment("TMPDIR", workspace.join("tmp").display().to_string())
        .with_working_directory(workspace)
        .with_output_limit(output_limit_bytes)
}

/// Parse an OSV v2 JSON report, preserving source-dependency identity and aliases.
// JUSTIFICATION: Evidence identity, provider provenance, and target revision are independent
// integrity fields and remain explicit at the parser boundary.
#[allow(clippy::too_many_arguments)]
pub fn parse_osv_report(
    bytes: &[u8],
    raw_evidence_path: &Path,
    target_revision: &str,
    tool_version: &str,
    provider_snapshot_id: &str,
) -> Result<SupplyChainToolReport> {
    let root = parse_report_root("osv-scanner", bytes)?;
    let results = required_array("osv-scanner", &root, "results")?;
    let mut report = SupplyChainToolReport::default();

    for result in results {
        let source_location = result
            .get("source")
            .and_then(|source| source.get("path"))
            .and_then(Value::as_str)
            .map(str::to_string);
        for package_entry in required_array("osv-scanner", result, "packages")? {
            let package = required_object("osv-scanner", package_entry, "package")?;
            let name = required_string("osv-scanner", package, "name")?;
            let installed_version = required_string("osv-scanner", package, "version")?;
            let package_type = required_string("osv-scanner", package, "ecosystem")?;
            for vulnerability in required_array("osv-scanner", package_entry, "vulnerabilities")? {
                let advisory = advisory_from_osv(vulnerability)?;
                let severity = severity_from_osv(vulnerability);
                let summary = vulnerability
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or(&advisory.primary_id);
                let affected = format!("{name}@{installed_version}");
                report.findings.push(
                    Finding::new(
                        "osv-scanner",
                        severity,
                        format!("{}: {summary}", advisory.primary_id),
                        format!("Vulnerable declared dependency {affected}: {summary}"),
                        &affected,
                    )
                    .with_evidence(format!("Package: {name} {installed_version} ({package_type})"))
                    .with_remediation(format!("Update {name} to a non-affected version."))
                    .with_owasp("A06:2021 Vulnerable and Outdated Components")
                    .with_cwe(1104)
                    .with_confidence(0.9),
                );
                report.observations.push(SupplyChainObservation {
                    tool: "osv-scanner".to_string(),
                    tool_version: tool_version.to_string(),
                    provider_snapshot_id: Some(provider_snapshot_id.to_string()),
                    target_revision: target_revision.to_string(),
                    package: PackageIdentity {
                        evidence_kind: DependencyEvidenceKind::DeclaredSourceDependency,
                        package_type: package_type.to_string(),
                        name: name.to_string(),
                        installed_version: installed_version.to_string(),
                        fixed_version: None,
                        purl: None,
                        invalid_purl: None,
                        source_location: source_location.clone(),
                        direct: None,
                    },
                    advisory,
                    severity,
                    data_source: Some("OSV offline database".to_string()),
                    raw_evidence_sha256: scorchkit_core::sha256_hex(bytes),
                    raw_evidence_path: raw_evidence_path.to_path_buf(),
                });
            }
        }
    }
    Ok(report)
}

/// Parse Grype JSON and require the expected descriptor before accepting an empty match set.
// JUSTIFICATION: Evidence identity, provider provenance, and target revision are independent
// integrity fields and remain explicit at the parser boundary.
#[allow(clippy::too_many_arguments)]
pub fn parse_grype_report(
    bytes: &[u8],
    raw_evidence_path: &Path,
    target_revision: &str,
    expected_tool_version: &str,
    provider_snapshot_id: &str,
) -> Result<SupplyChainToolReport> {
    let root = parse_report_root("grype", bytes)?;
    let descriptor = required_object("grype", &root, "descriptor")?;
    if required_string("grype", descriptor, "name")? != "grype"
        || required_string("grype", descriptor, "version")? != expected_tool_version
    {
        return Err(report_error("grype", "unexpected tool descriptor"));
    }
    let matches = required_array("grype", &root, "matches")?;
    let mut report = SupplyChainToolReport::default();
    for matched in matches {
        let vulnerability = required_object("grype", matched, "vulnerability")?;
        let artifact = required_object("grype", matched, "artifact")?;
        let advisory = advisory_from_grype(matched, vulnerability)?;
        let severity = map_severity(
            vulnerability.get("severity").and_then(Value::as_str).unwrap_or("unknown"),
        );
        let name = required_string("grype", artifact, "name")?;
        let installed_version = required_string("grype", artifact, "version")?;
        let package_type = required_string("grype", artifact, "type")?;
        let (purl, invalid_purl) = supplied_purl(artifact.get("purl").and_then(Value::as_str));
        let fixed_version = vulnerability
            .get("fix")
            .and_then(|fix| fix.get("versions"))
            .and_then(Value::as_array)
            .and_then(|versions| versions.iter().find_map(Value::as_str))
            .map(str::to_string);
        let description = vulnerability
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or(&advisory.primary_id);
        let affected = format!("{name}@{installed_version}");
        report.findings.push(
            Finding::new(
                "grype",
                severity,
                format!("{}: {affected}", advisory.primary_id),
                description,
                &affected,
            )
            .with_evidence(format!("Package: {name} {installed_version} ({package_type})"))
            .with_remediation(fixed_version.as_ref().map_or_else(
                || format!("No fixed version is currently reported for {name}."),
                |version| format!("Update {name} to {version}."),
            ))
            .with_owasp("A06:2021 Vulnerable and Outdated Components")
            .with_cwe(1104)
            .with_confidence(0.9),
        );
        report.observations.push(SupplyChainObservation {
            tool: "grype".to_string(),
            tool_version: expected_tool_version.to_string(),
            provider_snapshot_id: Some(provider_snapshot_id.to_string()),
            target_revision: target_revision.to_string(),
            package: PackageIdentity {
                evidence_kind: DependencyEvidenceKind::BuiltArtifactComponent,
                package_type: package_type.to_string(),
                name: name.to_string(),
                installed_version: installed_version.to_string(),
                fixed_version,
                purl,
                invalid_purl,
                source_location: artifact
                    .get("locations")
                    .and_then(Value::as_array)
                    .and_then(|locations| locations.first())
                    .and_then(|location| location.get("path"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                direct: None,
            },
            advisory,
            severity,
            data_source: vulnerability.get("namespace").and_then(Value::as_str).map(str::to_string),
            raw_evidence_sha256: scorchkit_core::sha256_hex(bytes),
            raw_evidence_path: raw_evidence_path.to_path_buf(),
        });
    }
    Ok(report)
}

/// Parse native Trivy JSON from its owned output artifact.
// JUSTIFICATION: Evidence identity, provider provenance, and target revision are independent
// integrity fields and remain explicit at the parser boundary.
#[allow(clippy::too_many_arguments)]
pub fn parse_trivy_report(
    bytes: &[u8],
    raw_evidence_path: &Path,
    target_revision: &str,
    tool_version: &str,
    provider_snapshot_id: &str,
) -> Result<SupplyChainToolReport> {
    let root = parse_report_root("trivy", bytes)?;
    if root.get("SchemaVersion").and_then(Value::as_u64).is_none() {
        return Err(report_error("trivy", "missing numeric SchemaVersion"));
    }
    let results = required_array("trivy", &root, "Results")?;
    let mut report = SupplyChainToolReport::default();
    for result in results {
        let target_name = required_string("trivy", result, "Target")?;
        let vulnerabilities = result.get("Vulnerabilities").map_or(Ok(&[][..]), |value| {
            value
                .as_array()
                .map(Vec::as_slice)
                .ok_or_else(|| report_error("trivy", "field 'Vulnerabilities' must be an array"))
        })?;
        for vulnerability in vulnerabilities {
            let advisory = AdvisoryIdentity {
                primary_id: required_string("trivy", vulnerability, "VulnerabilityID")?.to_string(),
                aliases: BTreeSet::new(),
            };
            let severity = map_severity(
                vulnerability.get("Severity").and_then(Value::as_str).unwrap_or("unknown"),
            );
            let name = required_string("trivy", vulnerability, "PkgName")?;
            let installed_version = required_string("trivy", vulnerability, "InstalledVersion")?;
            let fixed_version = vulnerability
                .get("FixedVersion")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let package_type = result.get("Class").and_then(Value::as_str).unwrap_or("unknown");
            let raw_purl = vulnerability
                .get("PkgIdentifier")
                .and_then(|identifier| identifier.get("PURL"))
                .and_then(Value::as_str);
            let (purl, invalid_purl) = supplied_purl(raw_purl);
            let title =
                vulnerability.get("Title").and_then(Value::as_str).unwrap_or(&advisory.primary_id);
            let affected = format!("{name}@{installed_version}");
            report.findings.push(
                Finding::new(
                    "trivy",
                    severity,
                    format!("{}: {title}", advisory.primary_id),
                    format!("Vulnerable package {affected} in {target_name}."),
                    &affected,
                )
                .with_evidence(format!("Package: {name} {installed_version} ({package_type})"))
                .with_remediation(fixed_version.as_ref().map_or_else(
                    || format!("No fixed version is currently reported for {name}."),
                    |version| format!("Update {name} to {version}."),
                ))
                .with_owasp("A06:2021 Vulnerable and Outdated Components")
                .with_cwe(1104)
                .with_confidence(0.9),
            );
            report.observations.push(SupplyChainObservation {
                tool: "trivy".to_string(),
                tool_version: tool_version.to_string(),
                provider_snapshot_id: Some(provider_snapshot_id.to_string()),
                target_revision: target_revision.to_string(),
                package: PackageIdentity {
                    evidence_kind: DependencyEvidenceKind::BuiltArtifactComponent,
                    package_type: package_type.to_string(),
                    name: name.to_string(),
                    installed_version: installed_version.to_string(),
                    fixed_version,
                    purl,
                    invalid_purl,
                    source_location: Some(target_name.to_string()),
                    direct: None,
                },
                advisory,
                severity,
                data_source: vulnerability
                    .get("DataSource")
                    .and_then(|source| source.get("Name"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                raw_evidence_sha256: scorchkit_core::sha256_hex(bytes),
                raw_evidence_path: raw_evidence_path.to_path_buf(),
            });
        }
    }
    Ok(report)
}

fn parse_report_root(tool: &str, bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() {
        return Err(report_error(tool, "empty output"));
    }
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|error| report_error(tool, format!("invalid JSON: {error}")))?;
    if !root.is_object() {
        return Err(report_error(tool, "top-level output must be an object"));
    }
    Ok(root)
}

fn required_array<'a>(tool: &str, parent: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    parent
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| report_error(tool, format!("missing array field '{field}'")))
}

fn required_object<'a>(tool: &str, parent: &'a Value, field: &str) -> Result<&'a Value> {
    parent
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| report_error(tool, format!("missing object field '{field}'")))
}

fn required_string<'a>(tool: &str, parent: &'a Value, field: &str) -> Result<&'a str> {
    parent
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| report_error(tool, format!("missing string field '{field}'")))
}

fn advisory_from_osv(value: &Value) -> Result<AdvisoryIdentity> {
    Ok(AdvisoryIdentity {
        primary_id: required_string("osv-scanner", value, "id")?.to_string(),
        aliases: value
            .get("aliases")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
    })
}

fn advisory_from_grype(matched: &Value, vulnerability: &Value) -> Result<AdvisoryIdentity> {
    let mut aliases = matched
        .get("relatedVulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|related| related.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if let Some(alias) = vulnerability.get("dataSource").and_then(Value::as_str) {
        if alias.starts_with("CVE-") || alias.starts_with("GHSA-") {
            aliases.insert(alias.to_string());
        }
    }
    Ok(AdvisoryIdentity {
        primary_id: required_string("grype", vulnerability, "id")?.to_string(),
        aliases,
    })
}

fn severity_from_osv(value: &Value) -> Severity {
    let severity = value
        .get("database_specific")
        .and_then(|database| database.get("severity"))
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("severity")
                .and_then(Value::as_array)
                .and_then(|severities| severities.first())
                .and_then(|severity| severity.get("rating"))
                .and_then(Value::as_str)
        })
        .unwrap_or("unknown");
    map_severity(severity)
}

fn map_severity(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "moderate" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn supplied_purl(value: Option<&str>) -> (Option<String>, Option<String>) {
    value.map_or((None, None), |raw| {
        normalize_supplied_purl(raw)
            .map_or_else(|_| (None, Some(raw.to_string())), |normalized| (Some(normalized), None))
    })
}

fn report_error(tool: &str, reason: impl Into<String>) -> ScorchError {
    ScorchError::ToolOutputParse { tool: tool.to_string(), reason: reason.into() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_tools::{EnvironmentPolicy, ExitPolicy};

    #[test]
    fn version_output_requires_one_exact_numeric_token() {
        assert!(version_output_matches("grype 0.116.1", "", "0.116.1"));
        assert!(version_output_matches("", "Version: 0.116.1", "0.116.1"));
        assert!(!version_output_matches("grype 0.116.10", "", "0.116.1"));
        assert!(!version_output_matches("grype development", "", "0.116.1"));
    }

    #[test]
    fn invocation_contracts_are_offline_isolated_and_exact() {
        let workspace = Path::new("/owned/workspace");
        let target = SupplyChainTarget {
            kind: SupplyChainTargetKind::SourceDirectory,
            canonical_path: PathBuf::from("/authorized/source"),
            revision: Some("revision".to_string()),
            sha256: None,
        };
        let syft =
            syft_invocation("/tools/syft", &target, Path::new("/owned/syft.yaml"), workspace, 1024)
                .expect("Syft invocation");
        assert_eq!(syft.environment_policy, EnvironmentPolicy::Clear);
        assert!(syft.args.contains(&"dir:/authorized/source".to_string()));
        assert!(syft.args.iter().any(|arg| arg == "cyclonedx-json@1.6"));

        let osv = osv_invocation(
            "/tools/osv-scanner",
            &[PathBuf::from("/authorized/source/Cargo.lock")],
            Path::new("/owned/osv.toml"),
            Path::new("/cache/osv"),
            workspace,
            1024,
        );
        assert_eq!(osv.exit_policy, ExitPolicy::AcceptedCodes(vec![0, 1]));
        assert!(osv.args.contains(&"--offline".to_string()));
        assert!(!osv.args.contains(&"--recursive".to_string()));

        let trivy = trivy_invocation(
            "/tools/trivy",
            Path::new("/owned/sbom.json"),
            Path::new("/owned/trivy.yaml"),
            Path::new("/cache/trivy"),
            Path::new("/owned/ignore"),
            workspace,
            1024,
        );
        for required in [
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-vex-repo-update",
            "--offline-scan",
            "--disable-telemetry",
        ] {
            assert!(trivy.args.contains(&required.to_string()));
        }
        assert!(!trivy.args.contains(&"--output".to_string()));
    }

    #[test]
    fn parsers_distinguish_valid_empty_from_empty_or_malformed() {
        let grype = br#"{"descriptor":{"name":"grype","version":"0.116.1"},"matches":[]}"#;
        assert!(parse_grype_report(
            grype,
            Path::new("grype.json"),
            "revision",
            "0.116.1",
            "snapshot"
        )
        .is_ok());
        assert!(parse_grype_report(
            b"",
            Path::new("grype.json"),
            "revision",
            "0.116.1",
            "snapshot"
        )
        .is_err());
        assert!(parse_grype_report(
            b"{}",
            Path::new("grype.json"),
            "revision",
            "0.116.1",
            "snapshot"
        )
        .is_err());

        let trivy = br#"{"SchemaVersion":2,"Results":[]}"#;
        assert!(parse_trivy_report(
            trivy,
            Path::new("trivy.json"),
            "revision",
            "0.74.0",
            "snapshot"
        )
        .is_ok());
    }

    #[test]
    fn owned_tool_configs_are_nonempty_and_preserve_every_offline_control() {
        assert_eq!(syft_config(), "log:\n  quiet: true\ncheck-for-app-update: false\nenrich: []\n");
        assert_eq!(osv_config(), "{}\n");

        let grype: serde_yaml::Value = serde_yaml::from_str(
            &grype_config(Path::new("/cache/grype"), 345).expect("render Grype config"),
        )
        .expect("parse Grype config");
        assert_eq!(grype["check-for-app-update"], false);
        assert_eq!(grype["fail-on-severity"], "");
        assert_eq!(grype["db"]["cache-dir"], "/cache/grype");
        assert_eq!(grype["db"]["auto-update"], false);
        assert_eq!(grype["db"]["validate-by-hash-on-start"], true);
        assert_eq!(grype["db"]["validate-age"], true);
        assert_eq!(grype["db"]["max-allowed-built-age"], "345s");
        assert_eq!(grype["db"]["require-update-check"], false);

        let trivy: serde_yaml::Value = serde_yaml::from_str(
            &trivy_config(Path::new("/cache/trivy")).expect("render Trivy config"),
        )
        .expect("parse Trivy config");
        assert_eq!(trivy["cache-dir"], "/cache/trivy");
        assert_eq!(trivy["disable-telemetry"], true);
        assert_eq!(trivy["skip-version-check"], true);
        assert_eq!(trivy["offline-scan"], true);
        assert_eq!(trivy["scanners"][0], "vuln");
    }

    #[test]
    fn parsers_preserve_positive_osv_and_trivy_evidence() {
        let osv = br#"{
            "results":[{
                "source":{"path":"Cargo.lock"},
                "packages":[{
                    "package":{"name":"demo","version":"1.2.3","ecosystem":"crates.io"},
                    "vulnerabilities":[{
                        "id":"GHSA-DEMO",
                        "aliases":["CVE-2026-1"],
                        "summary":"fixture advisory",
                        "database_specific":{"severity":"critical"}
                    }]
                }]
            }]
        }"#;
        let report =
            parse_osv_report(osv, Path::new("osv.json"), "revision-a", "2.3.8", "osv-snapshot")
                .expect("parse OSV report");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.observations.len(), 1);
        let observation = &report.observations[0];
        assert_eq!(observation.tool, "osv-scanner");
        assert_eq!(observation.target_revision, "revision-a");
        assert_eq!(observation.package.name, "demo");
        assert_eq!(observation.package.source_location.as_deref(), Some("Cargo.lock"));
        assert_eq!(observation.advisory.primary_id, "GHSA-DEMO");
        assert!(observation.advisory.aliases.contains("CVE-2026-1"));
        assert_eq!(observation.severity, Severity::Critical);

        let trivy = br#"{
            "SchemaVersion":2,
            "Results":[{
                "Target":"fixture.sbom.json",
                "Class":"library",
                "Vulnerabilities":[{
                    "VulnerabilityID":"CVE-2026-2",
                    "PkgName":"demo",
                    "InstalledVersion":"1.2.3",
                    "FixedVersion":"",
                    "Severity":"HIGH",
                    "Title":"fixture title",
                    "PkgIdentifier":{"PURL":"pkg:cargo/demo@1.2.3"},
                    "DataSource":{"Name":"fixture-db"}
                }]
            }]
        }"#;
        let report = parse_trivy_report(
            trivy,
            Path::new("trivy.json"),
            "revision-a",
            "0.74.0",
            "trivy-snapshot",
        )
        .expect("parse Trivy report");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.observations.len(), 1);
        let observation = &report.observations[0];
        assert_eq!(observation.package.fixed_version, None);
        assert_eq!(observation.package.purl.as_deref(), Some("pkg:cargo/demo@1.2.3"));
        assert_eq!(observation.package.invalid_purl, None);
        assert_eq!(observation.severity, Severity::High);
        assert_eq!(observation.data_source.as_deref(), Some("fixture-db"));
    }

    #[test]
    fn required_arrays_severity_and_supplied_purls_are_exact() {
        let value = serde_json::json!({"items": [1]});
        assert_eq!(required_array("fixture", &value, "items").expect("array").len(), 1);
        assert!(required_array("fixture", &serde_json::json!({}), "items").is_err());
        assert!(required_array("fixture", &serde_json::json!({"items": {}}), "items").is_err());

        for (input, expected) in [
            ("critical", Severity::Critical),
            ("HIGH", Severity::High),
            ("medium", Severity::Medium),
            ("moderate", Severity::Medium),
            ("low", Severity::Low),
            ("unknown", Severity::Info),
        ] {
            assert_eq!(map_severity(input), expected);
        }

        assert_eq!(supplied_purl(None), (None, None));
        assert_eq!(
            supplied_purl(Some("pkg:cargo/demo@1.2.3")),
            (Some("pkg:cargo/demo@1.2.3".to_string()), None)
        );
        assert_eq!(supplied_purl(Some("not a purl")), (None, Some("not a purl".to_string())));
    }
}
