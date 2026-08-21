use std::time::Duration;

use scorchkit_config::NucleiConfig;
use scorchkit_core::{Result, ScorchError};
use scorchkit_policy::EffectClass;
use scorchkit_tools::{ArtifactBudget, ToolInvocation, ToolOutput};
use url::{Host, Url};

use crate::engine::observation::redact_text;
use crate::engine::scan_context::ScanContext;

use super::workspace::NucleiWorkspace;
use super::SUPPORTED_NUCLEI_VERSION;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNucleiTarget {
    pub canonical: Url,
    pub execution: Url,
    pub authority_header: Option<String>,
    pub sni: Option<String>,
}

pub async fn resolve_target(
    context: &ScanContext,
    effect: EffectClass,
) -> Result<ResolvedNucleiTarget> {
    let canonical = context.target.url.clone();
    let host = canonical
        .host_str()
        .ok_or_else(|| ScorchError::Config("Nuclei target has no host".to_string()))?;
    let port = canonical
        .port_or_known_default()
        .ok_or_else(|| ScorchError::Config("Nuclei target has no known port".to_string()))?;
    let addresses = context
        .resolve_network_target_for_effect(host, port, Duration::from_secs(10), effect)
        .await?;
    let address = addresses
        .first()
        .ok_or_else(|| ScorchError::Config("Nuclei target resolved to no addresses".to_string()))?;
    let mut execution = canonical.clone();
    execution.set_host(Some(&address.ip().to_string())).map_err(|error| {
        ScorchError::Config(format!("cannot construct concrete Nuclei target: {error}"))
    })?;
    execution
        .set_port(Some(address.port()))
        .map_err(|()| ScorchError::Config("cannot set concrete Nuclei target port".to_string()))?;

    let (authority_header, sni) = match canonical.host() {
        Some(Host::Domain(domain)) => {
            let authority = authority(&canonical, domain);
            (Some(authority), Some(domain.to_string()))
        }
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => (None, None),
        None => return Err(ScorchError::Config("Nuclei target has no host".to_string())),
    };
    Ok(ResolvedNucleiTarget { canonical, execution, authority_header, sni })
}

pub async fn probe_version(
    context: &ScanContext,
    program: &str,
    workspace: &NucleiWorkspace,
    config: &NucleiConfig,
    effect: EffectClass,
) -> Result<String> {
    let invocation = base_invocation(program, vec!["-version".to_string()], workspace, config);
    let output = context.run_invocation_for_effect(invocation, effect).await?;
    let version =
        parse_version(&format!("{}\n{}", output.stdout, output.stderr)).ok_or_else(|| {
            ScorchError::Config("cannot determine the pinned Nuclei version".to_string())
        })?;
    if version != SUPPORTED_NUCLEI_VERSION {
        return Err(ScorchError::Config(format!(
            "unsupported Nuclei version {version}; expected {SUPPORTED_NUCLEI_VERSION}"
        )));
    }
    Ok(version)
}

pub async fn validate_templates(
    context: &ScanContext,
    program: &str,
    workspace: &NucleiWorkspace,
    config: &NucleiConfig,
    effect: EffectClass,
) -> Result<()> {
    let mut args = vec![
        "-validate".to_string(),
        "-duc".to_string(),
        "-dut".to_string(),
        "-ni".to_string(),
        "-no-stdin".to_string(),
        "-nc".to_string(),
        "-auth=false".to_string(),
        "-mp".to_string(),
        "0".to_string(),
    ];
    append_templates(&mut args, workspace);
    let output = context
        .run_invocation_for_effect(base_invocation(program, args, workspace, config), effect)
        .await?;
    verify_validation_output(&output)
}

pub async fn scan_templates(
    context: &ScanContext,
    program: &str,
    workspace: &NucleiWorkspace,
    config: &NucleiConfig,
    effect: EffectClass,
    target: &ResolvedNucleiTarget,
) -> Result<ToolOutput> {
    let mut args = vec![
        "-u".to_string(),
        target.execution.as_str().to_string(),
        "-jsonl".to_string(),
        "-nc".to_string(),
        "-auth=false".to_string(),
        "-mp".to_string(),
        "0".to_string(),
        "-duc".to_string(),
        "-dut".to_string(),
        "-ni".to_string(),
        "-dr".to_string(),
        "-no-stdin".to_string(),
        "-nh".to_string(),
        "-nmhe".to_string(),
        "-dc".to_string(),
        "-jle".to_string(),
        workspace.result_path().to_string_lossy().into_owned(),
        "-rl".to_string(),
        config.rate_limit_per_second.to_string(),
        "-c".to_string(),
        config.concurrency.to_string(),
        "-timeout".to_string(),
        config.request_timeout_seconds.to_string(),
        "-retries".to_string(),
        "0".to_string(),
    ];
    if let Some(authority) = &target.authority_header {
        args.push("-H".to_string());
        args.push(format!("Host: {authority}"));
    }
    if let Some(sni) = &target.sni {
        args.push("-sni".to_string());
        args.push(sni.clone());
    }
    append_templates(&mut args, workspace);
    context
        .run_invocation_for_effect(base_invocation(program, args, workspace, config), effect)
        .await
}

pub fn verify_scan_trust(
    output: &ToolOutput,
    expected_template_count: usize,
    signer_identity: &str,
) -> Result<()> {
    let combined = format!("{}\n{}", output.stdout, output.stderr);
    reject_native_trust_diagnostic(&combined, "scan")?;
    let expected =
        format!("Executing {expected_template_count} signed templates from {signer_identity}");
    if !combined.contains(&expected) {
        return Err(ScorchError::Config(format!(
            "Nuclei did not confirm the exact signed collection: expected '{expected}'"
        )));
    }
    Ok(())
}

fn verify_validation_output(output: &ToolOutput) -> Result<()> {
    let combined = format!("{}\n{}", output.stdout, output.stderr);
    reject_native_trust_diagnostic(&combined, "validation")?;
    if !combined.contains("All templates validated successfully") {
        return Err(ScorchError::Config(
            "Nuclei did not confirm successful template validation".to_string(),
        ));
    }
    Ok(())
}

fn reject_native_trust_diagnostic(output: &str, phase: &str) -> Result<()> {
    let diagnostic = output.lines().find(|line| {
        let lower = line.to_ascii_lowercase();
        ["[err]", "[wrn]", "[ftl]", "unsigned template", "tampered template"]
            .iter()
            .any(|marker| lower.contains(marker))
    });
    if let Some(diagnostic) = diagnostic {
        return Err(ScorchError::Config(format!(
            "Nuclei {phase} reported a trust or execution diagnostic: {}",
            redact_text(diagnostic)
        )));
    }
    Ok(())
}

fn base_invocation(
    program: &str,
    args: Vec<String>,
    workspace: &NucleiWorkspace,
    config: &NucleiConfig,
) -> ToolInvocation {
    ToolInvocation::strict_owned(
        program.to_string(),
        args,
        Duration::from_secs(config.timeout_seconds),
    )
    .with_output_limit(config.output_limit_bytes)
    .with_clean_environment()
    .with_environment("HOME", workspace.home().to_string_lossy().into_owned())
    .with_environment("XDG_CONFIG_HOME", workspace.config().to_string_lossy().into_owned())
    .with_environment("XDG_CACHE_HOME", workspace.cache().to_string_lossy().into_owned())
    .with_environment("TMPDIR", workspace.temporary().to_string_lossy().into_owned())
    .with_environment(
        "NUCLEI_USER_CERTIFICATE",
        workspace.certificate().to_string_lossy().into_owned(),
    )
    .with_environment("DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD", "true")
    .with_environment("DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD", "true")
    .with_environment("DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD", "true")
    .with_environment("DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD", "true")
    .with_environment("DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD", "true")
    .with_environment("NO_COLOR", "1")
    .with_working_directory(workspace.root())
    .with_artifact_budget(ArtifactBudget::new(
        workspace.root(),
        config.artifact_limit_bytes,
        config.artifact_limit_files,
    ))
}

fn append_templates(args: &mut Vec<String>, workspace: &NucleiWorkspace) {
    for template in workspace.templates() {
        args.push("-t".to_string());
        args.push(template.to_string_lossy().into_owned());
    }
}

fn parse_version(output: &str) -> Option<String> {
    output
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .find(|candidate| {
            let mut parts = candidate.split('.');
            matches!(parts.next(), Some(major) if !major.is_empty())
                && matches!(parts.next(), Some(minor) if !minor.is_empty())
                && matches!(parts.next(), Some(patch) if !patch.is_empty())
                && parts.next().is_none()
        })
        .map(str::to_string)
}

fn authority(url: &Url, domain: &str) -> String {
    url.port().map_or_else(|| domain.to_string(), |port| format!("{domain}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use scorchkit_policy::{Capability, Engagement, EngagementPolicy, ScopeRule};
    use scorchkit_tools::{EnvironmentPolicy, ToolExecutor};

    use crate::config::AppConfig;
    use crate::engine::policy_network::PolicyNetwork;
    use crate::engine::target::Target;
    use crate::trusted_nuclei::collection::{VerifiedNucleiCollection, VerifiedNucleiTemplate};

    #[derive(Debug, Default)]
    struct InvocationRecorder(Mutex<Vec<ToolInvocation>>);

    #[async_trait]
    impl ToolExecutor for InvocationRecorder {
        async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
            let stdout = if invocation.args == ["-version"] {
                "Nuclei Engine Version: v3.11.1".to_string()
            } else if invocation.args.iter().any(|argument| argument == "-validate") {
                "All templates validated successfully".to_string()
            } else {
                "Executing 1 signed templates from fixture-signer".to_string()
            };
            self.0.lock().expect("recorder lock").push(invocation);
            Ok(output(&stdout, ""))
        }
    }

    fn trusted_collection() -> VerifiedNucleiCollection {
        VerifiedNucleiCollection {
            identity: "fixture@1:sha256:abc".to_string(),
            signer_identity: "fixture-signer".to_string(),
            certificate_bytes: b"fixture certificate".to_vec(),
            strongest_effect: EffectClass::ActiveSafe,
            templates: vec![VerifiedNucleiTemplate {
                id: "probe".to_string(),
                sha256: "b".repeat(64),
                bytes: b"id: probe".to_vec(),
            }],
        }
    }

    fn authorized_context(recorder: Arc<InvocationRecorder>) -> ScanContext {
        let target = Target::parse("https://example.com/app").expect("target");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.com").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::ActiveSafe);
        let engagement = Arc::new(Engagement::new("invocation fixture", policy));
        ScanContext::with_http_clients(
            target,
            Arc::new(AppConfig::default()),
            reqwest::Client::new(),
            reqwest::Client::new(),
            Vec::new(),
            PolicyNetwork::new(
                Arc::clone(&engagement),
                Capability::DastScan,
                EffectClass::ActiveSafe,
            ),
            Some(engagement),
        )
        .with_tool_executor(recorder)
    }

    #[test]
    fn version_parser_requires_exact_three_numeric_components() {
        assert_eq!(parse_version("[INF] Current Version: v3.11.1"), Some("3.11.1".to_string()));
        assert_eq!(parse_version("nuclei 3.11"), None);
        assert_eq!(parse_version("release unknown"), None);
    }

    #[test]
    fn authority_preserves_explicit_ports_only() {
        assert_eq!(
            authority(&Url::parse("https://example.com:8443/app").expect("URL"), "example.com"),
            "example.com:8443"
        );
        assert_eq!(
            authority(&Url::parse("https://example.com/app").expect("URL"), "example.com"),
            "example.com"
        );
    }

    fn output(stdout: &str, stderr: &str) -> ToolOutput {
        ToolOutput {
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            exit_code: 0,
            duration: Duration::ZERO,
            resolved_program: std::path::PathBuf::from("/owned/nuclei"),
        }
    }

    #[test]
    fn native_signature_confirmation_is_exact_and_diagnostics_fail_closed() {
        let valid = output(
            "Templates loaded for current scan: 1\nExecuting 1 signed templates from reviewer",
            "",
        );
        assert!(verify_scan_trust(&valid, 1, "reviewer").is_ok());
        assert!(verify_scan_trust(&valid, 2, "reviewer").is_err());
        assert!(verify_scan_trust(&valid, 1, "other").is_err());

        let unsigned = output("", "[WRN] Skipping 1 unsigned template[s]");
        assert!(verify_scan_trust(&unsigned, 1, "reviewer").is_err());
        assert!(verify_validation_output(&output(
            "All templates validated successfully",
            "[ERR] malformed user cert found",
        ))
        .is_err());
    }

    #[tokio::test]
    async fn every_nuclei_stage_uses_explicit_owned_inputs_and_a_clean_environment() {
        let recorder = Arc::new(InvocationRecorder::default());
        let context = authorized_context(Arc::clone(&recorder));
        let config = NucleiConfig::default();
        let workspace = NucleiWorkspace::create(&trusted_collection()).expect("workspace");
        let target = ResolvedNucleiTarget {
            canonical: Url::parse("https://example.com/app").expect("canonical"),
            execution: Url::parse("https://192.0.2.10/app").expect("execution"),
            authority_header: Some("example.com".to_string()),
            sni: Some("example.com".to_string()),
        };

        assert_eq!(
            probe_version(&context, "/owned/nuclei", &workspace, &config, EffectClass::ActiveSafe)
                .await
                .expect("version"),
            SUPPORTED_NUCLEI_VERSION
        );
        validate_templates(&context, "/owned/nuclei", &workspace, &config, EffectClass::ActiveSafe)
            .await
            .expect("validation");
        let scan_output = scan_templates(
            &context,
            "/owned/nuclei",
            &workspace,
            &config,
            EffectClass::ActiveSafe,
            &target,
        )
        .await
        .expect("scan");
        verify_scan_trust(&scan_output, 1, "fixture-signer").expect("native trust");

        let invocations = recorder.0.lock().expect("recorder lock").clone();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[0].args, ["-version"]);
        for invocation in &invocations {
            assert_eq!(invocation.program, "/owned/nuclei");
            assert_eq!(invocation.environment_policy, EnvironmentPolicy::Clear);
            assert_eq!(invocation.timeout, Duration::from_secs(config.timeout_seconds));
            assert_eq!(invocation.output_limit_bytes, config.output_limit_bytes);
            assert_eq!(invocation.working_directory.as_deref(), Some(workspace.root()));
            assert_eq!(
                invocation.artifact_budget.as_ref().map(|budget| (
                    budget.root.as_path(),
                    budget.max_bytes,
                    budget.max_files,
                )),
                Some((workspace.root(), config.artifact_limit_bytes, config.artifact_limit_files,))
            );
            for forbidden in ["-ut", "-update-templates", "-ai", "-it", "-headless"] {
                assert!(!invocation.args.iter().any(|argument| argument == forbidden));
            }
        }

        let validation = &invocations[1];
        for required in ["-validate", "-duc", "-dut", "-ni", "-no-stdin", "-auth=false"] {
            assert!(validation.args.iter().any(|argument| argument == required));
        }
        assert_eq!(validation.args.iter().filter(|argument| argument.as_str() == "-t").count(), 1);
        assert!(validation
            .args
            .iter()
            .any(|argument| argument == &workspace.templates()[0].to_string_lossy()));

        let scan = &invocations[2];
        for required in ["-jsonl", "-duc", "-dut", "-ni", "-dr", "-no-stdin", "-auth=false"] {
            assert!(scan.args.iter().any(|argument| argument == required));
        }
        assert!(scan
            .args
            .windows(2)
            .any(|pair| { pair[0] == "-u" && pair[1] == target.execution.as_str() }));
        assert!(scan
            .args
            .windows(2)
            .any(|pair| { pair[0] == "-H" && pair[1] == "Host: example.com" }));
        assert!(scan.args.windows(2).any(|pair| { pair[0] == "-sni" && pair[1] == "example.com" }));
        assert_eq!(scan.args.iter().filter(|argument| argument.as_str() == "-t").count(), 1);
    }
}
