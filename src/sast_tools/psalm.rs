//! Psalm taint-analysis adapter for deep PHP SAST.

use std::time::Duration;

use async_trait::async_trait;
use scorchkit_core::AdapterParseOutcome;

use super::sarif::{parse_sarif_output, read_bounded_sarif, SarifAdapter};
use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeAnalysisDepth, CodeCategory, CodeModule};
use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::runner::subprocess::ToolInvocation;

/// Deep PHP source-to-sink analysis using Psalm.
#[derive(Debug)]
pub struct PsalmModule;

#[async_trait]
impl CodeModule for PsalmModule {
    fn name(&self) -> &'static str {
        "Psalm PHP Taint Analysis"
    }

    fn id(&self) -> &'static str {
        "psalm"
    }

    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }

    fn depth(&self) -> CodeAnalysisDepth {
        CodeAnalysisDepth::Deep
    }

    fn description(&self) -> &'static str {
        "PHP source-to-sink taint analysis with SARIF flow evidence"
    }

    fn languages(&self) -> &'static [&'static str] {
        &["php"]
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&'static str> {
        Some("psalm")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let artifacts = tempfile::tempdir()?;
        let report = artifacts.path().join("psalm-taint.sarif");
        let config = artifacts.path().join("psalm.xml");
        let cache = artifacts.path().join("cache");
        let home = artifacts.path().join("home");
        std::fs::create_dir_all(&cache)?;
        std::fs::create_dir_all(&home)?;
        write_psalm_config(&ctx.path, &config, &cache)?;
        let output =
            ctx.run_invocation(psalm_invocation(artifacts.path(), &config, &report, &home)).await?;
        if !matches!(output.exit_code, 0 | 2) {
            return Err(ScorchError::ToolFailed {
                tool: "psalm".to_string(),
                status: output.exit_code,
                stderr: crate::engine::observation::redact_text(&output.stderr),
            });
        }
        let sarif = read_bounded_sarif(&report, "psalm")?;
        parse_psalm_sarif(&sarif).into_result("psalm")
    }
}

fn psalm_invocation(
    sandbox: &std::path::Path,
    config: &std::path::Path,
    report: &std::path::Path,
    home: &std::path::Path,
) -> ToolInvocation {
    let config_arg = format!("--config={}", config.display());
    let report_arg = format!("--report={}", report.display());
    let sandbox_value = sandbox.to_string_lossy().into_owned();
    let home_value = home.to_string_lossy().into_owned();
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
    ToolInvocation::lenient(
        "psalm",
        &["--taint-analysis", "--no-progress", "--no-cache", "--no-diff", &config_arg, &report_arg],
        Duration::from_mins(15),
    )
    .with_clean_environment()
    .with_environment("PATH", path)
    .with_environment("HOME", &home_value)
    .with_environment("XDG_CACHE_HOME", &sandbox_value)
    .with_environment("COMPOSER_HOME", &home_value)
    .with_environment("TMPDIR", &sandbox_value)
    .with_working_directory(sandbox)
}

fn write_psalm_config(
    root: &std::path::Path,
    config: &std::path::Path,
    cache: &std::path::Path,
) -> Result<()> {
    let root = root
        .to_str()
        .ok_or_else(|| ScorchError::Config("Psalm target path is not valid UTF-8".to_string()))?;
    let cache = cache
        .to_str()
        .ok_or_else(|| ScorchError::Config("Psalm cache path is not valid UTF-8".to_string()))?;
    let xml = format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<psalm xmlns=\"https://getpsalm.org/schema/config\" ",
            "errorLevel=\"2\" resolveFromConfigFile=\"true\" noCache=\"true\" ",
            "runTaintAnalysis=\"true\" allowFileIncludes=\"false\" ",
            "ignoreIncludeSideEffects=\"true\" cacheDirectory=\"{}\">\n",
            "  <projectFiles><directory name=\"{}\" /></projectFiles>\n",
            "</psalm>\n"
        ),
        xml_attribute(cache),
        xml_attribute(root),
    );
    std::fs::write(config, xml)?;
    Ok(())
}

fn xml_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
}

fn parse_psalm_sarif(sarif: &str) -> AdapterParseOutcome<Vec<Finding>> {
    parse_sarif_output(
        sarif,
        SarifAdapter {
            scanner_id: "psalm",
            config_identity: "psalm-taint-analysis/sarif",
            default_confidence: 0.85,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::runner::subprocess::{EnvironmentPolicy, ExitPolicy, ToolExecutor, ToolOutput};
    use scorchkit_core::ObservationLocation;

    #[test]
    fn invocation_is_taint_only_lenient_and_sandbox_scoped() {
        let sandbox = std::path::Path::new("/tmp/psalm-sandbox");
        let config = std::path::Path::new("/tmp/psalm-sandbox/psalm.xml");
        let report = std::path::Path::new("/tmp/output/psalm.sarif");
        let home = std::path::Path::new("/tmp/psalm-sandbox/home");
        let invocation = psalm_invocation(sandbox, config, report, home);
        assert_eq!(invocation.program, "psalm");
        assert_eq!(invocation.exit_policy, ExitPolicy::AllowNonZero);
        assert_eq!(invocation.environment_policy, EnvironmentPolicy::Clear);
        assert_eq!(invocation.working_directory.as_deref(), Some(sandbox));
        assert!(invocation.args.iter().any(|argument| argument == "--taint-analysis"));
        assert!(invocation.args.iter().any(|argument| argument == "--no-cache"));
        assert!(invocation.args.iter().any(|argument| argument == "--no-diff"));
        assert!(invocation
            .args
            .iter()
            .any(|argument| argument == "--config=/tmp/psalm-sandbox/psalm.xml"));
        assert!(invocation
            .args
            .iter()
            .any(|argument| argument == "--report=/tmp/output/psalm.sarif"));
        for required in ["PATH", "HOME", "XDG_CACHE_HOME", "COMPOSER_HOME", "TMPDIR"] {
            assert!(invocation.environment.contains_key(required));
        }
        assert!(!invocation.environment.contains_key("COMPOSER_AUTH"));
    }

    #[test]
    fn psalm_golden_preserves_source_and_sink_as_separate_steps() {
        let sarif = include_str!("../../tests/fixtures/sast/psalm-taint.sarif.json");
        let AdapterParseOutcome::Findings(findings) = parse_psalm_sarif(sarif) else {
            panic!("expected Psalm finding");
        };
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.appsec.provenance.rule_id.as_deref(), Some("TaintedSql"));
        let steps = &finding.appsec.code_flows[0].thread_flows[0].steps;
        assert_eq!(steps.len(), 2);
        assert!(matches!(
            steps[0].location,
            ObservationLocation::Source { ref path, .. } if path == "public/index.php"
        ));
        assert!(matches!(
            steps[1].location,
            ObservationLocation::Source { ref path, .. } if path == "src/Repository.php"
        ));
    }

    #[test]
    fn owned_config_escapes_paths_and_has_no_extension_execution_hooks() {
        let artifacts = tempfile::tempdir().expect("artifact root");
        let target = artifacts.path().join("project & \"fixture\"");
        let config = artifacts.path().join("psalm.xml");
        let cache = artifacts.path().join("cache");
        std::fs::create_dir_all(&target).expect("target");
        std::fs::create_dir_all(&cache).expect("cache");
        write_psalm_config(&target, &config, &cache).expect("write config");
        let xml = std::fs::read_to_string(config).expect("read config");

        assert!(xml.contains("project &amp; &quot;fixture&quot;"));
        assert!(xml.contains("allowFileIncludes=\"false\""));
        assert!(xml.contains("ignoreIncludeSideEffects=\"true\""));
        assert!(xml.contains("noCache=\"true\""));
        assert!(!xml.contains("<plugins"));
        assert!(!xml.contains("autoloader="));
        assert!(!xml.contains("xi:include"));
    }

    #[derive(Debug, Default)]
    struct PsalmRecordingExecutor {
        invocation: Mutex<Option<ToolInvocation>>,
        config: Mutex<Option<String>>,
    }

    #[async_trait::async_trait]
    impl ToolExecutor for PsalmRecordingExecutor {
        async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
            let config_path = invocation
                .args
                .iter()
                .find_map(|argument| argument.strip_prefix("--config="))
                .expect("owned config argument");
            let report_path = invocation
                .args
                .iter()
                .find_map(|argument| argument.strip_prefix("--report="))
                .expect("owned report argument");
            *self.config.lock().expect("config lock") = Some(std::fs::read_to_string(config_path)?);
            std::fs::write(
                report_path,
                include_str!("../../tests/fixtures/sast/psalm-taint.sarif.json"),
            )?;
            *self.invocation.lock().expect("invocation lock") = Some(invocation);
            Ok(ToolOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 2,
                duration: Duration::ZERO,
                resolved_program: std::path::PathBuf::from("/mock/psalm"),
            })
        }
    }

    #[tokio::test]
    async fn psalm_ignores_target_config_and_uses_owned_clean_contract() {
        let root = tempfile::tempdir().expect("PHP target");
        std::fs::write(
            root.path().join("psalm.xml"),
            "<psalm><plugins><plugin filename=\"payload.php\" /></plugins></psalm>",
        )
        .expect("target config");
        std::fs::write(root.path().join("payload.php"), "<?php file_put_contents('/tmp/x','x');")
            .expect("plugin payload");
        let executor = Arc::new(PsalmRecordingExecutor::default());
        let context = CodeContext::new(
            root.path().to_path_buf(),
            Some("php".to_string()),
            Arc::new(crate::config::AppConfig::default()),
            Vec::new(),
        )
        .with_tool_executor(executor.clone());

        let findings = PsalmModule.run(&context).await.expect("Psalm scan");
        assert_eq!(findings.len(), 1);
        let invocation = executor
            .invocation
            .lock()
            .expect("invocation lock")
            .clone()
            .expect("recorded invocation");
        assert_ne!(invocation.working_directory.as_deref(), Some(root.path()));
        assert_eq!(invocation.environment_policy, EnvironmentPolicy::Clear);
        let config = executor.config.lock().expect("config lock").clone().expect("recorded config");
        assert!(config.contains(&xml_attribute(root.path().to_str().expect("UTF-8 target"))));
        assert!(!config.contains("payload.php"));
        assert!(!config.contains("<plugins"));
    }

    #[test]
    fn psalm_descriptor_text_and_languages_are_exact() {
        assert_eq!(PsalmModule.name(), "Psalm PHP Taint Analysis");
        assert_eq!(
            PsalmModule.description(),
            "PHP source-to-sink taint analysis with SARIF flow evidence"
        );
        assert_eq!(PsalmModule.languages(), ["php"]);
    }
}
