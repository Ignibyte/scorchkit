use async_trait::async_trait;
use scorchkit_core::{
    AdapterExecutionAssessment, AdapterExecutionGap, AdapterExecutionGapKind,
    AdapterExecutionStatus, AdapterInputIdentity, AdapterParseOutcome,
};
use scorchkit_policy::EffectClass;

use crate::engine::error::{Result, ScorchError};
use crate::engine::events::ScanEvent;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::observation::redact_text;
use crate::engine::scan_context::ScanContext;
use crate::trusted_nuclei::collection::{load_collection, VerifiedNucleiCollection};
use crate::trusted_nuclei::invocation::{
    probe_version, resolve_target, scan_templates, validate_templates, verify_scan_trust,
};
use crate::trusted_nuclei::parser::parse_nuclei_output;
use crate::trusted_nuclei::workspace::NucleiWorkspace;

/// Trusted, application-only Nuclei template execution.
#[derive(Debug)]
pub struct NucleiModule;

#[async_trait]
impl ScanModule for NucleiModule {
    fn name(&self) -> &'static str {
        "Nuclei Vulnerability Scanner"
    }

    fn id(&self) -> &'static str {
        "nuclei"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Trusted application-only template scanning via Nuclei"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("nuclei")
    }

    async fn run(&self, context: &ScanContext) -> Result<Vec<Finding>> {
        run_trusted_nuclei(context).await
    }
}

#[allow(clippy::too_many_lines)] // JUSTIFICATION: linear fail-closed trust stages make bypass review explicit.
async fn run_trusted_nuclei(context: &ScanContext) -> Result<Vec<Finding>> {
    let config = &context.config.nuclei;
    let Some(manifest) = config.collection_manifest.as_deref() else {
        return fail(
            context,
            AdapterExecutionAssessment::new("nuclei"),
            AdapterExecutionStatus::Incomplete,
            AdapterExecutionGapKind::ConfigurationUnavailable,
            "collection",
            ScorchError::Config("trusted Nuclei requires nuclei.collection_manifest".to_string()),
        );
    };

    let collection = match load_collection(context, manifest, config) {
        Ok(collection) => collection,
        Err(error) => {
            let kind = collection_gap_kind(&error);
            return fail(
                context,
                AdapterExecutionAssessment::new("nuclei"),
                AdapterExecutionStatus::Degraded,
                kind,
                "collection",
                error,
            );
        }
    };
    let mut assessment = collection_assessment(&collection);
    let effect = collection.strongest_effect;
    context.events.publish(ScanEvent::Custom {
        kind: "nuclei.collection_verified".to_string(),
        data: serde_json::json!({
            "collection_identity": collection.identity,
            "signer_identity": collection.signer_identity,
            "template_count": collection.templates.len(),
            "effect": effect_name(effect),
        }),
    });

    if let Err(error) = context.authorize_adapter_effect(effect) {
        return fail(
            context,
            assessment,
            AdapterExecutionStatus::Incomplete,
            AdapterExecutionGapKind::UnsupportedCapability,
            "authorization",
            error,
        );
    }

    let target = match resolve_target(context, effect).await {
        Ok(target) => target,
        Err(error) => {
            let kind = if matches!(&error, ScorchError::Policy(_)) {
                AdapterExecutionGapKind::UnsupportedCapability
            } else {
                AdapterExecutionGapKind::ConfigurationUnavailable
            };
            return fail(
                context,
                assessment,
                AdapterExecutionStatus::Incomplete,
                kind,
                "target",
                error,
            );
        }
    };
    let workspace = match NucleiWorkspace::create(&collection) {
        Ok(workspace) => workspace,
        Err(error) => {
            return fail(
                context,
                assessment,
                AdapterExecutionStatus::Degraded,
                AdapterExecutionGapKind::ExecutionFailed,
                "workspace",
                error,
            );
        }
    };
    let program = context.config.tools.get_path("nuclei");
    let version = match probe_version(context, &program, &workspace, config, effect).await {
        Ok(version) => version,
        Err(error) => {
            return fail(
                context,
                assessment,
                AdapterExecutionStatus::Degraded,
                AdapterExecutionGapKind::VersionUnsupported,
                "version",
                error,
            );
        }
    };
    assessment.tool_version = Some(version.clone());

    if let Err(error) = validate_templates(context, &program, &workspace, config, effect).await {
        return fail(
            context,
            assessment,
            AdapterExecutionStatus::Degraded,
            AdapterExecutionGapKind::SignatureRejected,
            "native-signature",
            error,
        );
    }
    let scan_output =
        match scan_templates(context, &program, &workspace, config, effect, &target).await {
            Ok(output) => output,
            Err(error) => {
                return fail(
                    context,
                    assessment,
                    AdapterExecutionStatus::Degraded,
                    AdapterExecutionGapKind::ExecutionFailed,
                    "scan",
                    error,
                );
            }
        };
    if let Err(error) =
        verify_scan_trust(&scan_output, collection.templates.len(), &collection.signer_identity)
    {
        return fail(
            context,
            assessment,
            AdapterExecutionStatus::Degraded,
            AdapterExecutionGapKind::SignatureRejected,
            "native-signature",
            error,
        );
    }
    let output = match workspace.read_results(config.output_limit_bytes) {
        Ok(output) => output,
        Err(error) => {
            return fail(
                context,
                assessment,
                AdapterExecutionStatus::Degraded,
                AdapterExecutionGapKind::ExecutionFailed,
                "output",
                error,
            );
        }
    };
    let output = match std::str::from_utf8(&output) {
        Ok(output) => output,
        Err(error) => {
            return fail(
                context,
                assessment,
                AdapterExecutionStatus::Degraded,
                AdapterExecutionGapKind::OutputInvalid,
                "output",
                ScorchError::ToolOutputParse {
                    tool: "nuclei".to_string(),
                    reason: format!("JSONL output is not UTF-8: {error}"),
                },
            );
        }
    };
    let findings = match parse_nuclei_output(output, &target, &collection, &version) {
        AdapterParseOutcome::Findings(findings) => findings,
        AdapterParseOutcome::NoFindings => Vec::new(),
        AdapterParseOutcome::Malformed { reason } => {
            return fail(
                context,
                assessment,
                AdapterExecutionStatus::Degraded,
                AdapterExecutionGapKind::OutputInvalid,
                "output",
                ScorchError::ToolOutputParse { tool: "nuclei".to_string(), reason },
            );
        }
    };

    context.events.publish(ScanEvent::Custom {
        kind: "nuclei.execution_completed".to_string(),
        data: serde_json::json!({
            "collection_identity": collection.identity,
            "tool_version": version,
            "template_count": collection.templates.len(),
            "finding_count": findings.len(),
        }),
    });
    context.shared_data.publish_adapter_assessment(assessment);
    Ok(findings)
}

fn collection_assessment(collection: &VerifiedNucleiCollection) -> AdapterExecutionAssessment {
    let mut assessment = AdapterExecutionAssessment::new("nuclei");
    assessment.configuration_identity = Some(collection.identity.clone());
    assessment.strongest_effect = Some(effect_name(collection.strongest_effect).to_string());
    assessment.inputs = collection
        .templates
        .iter()
        .map(|template| {
            AdapterInputIdentity::new("nuclei_template", &template.id, &template.sha256)
                .with_signer(&collection.signer_identity)
        })
        .collect();
    assessment
}

#[allow(clippy::needless_pass_by_value)] // JUSTIFICATION: consuming the source error prevents unredacted reuse.
fn fail<T>(
    context: &ScanContext,
    assessment: AdapterExecutionAssessment,
    status: AdapterExecutionStatus,
    kind: AdapterExecutionGapKind,
    component: &str,
    error: ScorchError,
) -> Result<T> {
    let message = redact_text(&error.to_string());
    context.shared_data.publish_adapter_assessment(
        assessment.with_gap(status, AdapterExecutionGap::new(kind, component, &message)),
    );
    let detail = message.strip_prefix("configuration error: ").unwrap_or(&message).to_string();
    Err(ScorchError::Config(detail))
}

fn collection_gap_kind(error: &ScorchError) -> AdapterExecutionGapKind {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("signature")
        || message.contains("signer")
        || message.contains("digest")
        || message.contains("certificate")
    {
        AdapterExecutionGapKind::SignatureRejected
    } else {
        AdapterExecutionGapKind::InputRejected
    }
}

const fn effect_name(effect: EffectClass) -> &'static str {
    match effect {
        EffectClass::Passive => "passive",
        EffectClass::ActiveSafe => "active-safe",
        EffectClass::Intrusive => "intrusive",
        EffectClass::CredentialTest => "credential-test",
        EffectClass::Exploit => "exploit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use scorchkit_policy::{Capability, Engagement, EngagementPolicy, ScopeRule};
    use scorchkit_tools::{ToolExecutor, ToolInvocation, ToolOutput};

    use crate::config::AppConfig;
    use crate::engine::policy_network::PolicyNetwork;
    use crate::engine::target::Target;
    use crate::trusted_nuclei::collection::VerifiedNucleiTemplate;

    #[derive(Debug)]
    struct CountingExecutor(Arc<AtomicUsize>);

    #[async_trait]
    impl ToolExecutor for CountingExecutor {
        async fn execute(&self, _invocation: ToolInvocation) -> Result<ToolOutput> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ScorchError::Config("executor must not be reached".to_string()))
        }
    }

    #[test]
    fn assessment_uses_verified_collection_and_signer_identity() {
        let collection = VerifiedNucleiCollection {
            identity: "fixture@1:sha256:abc".to_string(),
            signer_identity: "review@example.test".to_string(),
            certificate_bytes: Vec::new(),
            strongest_effect: EffectClass::ActiveSafe,
            templates: vec![VerifiedNucleiTemplate {
                id: "probe".to_string(),
                sha256: "b".repeat(64),
                bytes: Vec::new(),
            }],
        };
        let assessment = collection_assessment(&collection);
        assert_eq!(assessment.configuration_identity.as_deref(), Some("fixture@1:sha256:abc"));
        assert_eq!(assessment.strongest_effect.as_deref(), Some("active-safe"));
        assert_eq!(assessment.inputs[0].signer_identity.as_deref(), Some("review@example.test"));
    }

    #[test]
    fn collection_integrity_errors_get_a_stable_gap_kind() {
        assert_eq!(
            collection_gap_kind(&ScorchError::Config("template digest mismatch".to_string())),
            AdapterExecutionGapKind::SignatureRejected
        );
        assert_eq!(
            collection_gap_kind(&ScorchError::Config("unknown template field".to_string())),
            AdapterExecutionGapKind::InputRejected
        );
    }

    #[tokio::test]
    async fn missing_exact_process_grant_denies_before_any_nuclei_invocation() {
        let fixture_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/nuclei")
            .canonicalize()
            .expect("fixture root");
        let target = Target::parse("http://127.0.0.1:38117").expect("target");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("127.0.0.1").expect("target scope"))
            .allow_scope(ScopeRule::path_prefix(&fixture_root).expect("fixture scope"))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive)
            .allow_effect(EffectClass::ActiveSafe);
        let engagement = Arc::new(Engagement::new("denied Nuclei process", policy));
        let mut config = AppConfig::default();
        config.nuclei.collection_manifest = Some(fixture_root.join("collection.json"));
        let calls = Arc::new(AtomicUsize::new(0));
        let context = ScanContext::with_http_clients(
            target,
            Arc::new(config),
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
        .with_tool_executor(Arc::new(CountingExecutor(Arc::clone(&calls))));

        assert!(run_trusted_nuclei(&context).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let assessment =
            context.shared_data.adapter_assessment("nuclei").expect("denied assessment");
        assert_eq!(assessment.status, AdapterExecutionStatus::Incomplete);
        assert_eq!(assessment.gaps[0].kind, AdapterExecutionGapKind::UnsupportedCapability);
    }

    #[tokio::test]
    async fn denied_resolved_address_is_incomplete_before_any_nuclei_invocation() {
        let fixture_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/nuclei")
            .canonicalize()
            .expect("fixture root");
        let target = Target::parse("http://localhost:38117").expect("target");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("localhost").expect("hostname scope"))
            .allow_scope(ScopeRule::path_prefix(&fixture_root).expect("fixture scope"))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::ExternalTool)
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive)
            .allow_effect(EffectClass::ActiveSafe);
        let engagement = Arc::new(Engagement::new("denied Nuclei address", policy));
        let mut config = AppConfig::default();
        config.nuclei.collection_manifest = Some(fixture_root.join("collection.json"));
        let calls = Arc::new(AtomicUsize::new(0));
        let context = ScanContext::with_http_clients(
            target,
            Arc::new(config),
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
        .with_tool_executor(Arc::new(CountingExecutor(Arc::clone(&calls))));

        assert!(run_trusted_nuclei(&context).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let assessment = context.shared_data.adapter_assessment("nuclei").expect("assessment");
        assert_eq!(assessment.status, AdapterExecutionStatus::Incomplete);
        assert_eq!(assessment.gaps[0].kind, AdapterExecutionGapKind::UnsupportedCapability);
        assert_eq!(assessment.gaps[0].component, "target");
    }
}
