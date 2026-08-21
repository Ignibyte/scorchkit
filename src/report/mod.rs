pub mod attack_chain;
pub mod attack_path;
pub mod dashboard;
pub mod diff;
pub mod html;
pub mod json;
pub mod pdf;
pub mod sarif;
pub mod terminal;

#[cfg(test)]
pub(crate) fn application_pentest_fixture() -> scorchkit_core::ApplicationPentestAssessment {
    use scorchkit_core::{
        ApplicationPentestBlastRadius, ApplicationPentestCleanupDisposition,
        ApplicationPentestEvidenceRequirement, ApplicationPentestGap, ApplicationPentestGapKind,
        ApplicationPentestOperation, ApplicationPentestPayloadClass,
        ApplicationPentestProposalKind, ApplicationPentestProposalSource,
        ApplicationPentestScenario, ApplicationPentestScenarioOutcome,
        ApplicationPentestScenarioStatus,
    };

    let plan = crate::application_pentest::compile_application_pentest_plan(
        "https://example.com/upload",
        vec![ApplicationPentestScenario {
            schema: String::new(),
            identity: String::new(),
            name: "reviewed upload <scenario>".to_string(),
            proposal_source: ApplicationPentestProposalSource {
                kind: ApplicationPentestProposalKind::Agent,
                label: "codex<script>".to_string(),
            },
            class: scorchkit_core::ApplicationPentestScenarioClass::FileUpload,
            payload_class: ApplicationPentestPayloadClass::InertUpload,
            operation: ApplicationPentestOperation {
                method: "POST".to_string(),
                route: "/upload".to_string(),
                parameter: None,
            },
            personas: Vec::new(),
            blast_radius: ApplicationPentestBlastRadius { max_seconds: 30, max_concurrency: 1 },
            cleanup: ApplicationPentestCleanupDisposition::ManualRequired,
            preconditions: vec!["test account exists".to_string()],
            evidence_requirements: vec![ApplicationPentestEvidenceRequirement::CleanupProof],
            source_finding_identities: vec!["a".repeat(64)],
            source_path_identities: Vec::new(),
            source_references_verified: false,
        }],
    )
    .expect("application-pentest report plan");
    let planned = &plan.scenarios[0];
    let now = chrono::Utc::now();
    let mut assessment = scorchkit_core::ApplicationPentestAssessment::new(&plan);
    assessment.record(ApplicationPentestScenarioOutcome {
        scenario_identity: planned.scenario.identity.clone(),
        executor_kind: planned.executor_kind,
        executor_id: planned.executor_id.clone(),
        authorization_requirements: planned.authorization_requirements.clone(),
        status: ApplicationPentestScenarioStatus::Incomplete,
        invariant: None,
        finding_identities: Vec::new(),
        evidence_identities: Vec::new(),
        evidence_records: Vec::new(),
        gaps: vec![ApplicationPentestGap::new(
            ApplicationPentestGapKind::CleanupRequired,
            "token=report-secret <cleanup>",
        )],
        started_at: now,
        completed_at: now,
    });
    assessment.validate().expect("valid report assessment");
    assessment
}
