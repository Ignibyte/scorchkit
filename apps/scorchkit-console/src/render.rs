//! Compiled, escaped server-rendered console pages.

use anyhow::{Context, Result};
use askama::Template;
use scorchkit_control::{
    EngagementViewV1, EvidenceViewV1, FindingViewV1, JobViewV1, PageV1, ProjectReportViewV1,
    ProjectViewV1, TargetViewV1,
};

/// Common immutable values rendered into every page.
#[derive(Debug, Clone)]
pub struct PageChrome {
    /// Per-process CSRF token for same-origin mutation forms.
    pub csrf: String,
    /// Last mirrored sequence at render time.
    pub event_after: u64,
    /// Safe status message selected from a closed query vocabulary.
    pub message: String,
}

/// Safe project row.
#[derive(Debug, Clone)]
pub struct ProjectRow {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// Safe job row.
#[derive(Debug, Clone)]
pub struct JobRow {
    pub id: String,
    pub state: String,
    pub target: String,
    pub profile: String,
    pub progress: String,
    pub degraded: String,
    pub terminal: bool,
}

/// Safe registered target row.
#[derive(Debug, Clone)]
pub struct TargetRow {
    pub id: String,
    pub url: String,
    pub label: String,
}

/// Safe finding summary row.
#[derive(Debug, Clone)]
pub struct FindingRow {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub severity_class: String,
    pub state: String,
    pub seen: u32,
}

/// Safe evidence row.
#[derive(Debug, Clone)]
pub struct EvidenceRow {
    pub identity: String,
    pub canonical: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    chrome: PageChrome,
    engagement_name: String,
    engagement_id: String,
    engagement_enabled: bool,
    engagement_expiry: String,
    capabilities: String,
    effects: String,
    projects: Vec<ProjectRow>,
    projects_page: String,
    jobs: Vec<JobRow>,
    jobs_page: String,
}

#[derive(Template)]
#[template(path = "project.html")]
struct ProjectTemplate {
    chrome: PageChrome,
    project: ProjectRow,
    targets: Vec<TargetRow>,
    targets_page: String,
    findings: Vec<FindingRow>,
    findings_page: String,
    report_summary: String,
    report_triage: String,
}

#[derive(Template)]
#[template(path = "finding.html")]
struct FindingTemplate {
    chrome: PageChrome,
    finding: FindingRow,
    project_id: String,
    identity: String,
    status_note: String,
    scanner_record: String,
    model_analysis: String,
    evidence: Vec<EvidenceRow>,
    evidence_ids_json: String,
    transitions: String,
    correlations: String,
    suppressions: String,
    active_suppressions: String,
}

#[derive(Template)]
#[template(path = "job.html")]
struct JobTemplate {
    chrome: PageChrome,
    job: JobRow,
    attempt: u32,
    revision: u64,
    active_modules: String,
    completed_modules: String,
    skipped_modules: String,
    failed_modules: String,
    finding_count: u32,
    error: String,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    title: String,
    message: String,
}

/// Render the operator dashboard.
///
/// # Errors
///
/// Returns a template error if the compiled render contract fails.
pub fn dashboard(
    chrome: PageChrome,
    engagement: EngagementViewV1,
    projects: PageV1<ProjectViewV1>,
    jobs: PageV1<JobViewV1>,
) -> Result<String> {
    let projects_page = page_notice(&projects);
    let jobs_page = page_notice(&jobs);
    DashboardTemplate {
        chrome,
        engagement_name: engagement.name,
        engagement_id: engagement.id.to_string(),
        engagement_enabled: engagement.enabled,
        engagement_expiry: engagement
            .expires_at
            .map_or_else(|| "No expiry".to_owned(), |value| value.to_rfc3339()),
        capabilities: join_or_none(&engagement.capabilities),
        effects: join_or_none(&engagement.effects),
        projects: projects.items.into_iter().map(project_row).collect(),
        projects_page,
        jobs: jobs.items.into_iter().map(job_row).collect(),
        jobs_page,
    }
    .render()
    .context("failed to render dashboard")
}

/// Render one project, its target registry, findings, and report summary.
///
/// # Errors
///
/// Returns a template error if the compiled render contract fails.
pub fn project(
    chrome: PageChrome,
    project: ProjectViewV1,
    targets: PageV1<TargetViewV1>,
    findings: &PageV1<FindingViewV1>,
    report: &ProjectReportViewV1,
) -> Result<String> {
    let report_summary = format!(
        "{} targets · {} scans · {} findings · {} actively suppressed",
        report.target_count,
        report.scan_count,
        report.finding_count,
        report.active_suppressed_count
    );
    let report_triage = map_summary(&report.triage_state_counts);
    let targets_page = page_notice(&targets);
    let findings_page = page_notice(findings);
    ProjectTemplate {
        chrome,
        project: project_row(project),
        targets: targets
            .items
            .into_iter()
            .map(|target| TargetRow {
                id: target.id.to_string(),
                url: target.url,
                label: target.label,
            })
            .collect(),
        targets_page,
        findings: findings.items.iter().map(finding_row).collect(),
        findings_page,
        report_summary,
        report_triage,
    }
    .render()
    .context("failed to render project")
}

/// Render one canonical finding with separately labeled scanner, model, evidence, and triage data.
///
/// # Errors
///
/// Returns a serialization or template error.
pub fn finding(
    chrome: PageChrome,
    finding: FindingViewV1,
    evidence: Vec<EvidenceViewV1>,
) -> Result<String> {
    let mut scanner = finding.canonical.clone();
    let model = scanner
        .get_mut("appsec")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|appsec| appsec.remove("agent_analysis"))
        .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
    let row = finding_row(&finding);
    let evidence_ids_json = serde_json::to_string(
        &evidence.iter().map(|item| item.evidence_identity.as_str()).collect::<Vec<_>>(),
    )?;
    FindingTemplate {
        chrome,
        finding: row,
        project_id: finding.project_id.to_string(),
        identity: finding.stable_identity,
        status_note: finding.status_note.unwrap_or_else(|| "No lifecycle note".to_owned()),
        scanner_record: pretty_json(&scanner)?,
        model_analysis: pretty_json(&model)?,
        evidence_ids_json,
        evidence: evidence
            .into_iter()
            .map(|item| {
                Ok(EvidenceRow {
                    identity: item.evidence_identity,
                    canonical: pretty_json(&item.canonical)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        transitions: pretty_json(&finding.triage.transitions)?,
        correlations: pretty_json(&finding.triage.correlations)?,
        suppressions: pretty_json(&finding.triage.suppressions)?,
        active_suppressions: join_or_none(&finding.triage.active_suppression_ids),
    }
    .render()
    .context("failed to render finding")
}

/// Render one durable job and complete progress/degradation state.
///
/// # Errors
///
/// Returns a template error if the compiled render contract fails.
pub fn job(chrome: PageChrome, value: JobViewV1) -> Result<String> {
    let row = job_row(value.clone());
    JobTemplate {
        chrome,
        job: row,
        attempt: value.attempt,
        revision: value.revision,
        active_modules: join_or_none(&value.progress.active_modules),
        completed_modules: join_or_none(&value.progress.completed_modules),
        skipped_modules: join_or_none(&value.progress.skipped_modules),
        failed_modules: join_or_none(&value.progress.failed_modules),
        finding_count: value.progress.finding_count,
        error: value.error.unwrap_or_else(|| "No terminal diagnostic".to_owned()),
    }
    .render()
    .context("failed to render job")
}

/// Render a safe standalone error page.
#[must_use]
pub fn error(title: &str, message: &str) -> String {
    ErrorTemplate { title: title.to_owned(), message: message.to_owned() }
        .render()
        .unwrap_or_else(|_| "ScorchKit Console could not render this response".to_owned())
}

fn project_row(project: ProjectViewV1) -> ProjectRow {
    ProjectRow { id: project.id.to_string(), name: project.name, description: project.description }
}

fn finding_row(finding: &FindingViewV1) -> FindingRow {
    let severity = json_text(&finding.canonical, "severity", "unknown");
    FindingRow {
        id: finding.id.to_string(),
        title: json_text(&finding.canonical, "title", "Untitled finding"),
        severity_class: match severity.as_str() {
            "critical" | "high" | "medium" | "low" | "info" => severity.clone(),
            _ => "unknown".to_owned(),
        },
        severity,
        state: finding.triage.current_state.clone(),
        seen: finding.seen_count,
    }
}

fn job_row(job: JobViewV1) -> JobRow {
    let terminal = matches!(job.state.as_str(), "completed" | "failed" | "cancelled");
    let degraded =
        if job.progress.failed_modules.is_empty() && job.progress.skipped_modules.is_empty() {
            "Complete coverage".to_owned()
        } else {
            format!(
                "Degraded: {} failed, {} skipped",
                job.progress.failed_modules.len(),
                job.progress.skipped_modules.len()
            )
        };
    JobRow {
        id: job.id.to_string(),
        state: job.state,
        target: job.target,
        profile: job.profile,
        progress: format!(
            "{} / {} modules · {} findings",
            job.progress.completed_modules.len(),
            job.progress.total_modules,
            job.progress.finding_count
        ),
        degraded,
        terminal,
    }
}

fn json_text(value: &serde_json::Value, key: &str, fallback: &str) -> String {
    value.get(key).and_then(serde_json::Value::as_str).unwrap_or(fallback).to_owned()
}

fn pretty_json(value: &impl serde::Serialize) -> Result<String> {
    serde_json::to_string_pretty(value).context("failed to encode validated console data")
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() { "None".to_owned() } else { values.join(", ") }
}

fn map_summary(values: &std::collections::BTreeMap<String, u32>) -> String {
    if values.is_empty() {
        "No triage states".to_owned()
    } else {
        values.iter().map(|(key, value)| format!("{key}: {value}")).collect::<Vec<_>>().join(" · ")
    }
}

fn page_notice<T>(page: &PageV1<T>) -> String {
    let suffix =
        if page.next_cursor.is_some() { "more available" } else { "complete bounded page" };
    format!("{} shown · {suffix}", page.items.len())
}
