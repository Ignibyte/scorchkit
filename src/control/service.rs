//! One provider-neutral application service for control commands and queries.

#[cfg(feature = "storage")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
#[cfg(feature = "storage")]
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
#[cfg(feature = "storage")]
use futures_util::TryStreamExt;
#[cfg(feature = "storage")]
use sqlx::PgPool;
#[cfg(feature = "storage")]
use url::Url;
use uuid::Uuid;

use super::journal::{ControlEventJournal, JournaledJobStore};
use crate::config::AppConfig;
use crate::engine::error::ScorchError;
use crate::engine::observation::{redact_text, redact_url};
use crate::engine::policy::{Capability, EffectClass, Engagement, PolicyTarget};
use crate::runner::job::{DastJobRequest, InMemoryJobStore, JobStore, ScanJob, ScanJobService};
#[cfg(feature = "storage")]
use crate::storage::jobs::PostgresJobStore;
use crate::webhooks::WebhookService;
#[cfg(test)]
use scorchkit_control::ConfigPatchV1;
use scorchkit_control::{
    description_v1, resolve_configuration, ConfigurationResolutionRequestV1, ControlCommandV1,
    ControlErrorCodeV1, ControlErrorV1, ControlEventBatchV1, ControlOperationV1,
    ControlPrincipalKindV1, ControlPrincipalV1, ControlQueryV1, ControlRequestV1,
    ControlResponseOutcomeV1, ControlResponseV1, ControlResultV1, ControlTargetKindV1,
    EventCursorV1, JobProgressViewV1, JobViewV1, ModelReadinessViewV1, ModuleViewV1, PageRequestV1,
    PageV1, ResolvedConfigurationV1, CONTROL_API_SCHEMA_V1,
};

const MAX_CONTROL_RECOVERY_CANDIDATES: usize = 1_000;
#[cfg(feature = "storage")]
use scorchkit_control::{
    EvidenceViewV1, FindingCorrelationFacetV1, FindingTriageSubjectViewV1, FindingTriageViewV1,
    FindingViewV1, ProjectReportViewV1, ProjectViewV1, TargetViewV1,
};

#[derive(Clone)]
struct VerifiedControlPrincipal {
    projection: ControlPrincipalV1,
}

#[cfg(feature = "storage")]
struct TransitionFindingInput {
    finding_id: Uuid,
    state: String,
    reason: String,
    evidence_ids: Vec<String>,
    model_analysis_identity: Option<String>,
}

#[cfg(feature = "storage")]
struct FindingSuppressionInput {
    finding_id: Uuid,
    scope: String,
    reason: String,
    expires_at: Option<chrono::DateTime<Utc>>,
    review_at: Option<chrono::DateTime<Utc>>,
}

#[cfg(feature = "storage")]
struct FindingCorrelationInput {
    finding_id: Uuid,
    contributing_finding_ids: Vec<Uuid>,
    evidence_ids: Vec<String>,
    facets: Vec<FindingCorrelationFacetV1>,
    explanation: String,
}

impl VerifiedControlPrincipal {
    fn local(config: &AppConfig) -> Self {
        Self {
            projection: ControlPrincipalV1 {
                kind: ControlPrincipalKindV1::LocalProcess,
                subject: "local-scorchkit-process".to_string(),
                engagement_id: config.engagement.as_ref().map(|engagement| engagement.id),
            },
        }
    }

    #[cfg(any(feature = "control-api", feature = "mcp"))]
    const fn authenticated(subject: String, engagement_id: Uuid) -> Self {
        Self {
            projection: ControlPrincipalV1 {
                kind: ControlPrincipalKindV1::AuthenticatedBearer,
                subject,
                engagement_id: Some(engagement_id),
            },
        }
    }
}

/// The single composed application-service boundary used by all control adapters.
#[derive(Clone)]
pub struct ControlService {
    config: Arc<AppConfig>,
    jobs: ScanJobService,
    journal: Arc<ControlEventJournal>,
    #[cfg(feature = "storage")]
    pool: Option<PgPool>,
}

impl std::fmt::Debug for ControlService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlService")
            .field("database_available", &self.database_available())
            .finish_non_exhaustive()
    }
}

impl ControlService {
    /// Build a process-local service with no durable project storage.
    #[must_use]
    pub fn in_memory(config: Arc<AppConfig>) -> Self {
        let store: Arc<dyn JobStore> = Arc::new(InMemoryJobStore::new());
        Self::from_parts(config, store, None, None)
    }

    /// Build a persistent service over one already-migrated pool.
    #[cfg(feature = "storage")]
    #[must_use]
    pub fn persistent(
        config: Arc<AppConfig>,
        pool: PgPool,
        webhooks: Option<Arc<WebhookService>>,
    ) -> Self {
        let store: Arc<dyn JobStore> = Arc::new(PostgresJobStore::new(pool.clone()));
        Self::from_parts(config, store, Some(pool), webhooks)
    }

    fn from_parts(
        config: Arc<AppConfig>,
        store: Arc<dyn JobStore>,
        #[cfg(feature = "storage")] pool: Option<PgPool>,
        #[cfg(not(feature = "storage"))] _pool: Option<()>,
        webhooks: Option<Arc<WebhookService>>,
    ) -> Self {
        let journal = Arc::new(ControlEventJournal::new(
            config.control_api.max_journal_events,
            config.control_api.max_event_bytes,
        ));
        let store: Arc<dyn JobStore> =
            Arc::new(JournaledJobStore::new(store, Arc::clone(&journal)));
        let mut jobs = ScanJobService::new(Arc::clone(&config), store);
        if let Some(webhooks) = webhooks {
            jobs = jobs.with_webhooks(webhooks);
        }
        Self {
            config,
            jobs,
            journal,
            #[cfg(feature = "storage")]
            pool,
        }
    }

    /// Execute as the current local process.
    pub async fn execute_local(&self, request: ControlRequestV1) -> ControlResponseV1 {
        self.execute(VerifiedControlPrincipal::local(&self.config), request).await
    }

    /// Execute for an identity established by an authenticated transport adapter.
    #[cfg(any(feature = "control-api", feature = "mcp"))]
    pub(crate) async fn execute_authenticated(
        &self,
        subject: String,
        engagement_id: Uuid,
        request: ControlRequestV1,
    ) -> ControlResponseV1 {
        self.execute(VerifiedControlPrincipal::authenticated(subject, engagement_id), request).await
    }

    /// Borrow the ordered event journal for an authenticated streaming adapter.
    #[must_use]
    pub const fn journal(&self) -> &Arc<ControlEventJournal> {
        &self.journal
    }

    /// Whether durable project storage is configured.
    #[must_use]
    pub const fn database_available(&self) -> bool {
        #[cfg(feature = "storage")]
        {
            self.pool.is_some()
        }
        #[cfg(not(feature = "storage"))]
        {
            false
        }
    }

    /// Borrow the shared lifecycle adapter for background workers owned by another host adapter.
    #[cfg(feature = "storage")]
    #[must_use]
    pub(crate) const fn job_service(&self) -> &ScanJobService {
        &self.jobs
    }

    /// Exact engagement identity composed into this service.
    #[cfg(feature = "control-api")]
    #[must_use]
    pub(crate) fn configured_engagement_id(&self) -> Option<Uuid> {
        self.config.engagement.as_ref().map(|engagement| engagement.id)
    }

    async fn execute(
        &self,
        principal: VerifiedControlPrincipal,
        request: ControlRequestV1,
    ) -> ControlResponseV1 {
        let request_id = request.request_id;
        let result = self.dispatch(&principal, request).await;
        let response = ControlResponseV1 {
            schema_version: CONTROL_API_SCHEMA_V1.to_string(),
            request_id,
            principal: principal.projection,
            result: match result {
                Ok(result) => ControlResponseOutcomeV1::Success(Box::new(result)),
                Err(error) => ControlResponseOutcomeV1::Error(error),
            },
        };
        self.enforce_response_bound(response)
    }

    async fn dispatch(
        &self,
        principal: &VerifiedControlPrincipal,
        request: ControlRequestV1,
    ) -> Result<ControlResultV1, ControlErrorV1> {
        request.validate()?;
        self.verify_principal_binding(principal, request.engagement_id)?;
        match request.operation {
            ControlOperationV1::Query(query) => self.query(principal, *query).await,
            ControlOperationV1::Command(command) => self.command(principal, command).await,
        }
    }

    async fn query(
        &self,
        principal: &VerifiedControlPrincipal,
        query: ControlQueryV1,
    ) -> Result<ControlResultV1, ControlErrorV1> {
        match query {
            ControlQueryV1::Describe => description_v1().map(ControlResultV1::Description),
            ControlQueryV1::ResolveConfiguration(request) => {
                self.resolve_configuration(principal, *request).map(ControlResultV1::Configuration)
            }
            ControlQueryV1::GetEngagement => {
                let engagement = self.require_engagement()?;
                engagement_view(engagement).map(ControlResultV1::Engagement)
            }
            ControlQueryV1::GetModelReadiness => Ok(ControlResultV1::ModelReadiness(
                crate::model_analysis::model_readiness(&self.config.model_analysis)
                    .into_iter()
                    .map(model_readiness_view)
                    .collect(),
            )),
            ControlQueryV1::ListJobs { page } => {
                self.list_jobs(page).await.map(ControlResultV1::Jobs)
            }
            ControlQueryV1::GetJob { id } => self
                .jobs
                .get(id)
                .await
                .map_err(control_error)
                .and_then(|job| job_view(&job))
                .map(ControlResultV1::Job),
            ControlQueryV1::ListModules { family, page } => {
                let modules = module_views(&self.config)?;
                paginate_modules(
                    modules,
                    family.as_deref(),
                    &page,
                    self.config.control_api.default_page_size,
                )
                .map(ControlResultV1::Modules)
            }
            ControlQueryV1::ReadEvents { cursor } => {
                self.read_events(cursor).map(ControlResultV1::Events)
            }
            #[cfg(feature = "storage")]
            ControlQueryV1::ListProjects { page } => {
                self.list_projects(page).await.map(ControlResultV1::Projects)
            }
            #[cfg(feature = "storage")]
            ControlQueryV1::GetProject { id } => {
                self.get_project(id).await.map(ControlResultV1::Project)
            }
            #[cfg(feature = "storage")]
            ControlQueryV1::ListTargets { project_id, page } => {
                self.list_targets(project_id, page).await.map(ControlResultV1::Targets)
            }
            #[cfg(feature = "storage")]
            ControlQueryV1::ListFindings { project_id, page } => {
                self.list_findings(project_id, page).await.map(ControlResultV1::Findings)
            }
            #[cfg(feature = "storage")]
            ControlQueryV1::GetFinding { id } => {
                self.get_finding(id).await.map(ControlResultV1::Finding)
            }
            #[cfg(feature = "storage")]
            ControlQueryV1::ListEvidence { finding_id, page } => {
                self.list_evidence(finding_id, page).await.map(ControlResultV1::Evidence)
            }
            #[cfg(feature = "storage")]
            ControlQueryV1::GetProjectReport { project_id } => {
                self.project_report(project_id).await.map(ControlResultV1::Report)
            }
            #[cfg(not(feature = "storage"))]
            ControlQueryV1::ListProjects { .. }
            | ControlQueryV1::GetProject { .. }
            | ControlQueryV1::ListTargets { .. }
            | ControlQueryV1::ListFindings { .. }
            | ControlQueryV1::GetFinding { .. }
            | ControlQueryV1::ListEvidence { .. }
            | ControlQueryV1::GetProjectReport { .. } => Err(storage_unavailable()),
        }
    }

    async fn command(
        &self,
        principal: &VerifiedControlPrincipal,
        command: ControlCommandV1,
    ) -> Result<ControlResultV1, ControlErrorV1> {
        let engagement = self.require_bound_engagement(principal)?;
        #[cfg(feature = "storage")]
        let command = match command {
            command @ (ControlCommandV1::TransitionFinding { .. }
            | ControlCommandV1::CreateFindingSuppression { .. }
            | ControlCommandV1::RecordFindingCorrelation { .. }) => {
                return self.finding_triage_command(principal, engagement, command).await;
            }
            command => command,
        };
        match command {
            ControlCommandV1::StartJob { target, profile, modules, skip } => {
                let target = canonical_new_control_web_target(&target)?;
                let request = DastJobRequest::new(target, profile, engagement.clone())
                    .with_modules(modules)
                    .with_skip(skip);
                let job = self.jobs.submit(request).await.map_err(control_error)?;
                let id = job.id;
                let jobs = self.jobs.clone();
                tokio::spawn(async move {
                    if let Err(error) = jobs.run(id).await {
                        tracing::warn!(
                            event = "control.job.background_failed",
                            job_id = %id,
                            error = %redact_text(&error.to_string()),
                            "control job execution failed"
                        );
                    }
                });
                job_view(&job).map(ControlResultV1::Job)
            }
            ControlCommandV1::CancelJob { id } => {
                let current = self.jobs.get(id).await.map_err(control_error)?;
                authorize_job_cancellation(engagement, &current)?;
                self.jobs
                    .cancel(id)
                    .await
                    .map_err(control_error)
                    .and_then(|job| job_view(&job))
                    .map(ControlResultV1::Job)
            }
            ControlCommandV1::ResumeJob { id } => {
                let current = self.jobs.get(id).await.map_err(control_error)?;
                validate_resumable_job_target(&current)?;
                authorize_job_target(
                    engagement,
                    &current,
                    profile_effect(&current.request.profile)?,
                )?;
                self.jobs
                    .resume(id)
                    .await
                    .map_err(control_error)
                    .and_then(|job| job_view(&job))
                    .map(ControlResultV1::Job)
            }
            ControlCommandV1::RecoverJobs => self.recover_jobs(engagement).await,
            #[cfg(feature = "storage")]
            ControlCommandV1::TransitionFinding { .. }
            | ControlCommandV1::CreateFindingSuppression { .. }
            | ControlCommandV1::RecordFindingCorrelation { .. } => unreachable!(),
            #[cfg(feature = "storage")]
            ControlCommandV1::CreateProject { name, description } => self
                .create_project(engagement, &name, &description)
                .await
                .map(ControlResultV1::Project),
            #[cfg(feature = "storage")]
            ControlCommandV1::DeleteProject { id } => {
                self.delete_project(engagement, id).await.map(|changed| {
                    ControlResultV1::Acknowledged { changed, affected: u32::from(changed) }
                })
            }
            #[cfg(feature = "storage")]
            ControlCommandV1::AddTarget { project_id, url, label } => self
                .add_target(engagement, project_id, &url, &label)
                .await
                .map(ControlResultV1::Target),
            #[cfg(feature = "storage")]
            ControlCommandV1::RemoveTarget { project_id, target_id } => {
                self.remove_target(engagement, project_id, target_id).await.map(|changed| {
                    ControlResultV1::Acknowledged { changed, affected: u32::from(changed) }
                })
            }
            #[cfg(not(feature = "storage"))]
            ControlCommandV1::CreateProject { .. }
            | ControlCommandV1::DeleteProject { .. }
            | ControlCommandV1::AddTarget { .. }
            | ControlCommandV1::RemoveTarget { .. }
            | ControlCommandV1::TransitionFinding { .. }
            | ControlCommandV1::CreateFindingSuppression { .. }
            | ControlCommandV1::RecordFindingCorrelation { .. } => Err(storage_unavailable()),
        }
    }

    #[cfg(feature = "storage")]
    async fn finding_triage_command(
        &self,
        principal: &VerifiedControlPrincipal,
        engagement: &Engagement,
        command: ControlCommandV1,
    ) -> Result<ControlResultV1, ControlErrorV1> {
        let finding = match command {
            ControlCommandV1::TransitionFinding {
                finding_id,
                state,
                reason,
                evidence_ids,
                model_analysis_identity,
            } => {
                self.transition_finding(
                    principal,
                    engagement,
                    TransitionFindingInput {
                        finding_id,
                        state,
                        reason,
                        evidence_ids,
                        model_analysis_identity,
                    },
                )
                .await?
            }
            ControlCommandV1::CreateFindingSuppression {
                finding_id,
                scope,
                reason,
                expires_at,
                review_at,
            } => {
                self.create_finding_suppression(
                    principal,
                    engagement,
                    FindingSuppressionInput { finding_id, scope, reason, expires_at, review_at },
                )
                .await?
            }
            ControlCommandV1::RecordFindingCorrelation {
                finding_id,
                contributing_finding_ids,
                evidence_ids,
                facets,
                explanation,
            } => {
                self.record_finding_correlation(
                    principal,
                    engagement,
                    FindingCorrelationInput {
                        finding_id,
                        contributing_finding_ids,
                        evidence_ids,
                        facets,
                        explanation,
                    },
                )
                .await?
            }
            _ => unreachable!(),
        };
        Ok(ControlResultV1::Finding(finding))
    }

    fn verify_principal_binding(
        &self,
        principal: &VerifiedControlPrincipal,
        requested_engagement: Option<Uuid>,
    ) -> Result<(), ControlErrorV1> {
        if let Some(requested) = requested_engagement {
            if principal.projection.engagement_id != Some(requested) {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::PrincipalBindingMismatch,
                    "control principal is not bound to the requested engagement",
                ));
            }
            let current = self.require_engagement()?;
            if current.id != requested {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::EngagementUnavailable,
                    "requested control engagement is not the active engagement",
                ));
            }
        }
        Ok(())
    }

    fn require_engagement(&self) -> Result<&Engagement, ControlErrorV1> {
        let engagement = self.config.engagement.as_ref().ok_or_else(|| {
            ControlErrorV1::new(
                ControlErrorCodeV1::EngagementUnavailable,
                "control operation requires an active engagement",
            )
        })?;
        if !engagement.enabled {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::EngagementUnavailable,
                "control engagement is disabled",
            ));
        }
        if engagement.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::EngagementUnavailable,
                "control engagement is expired",
            ));
        }
        Ok(engagement)
    }

    fn require_bound_engagement(
        &self,
        principal: &VerifiedControlPrincipal,
    ) -> Result<&Engagement, ControlErrorV1> {
        let engagement = self.require_engagement()?;
        if principal.projection.engagement_id != Some(engagement.id) {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::PrincipalBindingMismatch,
                "control principal is not bound to the active engagement",
            ));
        }
        Ok(engagement)
    }

    fn resolve_configuration(
        &self,
        principal: &VerifiedControlPrincipal,
        mut request: ConfigurationResolutionRequestV1,
    ) -> Result<ResolvedConfigurationV1, ControlErrorV1> {
        let engagement = self.require_bound_engagement(principal)?;
        validate_resolution_ceiling(&self.config, engagement, &mut request)?;
        resolve_configuration(
            request.ceiling,
            request.organization.as_ref(),
            request.project.as_ref(),
            request.run.as_ref(),
        )
    }

    fn read_events(&self, cursor: EventCursorV1) -> Result<ControlEventBatchV1, ControlErrorV1> {
        self.journal.replay(cursor)
    }

    async fn recover_jobs(
        &self,
        engagement: &Engagement,
    ) -> Result<ControlResultV1, ControlErrorV1> {
        authorize_control_state(engagement)?;
        let candidates = self
            .jobs
            .store()
            .list_recoverable_bounded(Utc::now(), MAX_CONTROL_RECOVERY_CANDIDATES.saturating_add(1))
            .await
            .map_err(control_error)?;
        if candidates.len() > MAX_CONTROL_RECOVERY_CANDIDATES {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::LimitExceeded,
                "recoverable job set exceeds the bounded 1000-job command limit",
            ));
        }
        for candidate in &candidates {
            authorize_job_cancellation(engagement, candidate)?;
        }
        let ids: Vec<_> = candidates.into_iter().map(|candidate| candidate.id).collect();
        let recovered = self.jobs.recover_interrupted_ids(&ids).await.map_err(control_error)?;
        Ok(ControlResultV1::Acknowledged {
            changed: !recovered.is_empty(),
            affected: u32::try_from(recovered.len()).map_err(|_| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::LimitExceeded,
                    "recovered job count exceeds the v1 result range",
                )
            })?,
        })
    }

    async fn list_jobs(&self, page: PageRequestV1) -> Result<PageV1<JobViewV1>, ControlErrorV1> {
        validate_page(&page, self.config.control_api.default_page_size)?;
        let cursor = page.cursor.as_deref().map(decode_uuid_cursor).transpose()?;
        let requested = usize::from(page.limit);
        let jobs = self
            .jobs
            .list_page(cursor, requested.saturating_add(1))
            .await
            .map_err(control_error)?;
        let has_more = jobs.len() > requested;
        let items = jobs
            .into_iter()
            .take(requested)
            .map(|job| job_view(&job))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor =
            has_more.then(|| items.last().map(|item| encode_uuid_cursor(item.id))).flatten();
        Ok(PageV1 { items, next_cursor })
    }

    fn enforce_response_bound(&self, mut response: ControlResponseV1) -> ControlResponseV1 {
        let oversized = serde_json::to_vec(&response).map_or(true, |serialized| {
            serialized.len() > self.config.control_api.max_response_bytes
        });
        if oversized {
            response.result = ControlResponseOutcomeV1::Error(ControlErrorV1::new(
                ControlErrorCodeV1::LimitExceeded,
                "control response exceeds the configured response limit",
            ));
        }
        response
    }

    #[cfg(feature = "storage")]
    async fn list_projects(
        &self,
        page: PageRequestV1,
    ) -> Result<PageV1<ProjectViewV1>, ControlErrorV1> {
        validate_page(&page, self.config.control_api.default_page_size)?;
        let cursor = page.cursor.as_deref().map(decode_uuid_cursor).transpose()?;
        let requested = usize::from(page.limit);
        let rows = crate::storage::projects::list_projects_page(
            self.require_pool()?,
            cursor,
            requested.saturating_add(1),
        )
        .await
        .map_err(control_error)?;
        let has_more = rows.len() > requested;
        let items: Vec<_> = rows.into_iter().take(requested).map(project_view).collect();
        let next_cursor =
            has_more.then(|| items.last().map(|item| encode_uuid_cursor(item.id))).flatten();
        Ok(PageV1 { items, next_cursor })
    }

    #[cfg(feature = "storage")]
    async fn get_project(&self, id: Uuid) -> Result<ProjectViewV1, ControlErrorV1> {
        crate::storage::projects::get_project(self.require_pool()?, id)
            .await
            .map_err(control_error)?
            .map(project_view)
            .ok_or_else(|| not_found("project"))
    }

    #[cfg(feature = "storage")]
    async fn list_targets(
        &self,
        project_id: Uuid,
        page: PageRequestV1,
    ) -> Result<PageV1<TargetViewV1>, ControlErrorV1> {
        self.get_project(project_id).await?;
        validate_page(&page, self.config.control_api.default_page_size)?;
        let cursor = page.cursor.as_deref().map(decode_uuid_cursor).transpose()?;
        let requested = usize::from(page.limit);
        let rows = crate::storage::projects::list_targets_page(
            self.require_pool()?,
            project_id,
            cursor,
            requested.saturating_add(1),
        )
        .await
        .map_err(control_error)?;
        let has_more = rows.len() > requested;
        let items =
            rows.into_iter().take(requested).map(target_view).collect::<Result<Vec<_>, _>>()?;
        let next_cursor =
            has_more.then(|| items.last().map(|item| encode_uuid_cursor(item.id))).flatten();
        Ok(PageV1 { items, next_cursor })
    }

    #[cfg(feature = "storage")]
    async fn list_findings(
        &self,
        project_id: Uuid,
        page: PageRequestV1,
    ) -> Result<PageV1<FindingViewV1>, ControlErrorV1> {
        self.get_project(project_id).await?;
        validate_page(&page, self.config.control_api.default_page_size)?;
        let cursor = page.cursor.as_deref().map(decode_uuid_cursor).transpose()?;
        let requested = usize::from(page.limit);
        let rows = crate::storage::findings::list_validated_findings_page(
            self.require_pool()?,
            project_id,
            cursor,
            requested.saturating_add(1),
        )
        .await
        .map_err(control_error)?;
        let has_more = rows.len() > requested;
        let mut items = Vec::with_capacity(requested.min(rows.len()));
        for row in rows.into_iter().take(requested) {
            items.push(finding_view(row)?);
        }
        let next_cursor =
            has_more.then(|| items.last().map(|item| encode_uuid_cursor(item.id))).flatten();
        Ok(PageV1 { items, next_cursor })
    }

    #[cfg(feature = "storage")]
    async fn get_finding(&self, id: Uuid) -> Result<FindingViewV1, ControlErrorV1> {
        crate::storage::findings::get_validated_finding(self.require_pool()?, id)
            .await
            .map_err(control_error)?
            .map(finding_view)
            .transpose()?
            .ok_or_else(|| not_found("finding"))
    }

    #[cfg(feature = "storage")]
    async fn list_evidence(
        &self,
        finding_id: Uuid,
        page: PageRequestV1,
    ) -> Result<PageV1<EvidenceViewV1>, ControlErrorV1> {
        validate_page(&page, self.config.control_api.default_page_size)?;
        let cursor = page.cursor.as_deref().map(decode_uuid_cursor).transpose()?;
        let requested = usize::from(page.limit);
        let rows = crate::storage::findings::list_validated_evidence_page(
            self.require_pool()?,
            finding_id,
            cursor,
            requested.saturating_add(1),
        )
        .await
        .map_err(control_error)?;
        let has_more = rows.len() > requested;
        let items: Vec<_> = rows.into_iter().take(requested).map(evidence_view).collect();
        let next_cursor =
            has_more.then(|| items.last().map(|item| encode_uuid_cursor(item.id))).flatten();
        Ok(PageV1 { items, next_cursor })
    }

    #[cfg(feature = "storage")]
    async fn project_report(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectReportViewV1, ControlErrorV1> {
        let project = self.get_project(project_id).await?;
        let pool = self.require_pool()?;
        let target_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM project_targets WHERE project_id = $1")
                .bind(project_id)
                .fetch_one(pool)
                .await
                .map_err(|error| {
                    control_error(ScorchError::Database(format!("count report targets: {error}")))
                })?;
        let scan_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM scan_records WHERE project_id = $1")
                .bind(project_id)
                .fetch_one(pool)
                .await
                .map_err(|error| {
                    control_error(ScorchError::Database(format!("count report scans: {error}")))
                })?;
        let findings =
            crate::storage::findings::list_validated_findings_bounded(pool, project_id, 10_000)
                .await
                .map_err(control_error)?;
        let mut severity_counts = BTreeMap::new();
        let mut triage_state_counts = BTreeMap::new();
        let mut active_suppressed_count = 0_u32;
        let generated_at = Utc::now();
        for finding in &findings {
            let severity =
                finding.canonical.get("severity").and_then(serde_json::Value::as_str).ok_or_else(
                    || {
                        ControlErrorV1::new(
                            ControlErrorCodeV1::CanonicalProjectionMismatch,
                            "validated finding has no canonical severity",
                        )
                    },
                )?;
            *severity_counts.entry(severity.to_string()).or_insert(0_u32) += 1;
            let triage = finding.triage.as_ref().ok_or_else(|| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::CanonicalProjectionMismatch,
                    "validated report finding has no triage projection",
                )
            })?;
            let subject = finding.triage_subject.as_ref().ok_or_else(|| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::CanonicalProjectionMismatch,
                    "validated report finding has no triage subject",
                )
            })?;
            *triage_state_counts
                .entry(triage.history.current_state.as_str().to_string())
                .or_insert(0_u32) += 1;
            if !triage.active_suppression_ids(subject, generated_at).is_empty() {
                active_suppressed_count =
                    active_suppressed_count.checked_add(1).ok_or_else(|| {
                        ControlErrorV1::new(
                            ControlErrorCodeV1::LimitExceeded,
                            "active suppressed finding count exceeds v1",
                        )
                    })?;
            }
        }
        Ok(ProjectReportViewV1 {
            schema_version: "scorchkit.control.project-report/v1".to_string(),
            project,
            target_count: nonnegative_count(target_count, "target")?,
            scan_count: nonnegative_count(scan_count, "scan")?,
            finding_count: u32::try_from(findings.len()).map_err(|_| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::LimitExceeded,
                    "project finding count exceeds v1",
                )
            })?,
            severity_counts,
            triage_state_counts,
            active_suppressed_count,
            generated_at,
        })
    }

    #[cfg(feature = "storage")]
    async fn create_project(
        &self,
        engagement: &Engagement,
        name: &str,
        description: &str,
    ) -> Result<ProjectViewV1, ControlErrorV1> {
        authorize_control_state(engagement)?;
        crate::storage::projects::create_project(self.require_pool()?, name, description)
            .await
            .map_err(control_error)
            .map(project_view)
    }

    #[cfg(feature = "storage")]
    async fn delete_project(
        &self,
        engagement: &Engagement,
        id: Uuid,
    ) -> Result<bool, ControlErrorV1> {
        authorize_control_state(engagement)?;
        let mut transaction = self.require_pool()?.begin().await.map_err(|error| {
            control_error(ScorchError::Database(format!("begin project deletion: {error}")))
        })?;
        let locked =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM projects WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|error| {
                    control_error(ScorchError::Database(format!(
                        "lock project for deletion: {error}"
                    )))
                })?;
        if locked.is_none() {
            return Err(not_found("project"));
        }
        let mut targets = sqlx::query_scalar::<_, String>(
            "SELECT url FROM project_targets WHERE project_id = $1 ORDER BY id",
        )
        .bind(id)
        .fetch(&mut *transaction);
        while let Some(target) = targets.try_next().await.map_err(|error| {
            control_error(ScorchError::Database(format!("read project deletion targets: {error}")))
        })? {
            authorize_control_target(engagement, &target)?;
        }
        drop(targets);
        let deleted = sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                control_error(ScorchError::Database(format!("delete project: {error}")))
            })?
            .rows_affected()
            > 0;
        transaction.commit().await.map_err(|error| {
            control_error(ScorchError::Database(format!("commit project deletion: {error}")))
        })?;
        Ok(deleted)
    }

    #[cfg(feature = "storage")]
    async fn add_target(
        &self,
        engagement: &Engagement,
        project_id: Uuid,
        url: &str,
        label: &str,
    ) -> Result<TargetViewV1, ControlErrorV1> {
        authorize_control_state(engagement)?;
        let canonical_url = canonical_new_control_web_target(url)?;
        authorize_control_target(engagement, &canonical_url)?;
        self.get_project(project_id).await?;
        crate::storage::projects::add_target(
            self.require_pool()?,
            project_id,
            &canonical_url,
            label,
        )
        .await
        .map_err(control_error)
        .and_then(target_view)
    }

    #[cfg(feature = "storage")]
    async fn remove_target(
        &self,
        engagement: &Engagement,
        project_id: Uuid,
        target_id: Uuid,
    ) -> Result<bool, ControlErrorV1> {
        authorize_control_state(engagement)?;
        let pool = self.require_pool()?;
        let target = crate::storage::projects::get_target(pool, project_id, target_id)
            .await
            .map_err(control_error)?
            .ok_or_else(|| not_found("target"))?;
        authorize_control_target(engagement, &target.url)?;
        crate::storage::projects::remove_target(pool, project_id, target_id)
            .await
            .map_err(control_error)
    }

    #[cfg(feature = "storage")]
    async fn transition_finding(
        &self,
        principal: &VerifiedControlPrincipal,
        engagement: &Engagement,
        input: TransitionFindingInput,
    ) -> Result<FindingViewV1, ControlErrorV1> {
        self.authorize_finding_mutation(engagement, input.finding_id).await?;
        let next = input.state.parse::<scorchkit_core::FindingTriageState>().map_err(|_| {
            ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "finding triage state is not in the closed v1 vocabulary",
            )
        })?;
        crate::storage::triage::transition_finding(
            self.require_pool()?,
            crate::storage::triage::FindingTransitionWrite {
                finding_id: input.finding_id,
                next,
                actor: triage_actor(principal),
                reason: input.reason,
                evidence_ids: input.evidence_ids,
                model_analysis_identity: input.model_analysis_identity,
                observed_at: Utc::now(),
            },
        )
        .await
        .map_err(control_error)?;
        self.get_finding(input.finding_id).await
    }

    #[cfg(feature = "storage")]
    async fn create_finding_suppression(
        &self,
        principal: &VerifiedControlPrincipal,
        engagement: &Engagement,
        input: FindingSuppressionInput,
    ) -> Result<FindingViewV1, ControlErrorV1> {
        let finding = self.authorize_finding_mutation(engagement, input.finding_id).await?;
        let kind =
            input.scope.parse::<scorchkit_core::FindingSuppressionScopeKind>().map_err(|_| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "finding suppression scope is not in the closed v1 vocabulary",
                )
            })?;
        let subject = finding.triage_subject.as_ref().ok_or_else(|| {
            ControlErrorV1::new(
                ControlErrorCodeV1::CanonicalProjectionMismatch,
                "validated finding has no triage subject",
            )
        })?;
        crate::storage::triage::create_suppression(
            self.require_pool()?,
            crate::storage::triage::FindingSuppressionWrite {
                finding_id: input.finding_id,
                subject: subject.clone(),
                kind,
                actor: triage_actor(principal),
                reason: input.reason,
                created_at: Utc::now(),
                expires_at: input.expires_at,
                review_at: input.review_at,
            },
        )
        .await
        .map_err(control_error)?;
        self.get_finding(input.finding_id).await
    }

    #[cfg(feature = "storage")]
    async fn record_finding_correlation(
        &self,
        principal: &VerifiedControlPrincipal,
        engagement: &Engagement,
        input: FindingCorrelationInput,
    ) -> Result<FindingViewV1, ControlErrorV1> {
        let parent = self.authorize_finding_mutation(engagement, input.finding_id).await?;
        for contributor_id in &input.contributing_finding_ids {
            let contributor = self.authorize_finding_mutation(engagement, *contributor_id).await?;
            if contributor.row.project_id != parent.row.project_id {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "finding correlation contributors must belong to the parent project",
                ));
            }
        }
        let facets = input
            .facets
            .into_iter()
            .map(|facet| scorchkit_core::CorrelationKey::new(facet.namespace, facet.value))
            .collect();
        crate::storage::triage::record_correlation(
            self.require_pool()?,
            crate::storage::triage::FindingCorrelationWrite {
                finding_id: input.finding_id,
                contributing_finding_ids: input.contributing_finding_ids,
                evidence_ids: input.evidence_ids,
                facets,
                explanation: input.explanation,
                actor: triage_actor(principal),
                created_at: Utc::now(),
            },
        )
        .await
        .map_err(control_error)?;
        self.get_finding(input.finding_id).await
    }

    #[cfg(feature = "storage")]
    async fn authorize_finding_mutation(
        &self,
        engagement: &Engagement,
        finding_id: Uuid,
    ) -> Result<crate::storage::findings::ValidatedFinding, ControlErrorV1> {
        authorize_control_state(engagement)?;
        let finding =
            crate::storage::findings::get_validated_finding(self.require_pool()?, finding_id)
                .await
                .map_err(control_error)?
                .ok_or_else(|| not_found("finding"))?;
        let scan_target = sqlx::query_scalar::<_, String>(
            "SELECT target_url FROM scan_records WHERE id = $1 AND project_id = $2",
        )
        .bind(finding.row.scan_id)
        .bind(finding.row.project_id)
        .fetch_optional(self.require_pool()?)
        .await
        .map_err(|error| {
            control_error(ScorchError::Database(format!(
                "load finding authorization target: {error}"
            )))
        })?
        .ok_or_else(|| {
            ControlErrorV1::new(
                ControlErrorCodeV1::CanonicalProjectionMismatch,
                "validated finding has no originating scan target",
            )
        })?;
        authorize_finding_target(engagement, &finding, &scan_target)?;
        Ok(finding)
    }

    #[cfg(feature = "storage")]
    fn require_pool(&self) -> Result<&PgPool, ControlErrorV1> {
        self.pool.as_ref().ok_or_else(storage_unavailable)
    }
}

fn validate_resolution_ceiling(
    config: &AppConfig,
    engagement: &Engagement,
    request: &mut ConfigurationResolutionRequestV1,
) -> Result<(), ControlErrorV1> {
    let ceiling = &mut request.ceiling;
    let capabilities: BTreeSet<_> =
        ceiling.capabilities.iter().copied().map(control_capability).collect();
    let effects: BTreeSet<_> = ceiling.effects.iter().copied().map(control_effect).collect();
    if !capabilities.is_subset(&engagement.policy.capabilities)
        || !effects.is_subset(&engagement.policy.effects)
    {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::ConfigurationWidening,
            "configuration ceiling exceeds engagement capability or effect grants",
        ));
    }
    let capability = capabilities.iter().next().copied();
    let effect = effects.iter().next().copied();
    if !ceiling.targets.is_empty() && (capability.is_none() || effect.is_none()) {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            "a nonempty target ceiling requires at least one capability and effect",
        ));
    }
    for target in &mut ceiling.targets {
        let policy_target = match target.kind {
            ControlTargetKindV1::Web => {
                let canonical = canonical_new_control_web_target(&target.value)?;
                let policy_target = PolicyTarget::web(&canonical).map_err(|_| {
                    ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "configuration ceiling contains an invalid web target",
                    )
                })?;
                target.value = canonical;
                policy_target
            }
            ControlTargetKindV1::Source | ControlTargetKindV1::Artifact => {
                let path = PathBuf::from(&target.value);
                if !path.is_absolute() {
                    return Err(ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "configuration source and artifact targets must be absolute",
                    ));
                }
                let policy_target = PolicyTarget::code(&path).map_err(|_| {
                    ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "configuration source or artifact target cannot be resolved",
                    )
                })?;
                target.value = policy_target.to_string();
                policy_target
            }
        };
        engagement
            .authorize(
                policy_target,
                capability.ok_or_else(|| {
                    ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "configuration target has no capability",
                    )
                })?,
                effect.ok_or_else(|| {
                    ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "configuration target has no effect",
                    )
                })?,
            )
            .require()
            .map_err(|_| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::PolicyDenied,
                    "configuration target is outside the active engagement",
                )
            })?;
    }
    let known: BTreeSet<_> = module_views(config)?.into_iter().map(|module| module.id).collect();
    if ceiling.modules.iter().any(|module| !known.contains(module)) {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            "configuration ceiling contains an unknown application module",
        ));
    }
    let max_concurrent = usize::from(ceiling.budgets.max_concurrent_modules);
    if ceiling.budgets.timeout_seconds > config.scan.timeout_seconds
        || max_concurrent > config.scan.max_concurrent_modules
        || ceiling.budgets.max_result_bytes > config.control_api.max_response_bytes as u64
        || ceiling.budgets.max_event_bytes > config.control_api.max_event_bytes as u64
    {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::ConfigurationWidening,
            "configuration ceiling exceeds application hard limits",
        ));
    }
    Ok(())
}

const fn control_capability(capability: scorchkit_control::ControlCapabilityV1) -> Capability {
    match capability {
        scorchkit_control::ControlCapabilityV1::DastScan => Capability::DastScan,
        scorchkit_control::ControlCapabilityV1::CodeScan => Capability::CodeScan,
        scorchkit_control::ControlCapabilityV1::ExternalTool => Capability::ExternalTool,
        scorchkit_control::ControlCapabilityV1::ExtensionExecute => Capability::ExtensionExecute,
        scorchkit_control::ControlCapabilityV1::CredentialUse => Capability::CredentialUse,
        scorchkit_control::ControlCapabilityV1::Exploit => Capability::Exploit,
        scorchkit_control::ControlCapabilityV1::LocalState => Capability::LocalState,
        scorchkit_control::ControlCapabilityV1::ProviderRefresh => Capability::ProviderRefresh,
        scorchkit_control::ControlCapabilityV1::WebhookDelivery => Capability::WebhookDelivery,
    }
}

const fn control_effect(effect: scorchkit_control::ControlEffectV1) -> EffectClass {
    match effect {
        scorchkit_control::ControlEffectV1::Passive => EffectClass::Passive,
        scorchkit_control::ControlEffectV1::ActiveSafe => EffectClass::ActiveSafe,
        scorchkit_control::ControlEffectV1::Intrusive => EffectClass::Intrusive,
        scorchkit_control::ControlEffectV1::CredentialTest => EffectClass::CredentialTest,
        scorchkit_control::ControlEffectV1::Exploit => EffectClass::Exploit,
    }
}

fn engagement_view(
    engagement: &Engagement,
) -> Result<scorchkit_control::EngagementViewV1, ControlErrorV1> {
    let capabilities = engagement
        .policy
        .capabilities
        .iter()
        .copied()
        .map(enum_name)
        .collect::<Result<Vec<_>, _>>()?;
    let effects =
        engagement.policy.effects.iter().copied().map(enum_name).collect::<Result<Vec<_>, _>>()?;
    Ok(scorchkit_control::EngagementViewV1 {
        id: engagement.id,
        name: engagement.name.clone(),
        enabled: engagement.enabled,
        expires_at: engagement.expires_at,
        capabilities,
        effects,
    })
}

fn authorize_control_state(engagement: &Engagement) -> Result<(), ControlErrorV1> {
    if !engagement.policy.capabilities.contains(&Capability::LocalState)
        || !engagement.policy.effects.contains(&EffectClass::ActiveSafe)
    {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::PolicyDenied,
            "control local-state command requires local-state and active-safe grants",
        ));
    }
    Ok(())
}

#[cfg(feature = "storage")]
fn triage_actor(principal: &VerifiedControlPrincipal) -> scorchkit_core::TriageActor {
    scorchkit_core::TriageActor::new(
        scorchkit_core::TriageActorKind::Human,
        principal.projection.subject.clone(),
    )
}

#[cfg(feature = "storage")]
fn authorize_finding_target(
    engagement: &Engagement,
    finding: &crate::storage::findings::ValidatedFinding,
    scan_target: &str,
) -> Result<(), ControlErrorV1> {
    let record = finding
        .canonical
        .get("appsec")
        .cloned()
        .map(serde_json::from_value::<scorchkit_core::FindingRecordV2>)
        .transpose()
        .map_err(|_| {
            ControlErrorV1::new(
                ControlErrorCodeV1::CanonicalProjectionMismatch,
                "validated finding has an invalid canonical application-security record",
            )
        })?
        .ok_or_else(|| {
            ControlErrorV1::new(
                ControlErrorCodeV1::CanonicalProjectionMismatch,
                "validated finding has no canonical application-security record",
            )
        })?;
    let target = finding_location_policy_target(&record.location, scan_target)
        .or_else(|| policy_target_from_stored_value(scan_target))
        .ok_or_else(|| {
            ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "finding has no policy-addressable canonical target",
            )
        })?;
    engagement
        .authorize(target, Capability::LocalState, EffectClass::ActiveSafe)
        .require()
        .map(|_| ())
        .map_err(|_| {
            ControlErrorV1::new(
                ControlErrorCodeV1::PolicyDenied,
                "active engagement does not authorize the finding target",
            )
        })
}

#[cfg(feature = "storage")]
fn finding_location_policy_target(
    location: &scorchkit_core::ObservationLocation,
    scan_target: &str,
) -> Option<PolicyTarget> {
    match location {
        scorchkit_core::ObservationLocation::Runtime { uri, .. } => PolicyTarget::web(uri).ok(),
        scorchkit_core::ObservationLocation::Source { path, .. } => {
            code_policy_target(path, scan_target)
        }
        scorchkit_core::ObservationLocation::Artifact { uri, .. } => {
            policy_target_from_stored_value(uri)
        }
        scorchkit_core::ObservationLocation::Legacy { value } => {
            policy_target_from_stored_value(value)
        }
        scorchkit_core::ObservationLocation::Package { .. } => None,
    }
}

#[cfg(feature = "storage")]
fn code_policy_target(path: &str, scan_target: &str) -> Option<PolicyTarget> {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        return PolicyTarget::code(&path).ok();
    }
    let root = stored_code_path(scan_target)?;
    let candidate = if root.is_dir() { root.join(path) } else { root.parent()?.join(path) };
    PolicyTarget::code(&candidate).ok()
}

#[cfg(feature = "storage")]
fn policy_target_from_stored_value(value: &str) -> Option<PolicyTarget> {
    let value = value.trim();
    if let Ok(target) = PolicyTarget::web(value) {
        return Some(target);
    }
    if let Some(cloud) = value.strip_prefix("cloud://") {
        return (!cloud.is_empty()).then(|| PolicyTarget::cloud(cloud));
    }
    if ["aws:", "gcp:", "azure:", "k8s:"].iter().any(|prefix| value.starts_with(prefix)) {
        return Some(PolicyTarget::cloud(value));
    }
    if let Some(network) =
        value.strip_prefix("infra://").or_else(|| value.strip_prefix("network://"))
    {
        return (!network.is_empty()).then(|| PolicyTarget::network(network));
    }
    if let Some(path) = stored_code_path(value) {
        return PolicyTarget::code(&path).ok();
    }
    is_network_literal(value).then(|| PolicyTarget::network(value))
}

#[cfg(feature = "storage")]
fn stored_code_path(value: &str) -> Option<PathBuf> {
    let path = if value.starts_with("file://") {
        Url::parse(value).ok()?.to_file_path().ok()?
    } else {
        PathBuf::from(value)
    };
    path.is_absolute().then_some(path)
}

#[cfg(feature = "storage")]
fn is_network_literal(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
        || value.parse::<SocketAddr>().is_ok()
        || value.split_once('/').is_some_and(|(address, prefix)| {
            let Ok(address) = address.parse::<IpAddr>() else {
                return false;
            };
            let Ok(prefix) = prefix.parse::<u8>() else {
                return false;
            };
            match address {
                IpAddr::V4(_) => prefix <= 32,
                IpAddr::V6(_) => prefix <= 128,
            }
        })
}

#[cfg(feature = "storage")]
fn authorize_control_target(engagement: &Engagement, target: &str) -> Result<(), ControlErrorV1> {
    let target = PolicyTarget::web(target).map_err(|_| {
        ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            "control request contains an invalid web target",
        )
    })?;
    engagement
        .authorize(target, Capability::LocalState, EffectClass::ActiveSafe)
        .require()
        .map(|_| ())
        .map_err(|_| {
            ControlErrorV1::new(
                ControlErrorCodeV1::PolicyDenied,
                "active engagement does not authorize the control target",
            )
        })
}

fn canonical_new_control_web_target(target: &str) -> Result<String, ControlErrorV1> {
    let policy_target = PolicyTarget::web(target).map_err(|_| {
        ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            "control request contains an invalid web target",
        )
    })?;
    let PolicyTarget::Web(url) = &policy_target else {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::Internal,
            "control web target normalization failed",
        ));
    };
    let (_, redacted_fields) = redact_url(url.as_str());
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !redacted_fields.is_empty()
    {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::InvalidRequest,
            "control web targets cannot contain inline credentials, sensitive query values, or fragments",
        ));
    }
    Ok(policy_target.to_string())
}

fn authorize_job_target(
    engagement: &Engagement,
    job: &ScanJob,
    effect: EffectClass,
) -> Result<(), ControlErrorV1> {
    let target = PolicyTarget::web(&job.request.target).map_err(|_| {
        ControlErrorV1::new(
            ControlErrorCodeV1::CanonicalProjectionMismatch,
            "stored job target is invalid",
        )
    })?;
    engagement.authorize(target, Capability::DastScan, effect).require().map(|_| ()).map_err(|_| {
        ControlErrorV1::new(
            ControlErrorCodeV1::PolicyDenied,
            "active engagement no longer authorizes the job target",
        )
    })
}

fn validate_resumable_job_target(job: &ScanJob) -> Result<(), ControlErrorV1> {
    let canonical = canonical_new_control_web_target(&job.request.target).map_err(|_| {
        ControlErrorV1::new(
            ControlErrorCodeV1::CanonicalProjectionMismatch,
            "stored job target is not safe to resume",
        )
    })?;
    if canonical != job.request.target {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::CanonicalProjectionMismatch,
            "stored job target is not canonical",
        ));
    }
    Ok(())
}

fn authorize_job_cancellation(
    engagement: &Engagement,
    job: &ScanJob,
) -> Result<(), ControlErrorV1> {
    let target = PolicyTarget::web(&job.request.target).map_err(|_| {
        ControlErrorV1::new(
            ControlErrorCodeV1::CanonicalProjectionMismatch,
            "stored job target is invalid",
        )
    })?;
    engagement
        .authorize(target, Capability::LocalState, EffectClass::ActiveSafe)
        .require()
        .map(|_| ())
        .map_err(|_| {
            ControlErrorV1::new(
                ControlErrorCodeV1::PolicyDenied,
                "active engagement does not authorize cancellation for the job target",
            )
        })
}

fn profile_effect(profile: &str) -> Result<EffectClass, ControlErrorV1> {
    match profile {
        "quick" => Ok(EffectClass::ActiveSafe),
        "standard" | "thorough" => Ok(EffectClass::Intrusive),
        "pentest" => Ok(EffectClass::Exploit),
        _ => Err(ControlErrorV1::new(
            ControlErrorCodeV1::CanonicalProjectionMismatch,
            "stored job has an unknown profile",
        )),
    }
}

fn job_view(job: &ScanJob) -> Result<JobViewV1, ControlErrorV1> {
    Ok(JobViewV1 {
        id: job.id,
        root_job_id: job.root_job_id,
        parent_job_id: job.parent_job_id,
        attempt: job.attempt,
        state: job.state.as_str().to_string(),
        revision: job.revision,
        target: safe_stored_web_projection(&job.request.target, "job")?,
        profile: job.request.profile.clone(),
        progress: JobProgressViewV1 {
            total_modules: u32::try_from(job.progress.total_modules).map_err(|_| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::LimitExceeded,
                    "job total module count exceeds v1",
                )
            })?,
            active_modules: job.progress.active_modules.clone(),
            completed_modules: job.progress.completed_modules.clone(),
            skipped_modules: job.progress.skipped_modules.clone(),
            failed_modules: job.progress.failed_modules.clone(),
            finding_count: u32::try_from(job.progress.findings.len()).map_err(|_| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::LimitExceeded,
                    "job finding count exceeds v1",
                )
            })?,
        },
        error: job.error.as_deref().map(redact_text),
        created_at: job.created_at,
        updated_at: job.updated_at,
        finished_at: job.finished_at,
    })
}

fn module_views(config: &AppConfig) -> Result<Vec<ModuleViewV1>, ControlErrorV1> {
    let mut modules = Vec::new();
    for module in crate::runner::orchestrator::application_modules() {
        let descriptor = module.descriptor();
        modules.push(ModuleViewV1 {
            id: descriptor.id.to_string(),
            family: "web".to_string(),
            name: descriptor.name.to_string(),
            description: descriptor.description.to_string(),
            security_domain: enum_name(descriptor.adapter.security_domain)?,
            lifecycle_stage: enum_name(descriptor.adapter.lifecycle_stage)?,
            strongest_effect: enum_name(descriptor.adapter.strongest_effect)?,
            trust: enum_name(descriptor.adapter.trust)?,
            runtime: enum_name(descriptor.adapter.runtime)?,
            requires_external_tool: descriptor.requires_external_tool,
            required_tool: descriptor.required_tool.map(str::to_string),
        });
    }
    if !config.extensions.manifests.is_empty() {
        let engagement = config.engagement.as_ref().ok_or_else(|| {
            ControlErrorV1::new(
                ControlErrorCodeV1::PolicyDenied,
                "configured extension catalog has no active engagement",
            )
        })?;
        for manifest_path in &config.extensions.manifests {
            let loaded = crate::extension::LoadedExtension::load_for_catalog(
                &config.extensions,
                engagement,
                manifest_path,
            )
            .map_err(|_| {
                ControlErrorV1::new(
                    ControlErrorCodeV1::PolicyDenied,
                    "configured extension registration is invalid or unauthorized",
                )
            })?;
            if modules.iter().any(|module| module.id == loaded.manifest.id) {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::InvalidRequest,
                    "configured extension identity duplicates an application module",
                ));
            }
            modules.push(ModuleViewV1 {
                id: loaded.manifest.id,
                family: "web".to_string(),
                name: loaded.manifest.name,
                description: loaded.manifest.description,
                security_domain: enum_name(loaded.manifest.adapter.security_domain)?,
                lifecycle_stage: enum_name(loaded.manifest.adapter.lifecycle_stage)?,
                strongest_effect: enum_name(loaded.manifest.adapter.strongest_effect)?,
                trust: enum_name(scorchkit_core::AdapterTrust::ThirdParty)?,
                runtime: enum_name(scorchkit_core::AdapterRuntime::WasmWorker)?,
                requires_external_tool: false,
                required_tool: None,
            });
        }
    }
    for module in crate::runner::code_orchestrator::application_code_modules() {
        let descriptor = module.descriptor();
        modules.push(ModuleViewV1 {
            id: descriptor.id.to_string(),
            family: "code".to_string(),
            name: descriptor.name.to_string(),
            description: descriptor.description.to_string(),
            security_domain: enum_name(descriptor.adapter.security_domain)?,
            lifecycle_stage: enum_name(descriptor.adapter.lifecycle_stage)?,
            strongest_effect: enum_name(descriptor.adapter.strongest_effect)?,
            trust: enum_name(descriptor.adapter.trust)?,
            runtime: enum_name(descriptor.adapter.runtime)?,
            requires_external_tool: descriptor.requires_external_tool,
            required_tool: descriptor.required_tool.map(str::to_string),
        });
    }
    modules.sort_by(|left, right| (&left.family, &left.id).cmp(&(&right.family, &right.id)));
    Ok(modules)
}

fn enum_name(value: impl serde::Serialize) -> Result<String, ControlErrorV1> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(|| {
            ControlErrorV1::new(ControlErrorCodeV1::Internal, "failed to project a control enum")
        })
}

fn paginate_modules(
    modules: Vec<ModuleViewV1>,
    family: Option<&str>,
    page: &PageRequestV1,
    configured_maximum: u16,
) -> Result<PageV1<ModuleViewV1>, ControlErrorV1> {
    validate_page(page, configured_maximum)?;
    if let Some(family) = family {
        if !matches!(family, "web" | "code") {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "control module family must be web or code",
            ));
        }
    }
    let filtered: Vec<_> = modules
        .into_iter()
        .filter(|module| family.is_none_or(|family| module.family == family))
        .collect();
    let cursor = page.cursor.as_deref().map(decode_module_cursor).transpose()?;
    let start = cursor.map_or(Ok(0), |cursor| {
        filtered
            .iter()
            .position(|module| (module.family.as_str(), module.id.as_str()) == cursor)
            .map(|index| index + 1)
            .ok_or_else(|| invalid_cursor("module"))
    })?;
    let limit = usize::from(page.limit);
    let items: Vec<_> = filtered.iter().skip(start).take(limit).cloned().collect();
    let next_cursor = (start + items.len() < filtered.len())
        .then(|| items.last().map(encode_module_cursor))
        .flatten();
    Ok(PageV1 { items, next_cursor })
}

fn validate_page(page: &PageRequestV1, configured_maximum: u16) -> Result<(), ControlErrorV1> {
    page.validate()?;
    if page.limit > configured_maximum {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::LimitExceeded,
            format!("control page exceeds the configured {configured_maximum}-item limit"),
        ));
    }
    Ok(())
}

fn encode_uuid_cursor(id: Uuid) -> String {
    format!("v1:{id}")
}

fn decode_uuid_cursor(cursor: &str) -> Result<Uuid, ControlErrorV1> {
    cursor
        .strip_prefix("v1:")
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| invalid_cursor("resource"))
}

fn encode_module_cursor(module: &ModuleViewV1) -> String {
    format!("v1:{}:{}", module.family, module.id)
}

fn decode_module_cursor(cursor: &str) -> Result<(&str, &str), ControlErrorV1> {
    let value = cursor.strip_prefix("v1:").ok_or_else(|| invalid_cursor("module"))?;
    value.split_once(':').ok_or_else(|| invalid_cursor("module"))
}

fn invalid_cursor(resource: &str) -> ControlErrorV1 {
    ControlErrorV1::new(
        ControlErrorCodeV1::InvalidRequest,
        format!("control {resource} cursor is invalid or no longer present"),
    )
}

#[cfg(feature = "storage")]
fn project_view(project: crate::storage::models::Project) -> ProjectViewV1 {
    ProjectViewV1 {
        id: project.id,
        name: project.name,
        description: project.description,
        created_at: project.created_at,
        updated_at: project.updated_at,
    }
}

#[cfg(feature = "storage")]
fn target_view(
    target: crate::storage::models::ProjectTarget,
) -> Result<TargetViewV1, ControlErrorV1> {
    let url = safe_stored_web_projection(&target.url, "project target")?;
    Ok(TargetViewV1 {
        id: target.id,
        project_id: target.project_id,
        url,
        label: target.label,
        created_at: target.created_at,
    })
}

fn safe_stored_web_projection(target: &str, resource: &str) -> Result<String, ControlErrorV1> {
    let policy_target = PolicyTarget::web(target).map_err(|_| {
        ControlErrorV1::new(
            ControlErrorCodeV1::CanonicalProjectionMismatch,
            format!("stored {resource} is not a valid web URL"),
        )
    })?;
    let PolicyTarget::Web(mut url) = policy_target else {
        return Err(ControlErrorV1::new(
            ControlErrorCodeV1::Internal,
            "stored web target normalization failed",
        ));
    };
    if !url.username().is_empty() {
        url.set_username("REDACTED").map_err(|()| {
            ControlErrorV1::new(
                ControlErrorCodeV1::CanonicalProjectionMismatch,
                "stored web target user information cannot be redacted",
            )
        })?;
    }
    if url.password().is_some() {
        url.set_password(Some("REDACTED")).map_err(|()| {
            ControlErrorV1::new(
                ControlErrorCodeV1::CanonicalProjectionMismatch,
                "stored web target password cannot be redacted",
            )
        })?;
    }
    url.set_fragment(None);
    Ok(redact_url(url.as_str()).0)
}

#[cfg(feature = "storage")]
fn finding_view(
    finding: crate::storage::findings::ValidatedFinding,
) -> Result<FindingViewV1, ControlErrorV1> {
    let projection = finding.triage.ok_or_else(|| {
        ControlErrorV1::new(
            ControlErrorCodeV1::CanonicalProjectionMismatch,
            "validated finding has no triage projection",
        )
    })?;
    let subject = finding.triage_subject.ok_or_else(|| {
        ControlErrorV1::new(
            ControlErrorCodeV1::CanonicalProjectionMismatch,
            "validated finding has no triage subject",
        )
    })?;
    let active_suppression_ids = projection.active_suppression_ids(&subject, Utc::now());
    let transitions = projection
        .history
        .transitions
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            ControlErrorV1::new(
                ControlErrorCodeV1::Internal,
                "failed to serialize validated finding transitions",
            )
        })?;
    let correlations = projection
        .correlations
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            ControlErrorV1::new(
                ControlErrorCodeV1::Internal,
                "failed to serialize validated finding correlations",
            )
        })?;
    let suppressions = projection
        .suppressions
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            ControlErrorV1::new(
                ControlErrorCodeV1::Internal,
                "failed to serialize validated finding suppressions",
            )
        })?;
    let triage = FindingTriageViewV1 {
        schema: projection.schema,
        current_state: projection.history.current_state.as_str().to_string(),
        subject: FindingTriageSubjectViewV1 {
            project_identity: subject.project_identity,
            finding_identity: subject.finding_identity,
            rule_identity: subject.rule_identity,
            target_identity: subject.target_identity,
        },
        transitions,
        correlations,
        suppressions,
        active_suppression_ids,
    };
    Ok(FindingViewV1 {
        id: finding.row.id,
        project_id: finding.row.project_id,
        scan_id: finding.row.scan_id,
        fingerprint: finding.row.fingerprint,
        identity_schema: finding.row.identity_schema,
        stable_identity: finding.row.stable_identity,
        correlation_keys: finding.row.correlation_keys,
        status: finding.row.status,
        status_note: finding.row.status_note.as_deref().map(redact_text),
        seen_count: u32::try_from(finding.row.seen_count).map_err(|_| {
            ControlErrorV1::new(
                ControlErrorCodeV1::CanonicalProjectionMismatch,
                "validated finding has an invalid seen count",
            )
        })?,
        first_seen: finding.row.first_seen,
        last_seen: finding.row.last_seen,
        found_at: finding.row.found_at,
        canonical: finding.canonical,
        triage: Box::new(triage),
    })
}

fn model_readiness_view(readiness: scorchkit_core::ModelReadiness) -> ModelReadinessViewV1 {
    ModelReadinessViewV1 {
        role: readiness.role.as_str().to_string(),
        provider: readiness.provider,
        model: readiness.model,
        execution_location: readiness
            .execution_location
            .map(|location| location.as_str().to_string()),
        state: match readiness.state {
            scorchkit_core::ModelReadinessState::Disabled => "disabled",
            scorchkit_core::ModelReadinessState::Unconfigured => "unconfigured",
            scorchkit_core::ModelReadinessState::Invalid => "invalid",
            scorchkit_core::ModelReadinessState::Unavailable => "unavailable",
            scorchkit_core::ModelReadinessState::EvaluationRequired => "evaluation_required",
            scorchkit_core::ModelReadinessState::Ready => "ready",
        }
        .to_string(),
        reason: readiness.reason,
    }
}

#[cfg(feature = "storage")]
fn evidence_view(evidence: crate::storage::findings::ValidatedEvidence) -> EvidenceViewV1 {
    EvidenceViewV1 {
        id: evidence.row.id,
        finding_id: evidence.row.tracked_finding_id,
        scan_id: evidence.row.scan_id,
        evidence_schema: evidence.row.evidence_schema,
        evidence_identity: evidence.row.evidence_identity,
        canonical: evidence.canonical,
    }
}

#[cfg(feature = "storage")]
fn nonnegative_count(value: i64, resource: &str) -> Result<u32, ControlErrorV1> {
    u32::try_from(value).map_err(|_| {
        ControlErrorV1::new(
            ControlErrorCodeV1::CanonicalProjectionMismatch,
            format!("control {resource} count is outside the v1 range"),
        )
    })
}

#[cfg(feature = "storage")]
fn not_found(resource: &str) -> ControlErrorV1 {
    ControlErrorV1::new(ControlErrorCodeV1::NotFound, format!("control {resource} was not found"))
}

fn storage_unavailable() -> ControlErrorV1 {
    ControlErrorV1::new(
        ControlErrorCodeV1::StorageUnavailable,
        "control operation requires configured durable storage",
    )
}

fn control_error(error: ScorchError) -> ControlErrorV1 {
    let code = match &error {
        ScorchError::Policy(_) => ControlErrorCodeV1::PolicyDenied,
        ScorchError::InvalidTarget { .. } | ScorchError::Config(_) => {
            ControlErrorCodeV1::InvalidRequest
        }
        ScorchError::Job(message) if message.contains("cursor was not found") => {
            ControlErrorCodeV1::InvalidRequest
        }
        ScorchError::Job(message) if message.contains("was not found") => {
            ControlErrorCodeV1::NotFound
        }
        ScorchError::Job(_) => ControlErrorCodeV1::Conflict,
        ScorchError::Database(message)
            if message.starts_with("canonical projection mismatch:")
                || message.starts_with("canonical triage projection mismatch:") =>
        {
            ControlErrorCodeV1::CanonicalProjectionMismatch
        }
        ScorchError::Database(message) if message.contains("cursor was not found") => {
            ControlErrorCodeV1::InvalidRequest
        }
        ScorchError::Database(message) if message.contains("was not found") => {
            ControlErrorCodeV1::NotFound
        }
        ScorchError::Database(message) if message.contains("exceed") => {
            ControlErrorCodeV1::LimitExceeded
        }
        _ => ControlErrorCodeV1::Internal,
    };
    let message = match error {
        ScorchError::Policy(_) => "control operation was denied by engagement policy".to_string(),
        ScorchError::InvalidTarget { .. } => {
            "control request contains an invalid target".to_string()
        }
        ScorchError::Database(message)
            if message.starts_with("canonical projection mismatch:")
                || message.starts_with("canonical triage projection mismatch:") =>
        {
            "control durable canonical projection failed validation".to_string()
        }
        ScorchError::Job(message) | ScorchError::Database(message)
            if message.contains("cursor was not found") =>
        {
            "control resource cursor is invalid or no longer present".to_string()
        }
        ScorchError::Database(message) if message.contains("was not found") => {
            "control durable resource was not found".to_string()
        }
        ScorchError::Database(message) if message.contains("exceed") => {
            "control durable result exceeds its configured limit".to_string()
        }
        ScorchError::Database(_) => "control durable storage operation failed".to_string(),
        other => redact_text(&other.to_string()),
    };
    ControlErrorV1::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::EngagementPolicy;
    use crate::engine::scope::ScopeRule;
    use scorchkit_control::{
        ControlBudgetsV1, ControlCapabilityV1, ControlEffectV1, ControlResponseOutcomeV1,
        ControlTargetV1, ResolutionCeilingV1,
    };

    fn config() -> Arc<AppConfig> {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.test").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive)
            .allow_effect(EffectClass::ActiveSafe);
        Arc::new(AppConfig {
            engagement: Some(Engagement::new("control", policy)),
            ..AppConfig::default()
        })
    }

    fn resolution_ceiling(target: &str) -> ResolutionCeilingV1 {
        ResolutionCeilingV1 {
            targets: vec![ControlTargetV1 {
                kind: ControlTargetKindV1::Web,
                value: target.to_string(),
            }],
            capabilities: vec![ControlCapabilityV1::DastScan],
            effects: vec![ControlEffectV1::Passive],
            modules: vec!["headers".to_string()],
            budgets: ControlBudgetsV1 {
                timeout_seconds: 60,
                max_concurrent_modules: 1,
                max_result_bytes: 1_024,
                max_event_bytes: 1_024,
            },
        }
    }

    #[tokio::test]
    async fn description_is_available_without_an_engagement() {
        let service = ControlService::in_memory(Arc::new(AppConfig::default()));
        let response =
            service.execute_local(ControlRequestV1::query(ControlQueryV1::Describe, None)).await;
        assert!(matches!(response.result, ControlResponseOutcomeV1::Success(_)));
    }

    #[tokio::test]
    async fn model_readiness_is_complete_credential_safe_and_side_effect_free() {
        let service = ControlService::in_memory(config());
        let response = service
            .execute_local(ControlRequestV1::query(ControlQueryV1::GetModelReadiness, None))
            .await;
        let ControlResponseOutcomeV1::Success(result) = response.result else {
            panic!("model readiness failed");
        };
        let ControlResultV1::ModelReadiness(readiness) = *result else {
            panic!("unexpected readiness result");
        };
        assert_eq!(readiness.len(), 6);
        assert!(readiness.iter().all(|item| item.state == "disabled"));
        assert_eq!(readiness[0].role, "planning");
        assert_eq!(readiness[5].role, "verification");
        let encoded = serde_json::to_string(&readiness).expect("readiness JSON");
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("binary"));
        assert!(!encoded.contains("endpoint"));
    }

    #[tokio::test]
    async fn job_pages_follow_the_store_cursor_without_hiding_the_tail() {
        let config = config();
        let engagement = config.engagement.clone().expect("engagement");
        let service = ControlService::in_memory(config);
        for path in ["a", "b", "c"] {
            let job = ScanJob::new(
                DastJobRequest::new(
                    format!("https://example.test/{path}"),
                    "quick",
                    engagement.clone(),
                ),
                Uuid::new_v4(),
            );
            service.jobs.store().create(&job).await.expect("seed paged job");
        }

        let first = service
            .execute_local(ControlRequestV1::query(
                ControlQueryV1::ListJobs { page: PageRequestV1 { cursor: None, limit: 2 } },
                None,
            ))
            .await;
        let ControlResponseOutcomeV1::Success(first) = first.result else {
            panic!("first job page failed");
        };
        let ControlResultV1::Jobs(first) = *first else {
            panic!("unexpected first job page");
        };
        assert_eq!(first.items.len(), 2);
        let second = service
            .execute_local(ControlRequestV1::query(
                ControlQueryV1::ListJobs {
                    page: PageRequestV1 { cursor: first.next_cursor, limit: 2 },
                },
                None,
            ))
            .await;
        let ControlResponseOutcomeV1::Success(second) = second.result else {
            panic!("second job page failed");
        };
        let ControlResultV1::Jobs(second) = *second else {
            panic!("unexpected second job page");
        };
        assert_eq!(second.items.len(), 1);
        assert!(second.next_cursor.is_none());

        let missing = service
            .execute_local(ControlRequestV1::query(
                ControlQueryV1::ListJobs {
                    page: PageRequestV1 {
                        cursor: Some(encode_uuid_cursor(Uuid::new_v4())),
                        limit: 2,
                    },
                },
                None,
            ))
            .await;
        assert!(matches!(
            missing.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::InvalidRequest,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn command_engagement_mismatch_fails_before_job_creation() {
        let config = config();
        let service = ControlService::in_memory(Arc::clone(&config));
        let request = ControlRequestV1::command(
            ControlCommandV1::StartJob {
                target: "https://example.test/".to_string(),
                profile: "quick".to_string(),
                modules: Some(Vec::new()),
                skip: Vec::new(),
            },
            Uuid::new_v4(),
        );
        let response = service.execute_local(request).await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::PrincipalBindingMismatch,
                ..
            })
        ));
        assert!(service.jobs.list().await.expect("jobs").is_empty());
        assert_eq!(
            service
                .journal
                .replay(EventCursorV1 { after_sequence: 0, limit: 1 })
                .expect("empty")
                .events
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn secret_bearing_job_target_is_rejected_before_persistence() {
        let config = config();
        let engagement_id = config.engagement.as_ref().expect("engagement").id;
        let service = ControlService::in_memory(config);
        let sensitive = "job-input-value".repeat(2);
        let response = service
            .execute_local(ControlRequestV1::command(
                ControlCommandV1::StartJob {
                    target: format!("https://example.test/?access_token={sensitive}"),
                    profile: "quick".to_string(),
                    modules: None,
                    skip: Vec::new(),
                },
                engagement_id,
            ))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::InvalidRequest,
                ..
            })
        ));
        assert!(!serde_json::to_string(&response).expect("response JSON").contains(&sensitive));
        assert!(service.jobs.list().await.expect("jobs").is_empty());
    }

    #[tokio::test]
    async fn secret_bearing_stored_job_cannot_create_a_resume_successor() {
        let config = config();
        let engagement = config.engagement.clone().expect("engagement");
        let engagement_id = engagement.id;
        let store: Arc<dyn JobStore> = Arc::new(InMemoryJobStore::new());
        let sensitive = "resume-fixture-value".repeat(2);
        let queued = ScanJob::new(
            DastJobRequest::new(
                format!("https://example.test/?access_token={sensitive}"),
                "quick",
                engagement,
            ),
            Uuid::new_v4(),
        );
        store.create(&queued).await.expect("seed unsafe queued job");
        let mut interrupted = queued.clone();
        interrupted.state = crate::runner::job::ScanJobState::Interrupted;
        interrupted.revision = 1;
        interrupted.owner_id = None;
        interrupted.lease_expires_at = None;
        interrupted.updated_at = Utc::now();
        interrupted.finished_at = Some(interrupted.updated_at);
        assert!(store.compare_and_swap(0, &interrupted).await.expect("interrupt unsafe job"));
        let service = ControlService::from_parts(config, store, None, None);
        let response = service
            .execute_local(ControlRequestV1::command(
                ControlCommandV1::ResumeJob { id: interrupted.id },
                engagement_id,
            ))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::CanonicalProjectionMismatch,
                ..
            })
        ));
        assert!(!serde_json::to_string(&response).expect("response JSON").contains(&sensitive));
        assert_eq!(service.jobs.list().await.expect("jobs").len(), 1);
    }

    #[tokio::test]
    async fn target_capability_and_effect_denials_precede_job_persistence() {
        let policies = [
            EngagementPolicy::default()
                .allow_capability(Capability::DastScan)
                .allow_effect(EffectClass::ActiveSafe),
            EngagementPolicy::default()
                .allow_scope(ScopeRule::parse("example.test").expect("scope"))
                .allow_effect(EffectClass::ActiveSafe),
            EngagementPolicy::default()
                .allow_scope(ScopeRule::parse("example.test").expect("scope"))
                .allow_capability(Capability::DastScan),
        ];
        for policy in policies {
            let config = Arc::new(AppConfig {
                engagement: Some(Engagement::new("denied control", policy)),
                ..AppConfig::default()
            });
            let engagement_id = config.engagement.as_ref().expect("engagement").id;
            let service = ControlService::in_memory(config);
            let response = service
                .execute_local(ControlRequestV1::command(
                    ControlCommandV1::StartJob {
                        target: "https://example.test/".to_string(),
                        profile: "quick".to_string(),
                        modules: None,
                        skip: Vec::new(),
                    },
                    engagement_id,
                ))
                .await;
            assert!(matches!(
                response.result,
                ControlResponseOutcomeV1::Error(ControlErrorV1 {
                    code: ControlErrorCodeV1::PolicyDenied,
                    ..
                })
            ));
            assert!(service.jobs.list().await.expect("jobs").is_empty());
            assert!(service
                .journal
                .replay(EventCursorV1 { after_sequence: 0, limit: 1 })
                .expect("empty journal")
                .events
                .is_empty());
        }
    }

    #[tokio::test]
    async fn cancellation_requires_local_state_but_not_a_live_scan_grant() {
        async fn seeded_service(policy: EngagementPolicy) -> (ControlService, Uuid, Uuid) {
            let engagement = Engagement::new("cancel control", policy);
            let engagement_id = engagement.id;
            let config = Arc::new(AppConfig {
                engagement: Some(engagement.clone()),
                ..AppConfig::default()
            });
            let store: Arc<dyn JobStore> = Arc::new(InMemoryJobStore::new());
            let job = ScanJob::new(
                DastJobRequest::new("https://example.test/", "quick", engagement),
                Uuid::new_v4(),
            );
            store.create(&job).await.expect("seed queued job");
            let id = job.id;
            (ControlService::from_parts(config, store, None, None), engagement_id, id)
        }

        let local_state_policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.test").expect("scope"))
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::ActiveSafe);
        let (service, engagement_id, id) = seeded_service(local_state_policy).await;
        let response = service
            .execute_local(ControlRequestV1::command(
                ControlCommandV1::CancelJob { id },
                engagement_id,
            ))
            .await;
        assert!(matches!(response.result, ControlResponseOutcomeV1::Success(_)));
        assert_eq!(service.jobs.get(id).await.expect("cancelled job").state.as_str(), "cancelled");

        let scan_only_policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.test").expect("scope"))
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        let (service, engagement_id, id) = seeded_service(scan_only_policy).await;
        let response = service
            .execute_local(ControlRequestV1::command(
                ControlCommandV1::CancelJob { id },
                engagement_id,
            ))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::PolicyDenied,
                ..
            })
        ));
        assert_eq!(service.jobs.get(id).await.expect("queued job").state.as_str(), "queued");
    }

    #[tokio::test]
    async fn recovery_authorizes_the_complete_exact_candidate_set_before_mutation() {
        async fn seeded_recovery_service(
            policy: EngagementPolicy,
            targets: &[&str],
        ) -> (ControlService, Uuid, Vec<Uuid>) {
            let engagement = Engagement::new("recovery control", policy);
            let engagement_id = engagement.id;
            let config = Arc::new(AppConfig {
                engagement: Some(engagement.clone()),
                ..AppConfig::default()
            });
            let store: Arc<dyn JobStore> = Arc::new(InMemoryJobStore::new());
            let mut ids = Vec::new();
            for target in targets {
                let mut job = ScanJob::new(
                    DastJobRequest::new((*target).to_string(), "quick", engagement.clone()),
                    Uuid::new_v4(),
                );
                job.lease_expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
                store.create(&job).await.expect("seed recoverable job");
                ids.push(job.id);
            }
            (ControlService::from_parts(config, store, None, None), engagement_id, ids)
        }

        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("allowed.test").expect("scope"))
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::ActiveSafe);
        let (service, engagement_id, ids) = seeded_recovery_service(
            policy.clone(),
            &["https://allowed.test/", "https://denied.test/"],
        )
        .await;
        let response = service
            .execute_local(ControlRequestV1::command(ControlCommandV1::RecoverJobs, engagement_id))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::PolicyDenied,
                ..
            })
        ));
        for id in ids {
            assert_eq!(service.jobs.get(id).await.expect("unchanged job").state.as_str(), "queued");
        }

        let (service, engagement_id, ids) =
            seeded_recovery_service(policy, &["https://allowed.test/"]).await;
        let response = service
            .execute_local(ControlRequestV1::command(ControlCommandV1::RecoverJobs, engagement_id))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Success(result)
                if matches!(*result, ControlResultV1::Acknowledged { changed: true, affected: 1 })
        ));
        assert_eq!(
            service.jobs.get(ids[0]).await.expect("recovered job").state.as_str(),
            "interrupted"
        );
    }

    #[tokio::test]
    async fn recovery_rejects_an_oversized_candidate_set_before_mutation() {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.test").expect("scope"))
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::ActiveSafe);
        let engagement = Engagement::new("bounded recovery", policy);
        let engagement_id = engagement.id;
        let config =
            Arc::new(AppConfig { engagement: Some(engagement.clone()), ..AppConfig::default() });
        let store: Arc<dyn JobStore> = Arc::new(InMemoryJobStore::new());
        let mut first_id = None;
        for _ in 0..=1_000 {
            let mut job = ScanJob::new(
                DastJobRequest::new("https://example.test/", "quick", engagement.clone()),
                Uuid::new_v4(),
            );
            job.lease_expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
            first_id.get_or_insert(job.id);
            store.create(&job).await.expect("seed bounded recovery job");
        }
        let service = ControlService::from_parts(config, store, None, None);
        let response = service
            .execute_local(ControlRequestV1::command(ControlCommandV1::RecoverJobs, engagement_id))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::LimitExceeded,
                ..
            })
        ));
        assert_eq!(
            service.jobs.get(first_id.expect("first job")).await.expect("unchanged job").state,
            crate::runner::job::ScanJobState::Queued
        );
    }

    #[test]
    fn response_budget_includes_the_complete_versioned_envelope() {
        let mut bounded_config = (*config()).clone();
        bounded_config.control_api.max_response_bytes = 1_024;
        let service = ControlService::in_memory(Arc::new(bounded_config));
        let principal = VerifiedControlPrincipal::local(&service.config);
        let response = (1..1_024)
            .find_map(|length| {
                let mut job = ScanJob::new(
                    DastJobRequest::new(
                        "https://example.test/",
                        "quick",
                        service.config.engagement.clone().expect("engagement"),
                    ),
                    Uuid::new_v4(),
                );
                job.error = Some("x".repeat(length));
                let result = ControlResultV1::Job(job_view(&job).expect("job view"));
                let result_size = serde_json::to_vec(&result).expect("result JSON").len();
                let response = ControlResponseV1 {
                    schema_version: CONTROL_API_SCHEMA_V1.to_string(),
                    request_id: Uuid::new_v4(),
                    principal: principal.projection.clone(),
                    result: ControlResponseOutcomeV1::Success(Box::new(result)),
                };
                let response_size = serde_json::to_vec(&response).expect("response JSON").len();
                (result_size <= 1_024 && response_size > 1_024).then_some(response)
            })
            .expect("fixture whose payload fits while its envelope exceeds the bound");

        let response = service.enforce_response_bound(response);
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::LimitExceeded,
                ..
            })
        ));
        assert!(serde_json::to_vec(&response).expect("bounded response JSON").len() <= 1_024);
    }

    #[tokio::test]
    async fn configuration_ceiling_is_checked_against_policy_and_hard_limits() {
        let config = config();
        let engagement_id = config.engagement.as_ref().expect("engagement").id;
        let service = ControlService::in_memory(config);
        let ceiling = resolution_ceiling("https://example.test/");
        let request = ControlRequestV1::query(
            ControlQueryV1::ResolveConfiguration(Box::new(ConfigurationResolutionRequestV1 {
                ceiling,
                organization: Some(ConfigPatchV1 {
                    timeout_seconds: Some(30),
                    ..ConfigPatchV1::default()
                }),
                project: None,
                run: None,
            })),
            Some(engagement_id),
        );
        let response = service.execute_local(request).await;
        assert!(matches!(response.result, ControlResponseOutcomeV1::Success(_)));
    }

    #[tokio::test]
    async fn configuration_targets_are_canonical_and_secretless() {
        let config = config();
        let engagement_id = config.engagement.as_ref().expect("engagement").id;
        let service = ControlService::in_memory(config);
        let response = service
            .execute_local(ControlRequestV1::query(
                ControlQueryV1::ResolveConfiguration(Box::new(ConfigurationResolutionRequestV1 {
                    ceiling: resolution_ceiling("HTTPS://EXAMPLE.TEST:443/path"),
                    organization: None,
                    project: None,
                    run: None,
                })),
                Some(engagement_id),
            ))
            .await;
        let ControlResponseOutcomeV1::Success(result) = response.result else {
            panic!("canonical configuration was rejected");
        };
        let ControlResultV1::Configuration(resolved) = *result else {
            panic!("unexpected canonical configuration result");
        };
        assert_eq!(resolved.targets[0].value, "https://example.test/path");

        let sensitive = "sensitive-value".repeat(2);
        let secret_target = format!("https://example.test/?access_token={sensitive}");
        let response = service
            .execute_local(ControlRequestV1::query(
                ControlQueryV1::ResolveConfiguration(Box::new(ConfigurationResolutionRequestV1 {
                    ceiling: resolution_ceiling(&secret_target),
                    organization: None,
                    project: None,
                    run: None,
                })),
                Some(engagement_id),
            ))
            .await;
        assert!(matches!(
            &response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::InvalidRequest,
                ..
            })
        ));
        assert!(!serde_json::to_string(&response).expect("response JSON").contains(&sensitive));

        let response = service
            .execute_local(ControlRequestV1::command(
                ControlCommandV1::AddTarget {
                    project_id: Uuid::new_v4(),
                    url: format!("https://example.test/?access_token={sensitive}"),
                    label: "secret-bearing target".to_string(),
                },
                engagement_id,
            ))
            .await;
        assert!(matches!(
            &response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::InvalidRequest,
                ..
            })
        ));
        assert!(!serde_json::to_string(&response).expect("response JSON").contains(&sensitive));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn legacy_target_projection_redacts_userinfo_sensitive_query_and_fragment() {
        let sensitive = "fixture-value".repeat(2);
        let raw = format!(
            "https://{}:{}@example.test/?{}={}#{}",
            "fixture-user", sensitive, "access_token", sensitive, sensitive
        );
        let view = target_view(crate::storage::models::ProjectTarget {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            url: raw,
            label: "legacy".to_string(),
            created_at: Utc::now(),
        })
        .expect("safe target view");
        assert!(!view.url.contains("fixture-user"));
        assert!(!view.url.contains(&sensitive));
        assert!(!view.url.contains('#'));
        assert!(view.url.contains("REDACTED"));
    }

    #[test]
    fn legacy_job_projection_redacts_userinfo_sensitive_query_and_fragment() {
        let sensitive = "job-fixture-value".repeat(2);
        let target = format!(
            "https://{}:{}@example.test/?{}={}#{}",
            "fixture-user", sensitive, "access_token", sensitive, sensitive
        );
        let engagement = config().engagement.clone().expect("engagement");
        let job = ScanJob::new(DastJobRequest::new(target, "quick", engagement), Uuid::new_v4());
        let view = job_view(&job).expect("safe job view");
        assert!(!view.target.contains("fixture-user"));
        assert!(!view.target.contains(&sensitive));
        assert!(!view.target.contains('#'));
        assert!(view.target.contains("REDACTED"));
    }

    #[cfg(feature = "storage")]
    async fn persistent_control_fixture() -> Option<(PgPool, ControlService, Uuid)> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::storage::connect(&database_url).await.expect("connect control database");
        crate::storage::migrate::run_migrations(&pool).await.expect("migrate control database");
        let config = config();
        let engagement_id = config.engagement.as_ref().expect("engagement").id;
        let service = ControlService::persistent(config, pool.clone(), None);
        Some((pool, service, engagement_id))
    }

    #[cfg(feature = "storage")]
    async fn create_control_project(
        service: &ControlService,
        engagement_id: Uuid,
    ) -> ProjectViewV1 {
        let response = service
            .execute_local(ControlRequestV1::command(
                ControlCommandV1::CreateProject {
                    name: format!("control-service-{}", Uuid::new_v4()),
                    description: "persistent service fixture".to_string(),
                },
                engagement_id,
            ))
            .await;
        let ControlResponseOutcomeV1::Success(result) = response.result else {
            panic!("create project failed");
        };
        let ControlResultV1::Project(project) = *result else {
            panic!("unexpected project result");
        };
        project
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn persistent_crud_pages_and_reports_share_the_control_boundary() {
        let Some((pool, service, engagement_id)) = persistent_control_fixture().await else {
            return;
        };
        let project = create_control_project(&service, engagement_id).await;
        for (url, label) in
            [("HTTPS://EXAMPLE.TEST:443/a", "first"), ("https://example.test/b", "second")]
        {
            let response = service
                .execute_local(ControlRequestV1::command(
                    ControlCommandV1::AddTarget {
                        project_id: project.id,
                        url: url.to_string(),
                        label: label.to_string(),
                    },
                    engagement_id,
                ))
                .await;
            assert!(matches!(response.result, ControlResponseOutcomeV1::Success(_)));
        }
        let first = target_page(&service, engagement_id, project.id, None).await;
        assert_eq!(first.items.len(), 1);
        let second = target_page(&service, engagement_id, project.id, first.next_cursor).await;
        assert_eq!(second.items.len(), 1);
        assert_ne!(first.items[0].id, second.items[0].id);

        let response = service
            .execute_local(ControlRequestV1::query(
                ControlQueryV1::GetProjectReport { project_id: project.id },
                Some(engagement_id),
            ))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Success(result)
                if matches!(*result, ControlResultV1::Report(ProjectReportViewV1 {
                    target_count: 2, scan_count: 0, finding_count: 0, ..
                }))
        ));
        let response = service
            .execute_local(ControlRequestV1::command(
                ControlCommandV1::DeleteProject { id: project.id },
                engagement_id,
            ))
            .await;
        assert!(matches!(response.result, ControlResponseOutcomeV1::Success(_)));
        assert!(crate::storage::projects::get_project(&pool, project.id)
            .await
            .expect("read deleted project")
            .is_none());
    }

    #[cfg(feature = "storage")]
    async fn target_page(
        service: &ControlService,
        engagement_id: Uuid,
        project_id: Uuid,
        cursor: Option<String>,
    ) -> PageV1<TargetViewV1> {
        let response = service
            .execute_local(ControlRequestV1::query(
                ControlQueryV1::ListTargets {
                    project_id,
                    page: PageRequestV1 { cursor, limit: 1 },
                },
                Some(engagement_id),
            ))
            .await;
        let ControlResponseOutcomeV1::Success(result) = response.result else {
            panic!("target page failed");
        };
        let ControlResultV1::Targets(page) = *result else {
            panic!("unexpected target page");
        };
        page
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn persistent_deletion_rolls_back_when_any_target_is_denied() {
        let Some((pool, service, engagement_id)) = persistent_control_fixture().await else {
            return;
        };
        let denied = crate::storage::projects::create_project(
            &pool,
            &format!("control-denied-delete-{}", Uuid::new_v4()),
            "rollback fixture",
        )
        .await
        .expect("create denied-delete project");
        crate::storage::projects::add_target(
            &pool,
            denied.id,
            "https://denied.test/",
            "outside scope",
        )
        .await
        .expect("seed denied target");
        let response = service
            .execute_local(ControlRequestV1::command(
                ControlCommandV1::DeleteProject { id: denied.id },
                engagement_id,
            ))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ControlErrorV1 {
                code: ControlErrorCodeV1::PolicyDenied,
                ..
            })
        ));
        assert!(crate::storage::projects::get_project(&pool, denied.id)
            .await
            .expect("read retained project")
            .is_some());
        crate::storage::projects::delete_project(&pool, denied.id)
            .await
            .expect("delete denied-delete fixture");
    }

    #[cfg(feature = "storage")]
    #[test]
    fn stored_finding_targets_map_to_exact_policy_kinds() {
        let runtime = scorchkit_core::ObservationLocation::Runtime {
            uri: "https://example.test/path".to_string(),
            route: Some("/path".to_string()),
            parameter: None,
        };
        assert!(matches!(
            finding_location_policy_target(&runtime, "https://example.test/"),
            Some(PolicyTarget::Web(_))
        ));
        let source = scorchkit_core::ObservationLocation::Source {
            path: "src/lib.rs".to_string(),
            region: None,
        };
        assert!(matches!(
            finding_location_policy_target(&source, env!("CARGO_MANIFEST_DIR")),
            Some(PolicyTarget::Code(_))
        ));
        assert!(matches!(
            code_policy_target("src/lib.rs", env!("CARGO_MANIFEST_DIR")),
            Some(PolicyTarget::Code(_))
        ));
        let package = scorchkit_core::ObservationLocation::Package {
            ecosystem: "cargo".to_string(),
            name: "fixture".to_string(),
            version: Some("1.0.0".to_string()),
            manifest_path: None,
        };
        assert!(finding_location_policy_target(&package, "package@1.0.0").is_none());

        assert!(matches!(
            policy_target_from_stored_value("https://example.test/path"),
            Some(PolicyTarget::Web(_))
        ));
        assert_eq!(
            policy_target_from_stored_value("cloud://aws:123456789012"),
            Some(PolicyTarget::cloud("aws:123456789012"))
        );
        assert_eq!(
            policy_target_from_stored_value("infra://127.0.0.1:443"),
            Some(PolicyTarget::network("127.0.0.1:443"))
        );
        assert_eq!(
            policy_target_from_stored_value("2001:db8::1"),
            Some(PolicyTarget::network("2001:db8::1"))
        );
        assert!(matches!(
            policy_target_from_stored_value(env!("CARGO_MANIFEST_DIR")),
            Some(PolicyTarget::Code(_))
        ));
        assert!(policy_target_from_stored_value("package@1.2.3").is_none());
        assert!(is_network_literal("10.0.0.0/32"));
        assert!(!is_network_literal("10.0.0.0/33"));
        assert!(is_network_literal("2001:db8::/128"));
        assert!(!is_network_literal("2001:db8::/129"));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn finding_authorization_rejects_a_missing_canonical_application_record() {
        let config = config();
        let engagement = config.engagement.as_ref().expect("engagement");
        let now = Utc::now();
        let finding = crate::storage::findings::ValidatedFinding {
            row: crate::storage::models::TrackedFinding {
                id: Uuid::new_v4(),
                scan_id: Uuid::new_v4(),
                project_id: Uuid::new_v4(),
                fingerprint: "legacy".to_string(),
                identity_schema: "scorchkit.finding-identity/v2".to_string(),
                stable_identity: "a".repeat(64),
                correlation_keys: serde_json::json!([]),
                module_id: "fixture".to_string(),
                severity: "high".to_string(),
                title: "Fixture".to_string(),
                description: "Fixture".to_string(),
                affected_target: "https://example.test/".to_string(),
                evidence: None,
                remediation: None,
                owasp_category: None,
                cwe_id: Some(79),
                raw_finding: serde_json::json!({}),
                confidence: 1.0,
                first_seen: now,
                last_seen: now,
                seen_count: 1,
                status: "new".to_string(),
                triage_state: "needs_context".to_string(),
                status_note: None,
                found_at: now,
            },
            canonical: serde_json::json!({}),
            triage: None,
            triage_subject: None,
        };
        assert_eq!(
            authorize_finding_target(engagement, &finding, "https://example.test/")
                .expect_err("missing canonical appsec record")
                .code,
            ControlErrorCodeV1::CanonicalProjectionMismatch
        );
    }

    #[test]
    fn control_error_classification_and_safe_messages_are_exact() {
        let conflict = control_error(ScorchError::Job("already running".to_string()));
        assert_eq!(conflict.code, ControlErrorCodeV1::Conflict);
        assert!(conflict.message.contains("already running"));

        for prefix in [
            "canonical projection mismatch: fixture",
            "canonical triage projection mismatch: fixture",
        ] {
            let mismatch = control_error(ScorchError::Database(prefix.to_string()));
            assert_eq!(mismatch.code, ControlErrorCodeV1::CanonicalProjectionMismatch);
            assert_eq!(mismatch.message, "control durable canonical projection failed validation");
        }

        let internal = control_error(ScorchError::Database("driver detail".to_string()));
        assert_eq!(internal.code, ControlErrorCodeV1::Internal);
        assert_eq!(internal.message, "control durable storage operation failed");
    }

    #[test]
    fn module_inventory_is_sorted_application_only_and_unique() {
        let modules = module_views(&AppConfig::default()).expect("modules");
        assert!(!modules.is_empty());
        assert!(modules
            .windows(2)
            .all(|pair| { (&pair[0].family, &pair[0].id) < (&pair[1].family, &pair[1].id) }));
        assert!(modules.iter().all(|module| module.security_domain.starts_with("application_")));
        assert!(modules
            .iter()
            .all(|module| module.trust == "first_party" && module.runtime == "compiled"));
        assert_eq!(
            modules.iter().map(|module| &module.id).collect::<BTreeSet<_>>().len(),
            modules.len(),
            "control configuration identifies modules by globally unique IDs"
        );
    }
}
