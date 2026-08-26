//! Hard-cell composition, admission, RBAC, canonical preflight, and durable audit.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use scorchkit_config::TeamServiceConfig;
use scorchkit_control::{
    ControlCommandV1, ControlErrorCodeV1, ControlErrorV1, ControlOperationV1, ControlQueryV1,
    ControlRequestV1, ControlResponseOutcomeV1, TeamAuditEventV1, TeamAuditOutcomeV1,
    TeamControlResponseV1, TeamObjectKindV1, TeamObjectViewV1, TeamPermissionV1, TeamPrincipalV1,
    TeamRecoveryManifestV1, TeamRoleV1, TEAM_API_SCHEMA_V1,
};
use scorchkit_core::sha256_hex;
use sqlx::{Connection, PgConnection, PgPool, Row};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::auth::{authenticate_binding, PreparedBinding, PreparedCell, PreparedTeamService};
use super::object_store::TeamObjectStore;
use super::recovery::RecoveryInput;
use crate::config::AppConfig;
use crate::control::ControlService;
use crate::engine::error::{Result, ScorchError};
use crate::storage::webhooks::PostgresWebhookStore;
use crate::webhooks::WebhookService;

#[derive(Clone)]
pub struct TeamService {
    inner: Arc<TeamServiceInner>,
}

struct TeamServiceInner {
    config: TeamServiceConfig,
    bindings: Vec<PreparedBinding>,
    cells: HashMap<String, Arc<TeamCell>>,
}

impl std::fmt::Debug for TeamService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TeamService")
            .field("config", &self.inner.config)
            .field("cell_ids", &self.inner.cells.keys().collect::<BTreeSet<_>>())
            .field("binding_count", &self.inner.bindings.len())
            .finish()
    }
}

struct TeamCell {
    cell_id: String,
    organization_id: String,
    project_id: Uuid,
    engagement_id: Uuid,
    database_identity_sha256: String,
    role_service: ControlService,
    pool: PgPool,
    lease: Mutex<PgConnection>,
    objects: TeamObjectStore,
    max_active_jobs: u32,
    requests_per_minute: u32,
    rate_window: Mutex<VecDeque<(Uuid, Instant)>>,
    job_admission: Mutex<()>,
}

#[derive(Clone)]
pub struct TeamSession {
    principal: TeamPrincipalV1,
    cell: Arc<TeamCell>,
}

impl std::fmt::Debug for TeamSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TeamSession")
            .field("principal", &self.principal)
            .finish_non_exhaustive()
    }
}

impl TeamService {
    /// Resolve secrets, compose every isolated cell, and reject collisions before listening.
    ///
    /// # Errors
    ///
    /// Returns before listening when configuration, secret resolution, policy, filesystem,
    /// database, project, migration, or cell-identity preflight fails.
    pub async fn from_app_config(config: Arc<AppConfig>) -> Result<Self> {
        let team = config.team.as_ref().ok_or_else(|| {
            ScorchError::Config("team service requires an explicit [team] profile".to_string())
        })?;
        let prepared = PreparedTeamService::from_config(team)?;
        Self::from_prepared(config, prepared).await
    }

    async fn from_prepared(config: Arc<AppConfig>, prepared: PreparedTeamService) -> Result<Self> {
        validate_distinct_roots(&prepared.cells)?;
        let PreparedTeamService { config: team_config, cells: prepared_cells, bindings } = prepared;
        let mut cells = HashMap::with_capacity(prepared_cells.len());
        let mut database_identities = BTreeSet::new();
        for prepared_cell in prepared_cells {
            let cell = TeamCell::compose(&config, prepared_cell).await?;
            if !database_identities.insert(cell.database_identity_sha256.clone()) {
                return Err(ScorchError::Config(
                    "team cells resolve to the same live PostgreSQL database".to_string(),
                ));
            }
            let cell_id = cell.cell_id.clone();
            if cells.insert(cell_id, Arc::new(cell)).is_some() {
                return Err(ScorchError::Config("team cell identity collision".to_string()));
            }
        }
        Ok(Self { inner: Arc::new(TeamServiceInner { config: team_config, bindings, cells }) })
    }

    /// Authenticate one bearer without consulting request-controlled cell or role claims.
    #[must_use]
    pub fn authenticate(&self, bearer: &str) -> Option<TeamSession> {
        let binding = authenticate_binding(&self.inner.bindings, bearer)?;
        let cell = Arc::clone(self.inner.cells.get(&binding.cell_id)?);
        Some(TeamSession {
            principal: TeamPrincipalV1 {
                subject: binding.subject.clone(),
                organization_id: cell.organization_id.clone(),
                project_id: cell.project_id,
                cell_id: cell.cell_id.clone(),
                role: binding.role,
                engagement_id: cell.engagement_id,
            },
            cell,
        })
    }

    #[must_use]
    pub fn config(&self) -> &TeamServiceConfig {
        &self.inner.config
    }
}

impl TeamSession {
    #[must_use]
    pub const fn principal(&self) -> &TeamPrincipalV1 {
        &self.principal
    }

    pub async fn execute_control(&self, request: ControlRequestV1) -> TeamControlResponseV1 {
        let request_id = request.request_id;
        let result = self.execute_control_inner(&request).await;
        TeamControlResponseV1 {
            schema_version: TEAM_API_SCHEMA_V1.to_string(),
            request_id,
            principal: self.principal.clone(),
            result,
        }
    }

    async fn execute_control_inner(&self, request: &ControlRequestV1) -> ControlResponseOutcomeV1 {
        let action = control_action(&request.operation);
        if let Err(error) = self.cell.admit_request(request.request_id).await {
            return ControlResponseOutcomeV1::Error(error);
        }
        if let Err(error) = self.cell.verify_identity().await {
            let _ = self.audit(request.request_id, action, TeamAuditOutcomeV1::Failed).await;
            return ControlResponseOutcomeV1::Error(error);
        }
        if !self.principal.role.allows_control(&request.operation) {
            let error = denied("team role does not permit this control operation");
            let _ = self.audit(request.request_id, action, TeamAuditOutcomeV1::Denied).await;
            return ControlResponseOutcomeV1::Error(error);
        }
        let _job_admission = if consumes_job_capacity(&request.operation) {
            Some(self.cell.job_admission.lock().await)
        } else {
            None
        };
        if let Err(error) = self.cell.verify_operation_scope(&request.operation).await {
            let _ = self.audit(request.request_id, action, TeamAuditOutcomeV1::Denied).await;
            return ControlResponseOutcomeV1::Error(error);
        }
        let mutation = matches!(request.operation, ControlOperationV1::Command(_));
        if mutation
            && self.audit(request.request_id, action, TeamAuditOutcomeV1::Pending).await.is_err()
        {
            return ControlResponseOutcomeV1::Error(internal("team mutation audit is unavailable"));
        }
        let response = self
            .cell
            .role_service
            .execute_authenticated(
                self.principal.subject.clone(),
                self.principal.engagement_id,
                request.clone(),
            )
            .await;
        let outcome = match response.result {
            ControlResponseOutcomeV1::Success(result) => {
                if self
                    .audit(request.request_id, action, TeamAuditOutcomeV1::Succeeded)
                    .await
                    .is_err()
                {
                    return ControlResponseOutcomeV1::Error(internal(
                        "team terminal audit is unavailable; mutation outcome requires recovery",
                    ));
                }
                ControlResponseOutcomeV1::Success(result)
            }
            ControlResponseOutcomeV1::Error(error) => {
                let outcome = if matches!(
                    error.code,
                    ControlErrorCodeV1::PolicyDenied
                        | ControlErrorCodeV1::PrincipalBindingMismatch
                        | ControlErrorCodeV1::EngagementUnavailable
                ) {
                    TeamAuditOutcomeV1::Denied
                } else {
                    TeamAuditOutcomeV1::Failed
                };
                if self.audit(request.request_id, action, outcome).await.is_err() {
                    return ControlResponseOutcomeV1::Error(internal(
                        "team terminal audit is unavailable",
                    ));
                }
                ControlResponseOutcomeV1::Error(error)
            }
        };
        outcome
    }

    /// Authorize, audit, encrypt, and store one cell-local object.
    ///
    /// # Errors
    ///
    /// Returns a typed admission, identity, role, audit, or object-storage failure.
    pub async fn put_object(
        &self,
        request_id: Uuid,
        kind: TeamObjectKindV1,
        plaintext: &[u8],
    ) -> std::result::Result<TeamObjectViewV1, ControlErrorV1> {
        self.team_effect(
            request_id,
            "object.put",
            TeamPermissionV1::WriteObject,
            self.cell.objects.put(kind, plaintext),
        )
        .await
    }

    /// Authorize, audit, authenticate, and decrypt one cell-local object.
    ///
    /// # Errors
    ///
    /// Returns a typed admission, identity, role, audit, absence, expiry, or integrity failure.
    pub async fn read_object(
        &self,
        request_id: Uuid,
        object_id: &str,
    ) -> std::result::Result<(TeamObjectViewV1, zeroize::Zeroizing<Vec<u8>>), ControlErrorV1> {
        self.team_effect(
            request_id,
            "object.read",
            TeamPermissionV1::ReadObject,
            self.cell.objects.read(object_id),
        )
        .await
    }

    /// Re-encrypt one object under the cell's current write key.
    ///
    /// # Errors
    ///
    /// Returns a typed admission, identity, administrator-role, audit, or storage failure.
    pub async fn rotate_object(
        &self,
        request_id: Uuid,
        object_id: &str,
    ) -> std::result::Result<TeamObjectViewV1, ControlErrorV1> {
        self.team_effect(
            request_id,
            "object.rotate",
            TeamPermissionV1::RotateObjectKey,
            self.cell.objects.rotate(object_id),
        )
        .await
    }

    /// Apply the cell's mandatory object-retention boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed admission, identity, administrator-role, audit, or storage failure.
    pub async fn apply_retention(
        &self,
        request_id: Uuid,
    ) -> std::result::Result<u64, ControlErrorV1> {
        self.team_effect(
            request_id,
            "object.retention",
            TeamPermissionV1::ApplyRetention,
            self.cell.objects.apply_retention(Utc::now()),
        )
        .await
    }

    /// Read one bounded cell-local page from the immutable audit sequence.
    ///
    /// # Errors
    ///
    /// Returns a typed cursor, admission, identity, administrator-role, audit, or storage failure.
    pub async fn read_audit(
        &self,
        request_id: Uuid,
        after: u64,
        limit: u16,
    ) -> std::result::Result<Vec<TeamAuditEventV1>, ControlErrorV1> {
        if !(1..=200).contains(&limit) {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "team audit limit must be 1-200",
            ));
        }
        self.cell.admit_request(request_id).await?;
        self.cell.verify_identity().await?;
        if !self.principal.role.allows_team(TeamPermissionV1::ReadAudit) {
            self.audit(request_id, "audit.read", TeamAuditOutcomeV1::Denied).await?;
            return Err(denied("team role does not permit audit access"));
        }
        let rows = sqlx::query(
            "SELECT sequence, request_id, cell_id, organization_id, project_id, engagement_id, \
             subject, role, action, outcome, occurred_at \
             FROM team_audit_events WHERE sequence > $1 ORDER BY sequence LIMIT $2",
        )
        .bind(i64::try_from(after).unwrap_or(i64::MAX))
        .bind(i64::from(limit))
        .fetch_all(&self.cell.pool)
        .await
        .map_err(|_| internal("team audit storage is unavailable"))?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let event = audit_event(&row)?;
            if event.cell_id != self.principal.cell_id
                || event.organization_id != self.principal.organization_id
                || event.project_id != self.principal.project_id
                || event.engagement_id != self.principal.engagement_id
            {
                return Err(internal("team audit row is corrupt"));
            }
            events.push(event);
        }
        self.audit(request_id, "audit.read", TeamAuditOutcomeV1::Succeeded).await?;
        Ok(events)
    }

    /// Reverify exact recovery inputs under administrator attribution.
    ///
    /// # Errors
    ///
    /// Returns a typed admission, identity, administrator-role, audit, destination, or manifest
    /// integrity failure.
    pub async fn verify_recovery(
        &self,
        request_id: Uuid,
        manifest: &TeamRecoveryManifestV1,
        input: &RecoveryInput,
        destination_database_identity_sha256: &str,
    ) -> std::result::Result<(), ControlErrorV1> {
        self.team_effect(request_id, "recovery.verify", TeamPermissionV1::VerifyRecovery, async {
            if manifest.cell_id != self.principal.cell_id
                || manifest.organization_id != self.principal.organization_id
                || manifest.project_id != self.principal.project_id
                || manifest.engagement_id != self.principal.engagement_id
                || manifest.database_identity_sha256 != self.cell.database_identity_sha256
            {
                return Err(ScorchError::Config(
                    "team recovery manifest does not match the authenticated cell".into(),
                ));
            }
            super::recovery::verify_recovery_manifest(
                manifest,
                input,
                destination_database_identity_sha256,
            )
        })
        .await
    }

    async fn team_effect<T>(
        &self,
        request_id: Uuid,
        action: &'static str,
        permission: TeamPermissionV1,
        effect: impl std::future::Future<Output = Result<T>>,
    ) -> std::result::Result<T, ControlErrorV1> {
        self.cell.admit_request(request_id).await?;
        self.cell.verify_identity().await?;
        if !self.principal.role.allows_team(permission) {
            self.audit(request_id, action, TeamAuditOutcomeV1::Denied).await?;
            return Err(denied("team role does not permit this operation"));
        }
        let mutation = !matches!(
            permission,
            TeamPermissionV1::ReadObject
                | TeamPermissionV1::ReadAudit
                | TeamPermissionV1::VerifyRecovery
        );
        if mutation {
            self.audit(request_id, action, TeamAuditOutcomeV1::Pending).await?;
        }
        let result = effect.await;
        if let Err(error) = &result {
            tracing::warn!(
                event = "team.operation_failed",
                action,
                error = %crate::engine::observation::redact_text(&error.to_string()),
                "team operation failed"
            );
        }
        if let Ok(value) = result {
            self.audit(request_id, action, TeamAuditOutcomeV1::Succeeded).await?;
            Ok(value)
        } else {
            self.audit(request_id, action, TeamAuditOutcomeV1::Failed).await?;
            Err(internal("team operation failed"))
        }
    }

    async fn audit(
        &self,
        request_id: Uuid,
        action: &str,
        outcome: TeamAuditOutcomeV1,
    ) -> std::result::Result<(), ControlErrorV1> {
        append_audit(&self.cell.pool, &self.principal, request_id, action, outcome).await
    }
}

impl TeamCell {
    async fn compose(base: &Arc<AppConfig>, prepared: PreparedCell) -> Result<Self> {
        let pool =
            crate::storage::connect_with_max(&prepared.database_url, base.database.max_connections)
                .await
                .map_err(|_| {
                    ScorchError::Database("team cell database connection failed".to_string())
                })?;
        let mut lease = PgConnection::connect(&prepared.database_url).await.map_err(|_| {
            ScorchError::Database("team cell database lease connection failed".to_string())
        })?;
        let acquired: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_lock( \
             (739983542::bigint << 32) # ( \
                 SELECT oid::bigint FROM pg_database WHERE datname = current_database() \
             ))",
        )
        .fetch_one(&mut lease)
        .await
        .map_err(|error| database_error("acquire cell service lease", &error))?;
        if !acquired {
            return Err(ScorchError::Config(
                "team cell database already has an active service lease".to_string(),
            ));
        }
        crate::storage::migrate::run_migrations(&pool).await?;
        provision_and_verify_identity(&pool, &prepared).await?;
        recover_pending_audits(&pool).await?;
        let database_identity_sha256 = database_identity(&pool).await?;
        let objects = TeamObjectStore::new(&prepared, pool.clone())?;
        objects.recover_pending_deletions().await?;
        let mut cell_config = (**base).clone();
        cell_config.engagement = Some(prepared.config.engagement.clone());
        cell_config.database.url = None;
        cell_config.team = None;
        cell_config.control_api.max_journal_events = prepared.config.quotas.max_journal_events;
        cell_config.control_api.max_event_bytes = prepared.config.quotas.max_event_bytes;
        cell_config.control_api.max_subscribers = prepared.config.quotas.max_subscribers;
        cell_config.control_api.default_page_size = prepared.config.quotas.default_page_size;
        let webhooks = if cell_config.webhooks.is_empty() {
            None
        } else {
            Some(Arc::new(WebhookService::new(
                &cell_config.webhooks,
                Arc::new(PostgresWebhookStore::new(pool.clone())),
            )?))
        };
        let role_service =
            ControlService::persistent(Arc::new(cell_config), pool.clone(), webhooks);
        Ok(Self {
            cell_id: prepared.config.cell_id,
            organization_id: prepared.config.organization_id,
            project_id: prepared.config.project_id,
            engagement_id: prepared.config.engagement.id,
            database_identity_sha256,
            role_service,
            pool,
            lease: Mutex::new(lease),
            objects,
            max_active_jobs: prepared.config.quotas.max_active_jobs,
            requests_per_minute: prepared.config.quotas.max_requests_per_minute,
            rate_window: Mutex::new(VecDeque::new()),
            job_admission: Mutex::new(()),
        })
    }

    async fn admit_request(&self, request_id: Uuid) -> std::result::Result<(), ControlErrorV1> {
        if request_id.is_nil() {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::InvalidRequest,
                "team request identity is invalid",
            ));
        }
        let now = Instant::now();
        let cutoff = now.checked_sub(Duration::from_mins(1)).unwrap_or(now);
        let mut window = self.rate_window.lock().await;
        while window.front().is_some_and(|(_, instant)| reservation_expired(*instant, cutoff)) {
            window.pop_front();
        }
        if window.len() >= usize::try_from(self.requests_per_minute).unwrap_or(usize::MAX) {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::Busy,
                "team cell request capacity is exhausted",
            )
            .retryable());
        }
        window.push_back((request_id, now));
        drop(window);
        let claim = sqlx::query("INSERT INTO team_request_ids (request_id) VALUES ($1)")
            .bind(request_id)
            .execute(&self.pool)
            .await;
        if let Err(error) = claim {
            let mut window = self.rate_window.lock().await;
            if let Some(position) = window.iter().rposition(|(reserved, _)| *reserved == request_id)
            {
                window.remove(position);
            }
            drop(window);
            if error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .is_some_and(|code| code == "23505")
            {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::Conflict,
                    "team request identity was already used",
                ));
            }
            return Err(internal("team request admission storage is unavailable"));
        }
        Ok(())
    }

    async fn verify_identity(&self) -> std::result::Result<(), ControlErrorV1> {
        self.lease
            .lock()
            .await
            .ping()
            .await
            .map_err(|_| internal("team cell service lease is unavailable"))?;
        let row = sqlx::query(
            "SELECT cell_id, organization_id, project_id, engagement_id, \
             (SELECT count(*)::bigint FROM projects) AS project_count \
             FROM team_cell_identity WHERE singleton",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| internal("team cell identity is unavailable"))?
        .ok_or_else(|| internal("team cell identity is unavailable"))?;
        let project_count: i64 = row.get("project_count");
        if row.get::<String, _>("cell_id") != self.cell_id
            || row.get::<String, _>("organization_id") != self.organization_id
            || row.get::<Uuid, _>("project_id") != self.project_id
            || row.get::<Uuid, _>("engagement_id") != self.engagement_id
            || project_count != 1
        {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::CanonicalProjectionMismatch,
                "team cell canonical identity does not match its runtime binding",
            ));
        }
        Ok(())
    }

    async fn verify_operation_scope(
        &self,
        operation: &ControlOperationV1,
    ) -> std::result::Result<(), ControlErrorV1> {
        let project = match operation {
            ControlOperationV1::Query(query) => match query.as_ref() {
                ControlQueryV1::GetProject { id } => Some(*id),
                ControlQueryV1::ListTargets { project_id, .. }
                | ControlQueryV1::ListFindings { project_id, .. }
                | ControlQueryV1::GetProjectReport { project_id } => Some(*project_id),
                _ => None,
            },
            ControlOperationV1::Command(command) => match command {
                ControlCommandV1::CreateProject { .. } | ControlCommandV1::DeleteProject { .. } => {
                    return Err(denied("team project lifecycle is a provisioning operation"));
                }
                ControlCommandV1::AddTarget { project_id, .. }
                | ControlCommandV1::RemoveTarget { project_id, .. } => Some(*project_id),
                _ => None,
            },
        };
        if project.is_some_and(|project| project != self.project_id) {
            return Err(ControlErrorV1::new(
                ControlErrorCodeV1::NotFound,
                "team resource was not found",
            ));
        }
        if let ControlOperationV1::Command(ControlCommandV1::StartJob { target, .. }) = operation {
            let canonical = url::Url::parse(target)
                .ok()
                .filter(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
                .map(|url| url.to_string())
                .ok_or_else(|| {
                    ControlErrorV1::new(
                        ControlErrorCodeV1::InvalidRequest,
                        "team job target is invalid",
                    )
                })?;
            let registered: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM project_targets WHERE project_id = $1 AND url = $2)",
            )
            .bind(self.project_id)
            .bind(canonical)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| internal("team target registry is unavailable"))?;
            if !registered {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::NotFound,
                    "team resource was not found",
                ));
            }
        }
        if consumes_job_capacity(operation) {
            let active: i64 = sqlx::query_scalar(
                "SELECT count(*)::bigint FROM scan_jobs \
                 WHERE state IN ('queued', 'running', 'cancelling')",
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|_| internal("team job capacity is unavailable"))?;
            if active >= i64::from(self.max_active_jobs) {
                return Err(ControlErrorV1::new(
                    ControlErrorCodeV1::Busy,
                    "team cell active-job capacity is exhausted",
                )
                .retryable());
            }
        }
        Ok(())
    }
}

const fn consumes_job_capacity(operation: &ControlOperationV1) -> bool {
    matches!(
        operation,
        ControlOperationV1::Command(
            ControlCommandV1::StartJob { .. } | ControlCommandV1::ResumeJob { .. }
        )
    )
}

fn reservation_expired(reservation: Instant, cutoff: Instant) -> bool {
    reservation <= cutoff
}

async fn provision_and_verify_identity(pool: &PgPool, cell: &PreparedCell) -> Result<()> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| database_error("begin cell identity preflight", &error))?;
    sqlx::query("SELECT pg_advisory_xact_lock(739_983_541)")
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_error("lock cell identity preflight", &error))?;
    let projects: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM projects ORDER BY id LIMIT 2")
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| database_error("verify cell project census", &error))?;
    if projects.as_slice() != [cell.config.project_id] {
        return Err(ScorchError::Config(
            "team cell database must contain exactly its configured project".to_string(),
        ));
    }
    sqlx::query(
        "INSERT INTO team_cell_identity \
         (singleton, cell_id, organization_id, project_id, engagement_id) \
         VALUES (TRUE, $1, $2, $3, $4) ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(&cell.config.cell_id)
    .bind(&cell.config.organization_id)
    .bind(cell.config.project_id)
    .bind(cell.config.engagement.id)
    .execute(&mut *transaction)
    .await
    .map_err(|error| database_error("provision cell identity", &error))?;
    let identity = sqlx::query_as::<_, (String, String, Uuid, Uuid)>(
        "SELECT cell_id, organization_id, project_id, engagement_id \
         FROM team_cell_identity WHERE singleton",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| database_error("verify cell identity", &error))?;
    if identity
        != (
            cell.config.cell_id.clone(),
            cell.config.organization_id.clone(),
            cell.config.project_id,
            cell.config.engagement.id,
        )
    {
        return Err(ScorchError::Config(
            "team cell database is already bound to another identity".to_string(),
        ));
    }
    transaction
        .commit()
        .await
        .map_err(|error| database_error("commit cell identity preflight", &error))
}

async fn database_identity(pool: &PgPool) -> Result<String> {
    let row = sqlx::query(
        "SELECT (pg_control_system()).system_identifier::text AS system_identifier, \
         oid::text AS database_oid, datname AS database_name \
         FROM pg_database WHERE datname = current_database()",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| database_error("resolve live database identity", &error))?;
    let identity = format!(
        "{}\0{}\0{}",
        row.get::<String, _>("system_identifier"),
        row.get::<String, _>("database_oid"),
        row.get::<String, _>("database_name"),
    );
    Ok(sha256_hex(identity.as_bytes()))
}

fn validate_distinct_roots(cells: &[PreparedCell]) -> Result<()> {
    let mut roots: Vec<(&str, PathBuf)> = Vec::with_capacity(cells.len());
    for cell in cells {
        let metadata = std::fs::symlink_metadata(&cell.config.object_root).map_err(|error| {
            ScorchError::Config(format!("team object root is unavailable: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ScorchError::Config(
                "team object root must be a non-symlink directory".to_string(),
            ));
        }
        let canonical = cell.config.object_root.canonicalize()?;
        if canonical != cell.config.object_root {
            return Err(ScorchError::Config(
                "team object root must already be canonical".to_string(),
            ));
        }
        for (_, other) in &roots {
            if canonical.starts_with(other) || other.starts_with(&canonical) {
                return Err(ScorchError::Config(
                    "team object roots must be distinct and non-overlapping".to_string(),
                ));
            }
        }
        roots.push((&cell.config.cell_id, canonical));
    }
    Ok(())
}

async fn append_audit(
    pool: &PgPool,
    principal: &TeamPrincipalV1,
    request_id: Uuid,
    action: &str,
    outcome: TeamAuditOutcomeV1,
) -> std::result::Result<(), ControlErrorV1> {
    if action.is_empty() || action.len() > 128 {
        return Err(internal("team audit action is invalid"));
    }
    sqlx::query(
        "INSERT INTO team_audit_events \
         (request_id, cell_id, organization_id, project_id, engagement_id, subject, role, action, outcome) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(request_id)
    .bind(&principal.cell_id)
    .bind(&principal.organization_id)
    .bind(principal.project_id)
    .bind(principal.engagement_id)
    .bind(&principal.subject)
    .bind(role_name(principal.role))
    .bind(action)
    .bind(outcome_name(outcome))
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| internal("team audit storage is unavailable"))
}

async fn recover_pending_audits(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "INSERT INTO team_audit_events \
         (request_id, cell_id, organization_id, project_id, engagement_id, subject, role, action, outcome) \
         SELECT pending.request_id, pending.cell_id, pending.organization_id, pending.project_id, \
                pending.engagement_id, pending.subject, pending.role, pending.action, 'outcome_unknown' \
         FROM team_audit_events pending \
         WHERE pending.outcome = 'pending' AND NOT EXISTS ( \
             SELECT 1 FROM team_audit_events terminal \
             WHERE terminal.request_id = pending.request_id \
               AND terminal.sequence > pending.sequence \
               AND terminal.outcome <> 'pending' \
         )",
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|error| database_error("recover pending audit intents", &error))
}

fn audit_event(
    row: &sqlx::postgres::PgRow,
) -> std::result::Result<TeamAuditEventV1, ControlErrorV1> {
    let sequence: i64 = row.get("sequence");
    let role: String = row.get("role");
    let outcome: String = row.get("outcome");
    Ok(TeamAuditEventV1 {
        sequence: u64::try_from(sequence).map_err(|_| internal("team audit row is corrupt"))?,
        request_id: row.get("request_id"),
        cell_id: row.get("cell_id"),
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
        engagement_id: row.get("engagement_id"),
        subject: row.get("subject"),
        role: parse_role(&role).ok_or_else(|| internal("team audit row is corrupt"))?,
        action: row.get("action"),
        outcome: parse_outcome(&outcome).ok_or_else(|| internal("team audit row is corrupt"))?,
        occurred_at: row.get("occurred_at"),
    })
}

fn control_action(operation: &ControlOperationV1) -> &'static str {
    match operation {
        ControlOperationV1::Query(query) => match query.as_ref() {
            ControlQueryV1::Describe => "control.describe",
            ControlQueryV1::ResolveConfiguration(_) => "control.configuration.resolve",
            ControlQueryV1::GetEngagement => "control.engagement.get",
            ControlQueryV1::GetModelReadiness => "control.model_readiness.get",
            ControlQueryV1::ListProjects { .. } => "control.projects.list",
            ControlQueryV1::GetProject { .. } => "control.project.get",
            ControlQueryV1::ListTargets { .. } => "control.targets.list",
            ControlQueryV1::ListJobs { .. } => "control.jobs.list",
            ControlQueryV1::GetJob { .. } => "control.job.get",
            ControlQueryV1::ListFindings { .. } => "control.findings.list",
            ControlQueryV1::GetFinding { .. } => "control.finding.get",
            ControlQueryV1::ListEvidence { .. } => "control.evidence.list",
            ControlQueryV1::ListModules { .. } => "control.modules.list",
            ControlQueryV1::GetProjectReport { .. } => "control.report.get",
            ControlQueryV1::ReadEvents { .. } => "control.events.read",
        },
        ControlOperationV1::Command(command) => match command {
            ControlCommandV1::CreateProject { .. } => "control.project.create",
            ControlCommandV1::DeleteProject { .. } => "control.project.delete",
            ControlCommandV1::AddTarget { .. } => "control.target.add",
            ControlCommandV1::RemoveTarget { .. } => "control.target.remove",
            ControlCommandV1::StartJob { .. } => "control.job.start",
            ControlCommandV1::CancelJob { .. } => "control.job.cancel",
            ControlCommandV1::ResumeJob { .. } => "control.job.resume",
            ControlCommandV1::RecoverJobs => "control.jobs.recover",
            ControlCommandV1::TransitionFinding { .. } => "control.finding.transition",
            ControlCommandV1::CreateFindingSuppression { .. } => "control.finding.suppress",
            ControlCommandV1::RecordFindingCorrelation { .. } => "control.finding.correlate",
        },
    }
}

const fn role_name(role: TeamRoleV1) -> &'static str {
    match role {
        TeamRoleV1::Reader => "reader",
        TeamRoleV1::Analyst => "analyst",
        TeamRoleV1::Operator => "operator",
        TeamRoleV1::Administrator => "administrator",
    }
}

fn parse_role(value: &str) -> Option<TeamRoleV1> {
    match value {
        "reader" => Some(TeamRoleV1::Reader),
        "analyst" => Some(TeamRoleV1::Analyst),
        "operator" => Some(TeamRoleV1::Operator),
        "administrator" => Some(TeamRoleV1::Administrator),
        _ => None,
    }
}

const fn outcome_name(outcome: TeamAuditOutcomeV1) -> &'static str {
    match outcome {
        TeamAuditOutcomeV1::Pending => "pending",
        TeamAuditOutcomeV1::Succeeded => "succeeded",
        TeamAuditOutcomeV1::Denied => "denied",
        TeamAuditOutcomeV1::Failed => "failed",
        TeamAuditOutcomeV1::OutcomeUnknown => "outcome_unknown",
    }
}

fn parse_outcome(value: &str) -> Option<TeamAuditOutcomeV1> {
    match value {
        "pending" => Some(TeamAuditOutcomeV1::Pending),
        "succeeded" => Some(TeamAuditOutcomeV1::Succeeded),
        "denied" => Some(TeamAuditOutcomeV1::Denied),
        "failed" => Some(TeamAuditOutcomeV1::Failed),
        "outcome_unknown" => Some(TeamAuditOutcomeV1::OutcomeUnknown),
        _ => None,
    }
}

fn denied(message: &str) -> ControlErrorV1 {
    ControlErrorV1::new(ControlErrorCodeV1::PolicyDenied, message)
}

fn internal(message: &str) -> ControlErrorV1 {
    ControlErrorV1::new(ControlErrorCodeV1::Internal, message)
}

fn database_error(label: &str, error: &sqlx::Error) -> ScorchError {
    ScorchError::Database(format!("team {label}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_config::{
        TeamCellConfig, TeamKeyReferenceConfig, TeamQuotaConfig, TeamRetentionConfig,
    };
    use scorchkit_control::{EventCursorV1, PageRequestV1};
    use scorchkit_policy::{Capability, EffectClass, Engagement, EngagementPolicy, ScopeRule};
    use zeroize::Zeroizing;

    fn prepared_cell(root: PathBuf, id: &str, project: u128) -> PreparedCell {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&root).expect("root scope"))
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive);
        PreparedCell {
            config: TeamCellConfig {
                cell_id: id.into(),
                organization_id: format!("org-{id}"),
                project_id: Uuid::from_u128(project),
                engagement: Engagement::new(id, policy),
                database_url_env: format!("SCORCHKIT_TEAM_{}_DATABASE", id.to_ascii_uppercase()),
                object_root: root,
                write_key_id: "primary".into(),
                keys: vec![TeamKeyReferenceConfig {
                    key_id: "primary".into(),
                    key_env: format!("SCORCHKIT_TEAM_{}_KEY", id.to_ascii_uppercase()),
                }],
                quotas: TeamQuotaConfig::default(),
                retention: TeamRetentionConfig::default(),
            },
            database_url: Zeroizing::new(format!("postgresql:///{id}")),
            keys: vec![("primary".into(), Zeroizing::new([7_u8; 32]))],
        }
    }

    fn page() -> PageRequestV1 {
        PageRequestV1 { cursor: None, limit: 1 }
    }

    #[test]
    fn operation_action_and_job_capacity_mappings_are_exhaustive() {
        let project = Uuid::from_u128(1);
        let queries = [
            (ControlQueryV1::Describe, "control.describe"),
            (ControlQueryV1::GetEngagement, "control.engagement.get"),
            (ControlQueryV1::GetModelReadiness, "control.model_readiness.get"),
            (ControlQueryV1::ListProjects { page: page() }, "control.projects.list"),
            (ControlQueryV1::GetProject { id: project }, "control.project.get"),
            (
                ControlQueryV1::ListTargets { project_id: project, page: page() },
                "control.targets.list",
            ),
            (ControlQueryV1::ListJobs { page: page() }, "control.jobs.list"),
            (ControlQueryV1::GetJob { id: project }, "control.job.get"),
            (
                ControlQueryV1::ListFindings { project_id: project, page: page() },
                "control.findings.list",
            ),
            (ControlQueryV1::GetFinding { id: project }, "control.finding.get"),
            (
                ControlQueryV1::ListEvidence { finding_id: project, page: page() },
                "control.evidence.list",
            ),
            (ControlQueryV1::ListModules { family: None, page: page() }, "control.modules.list"),
            (ControlQueryV1::GetProjectReport { project_id: project }, "control.report.get"),
            (
                ControlQueryV1::ReadEvents {
                    cursor: EventCursorV1 { after_sequence: 0, limit: 1 },
                },
                "control.events.read",
            ),
        ];
        for (query, expected) in queries {
            let operation = ControlOperationV1::Query(Box::new(query));
            assert_eq!(control_action(&operation), expected);
            assert!(!consumes_job_capacity(&operation));
        }

        let commands = [
            (
                ControlCommandV1::CreateProject { name: "x".into(), description: String::new() },
                "control.project.create",
                false,
            ),
            (ControlCommandV1::DeleteProject { id: project }, "control.project.delete", false),
            (
                ControlCommandV1::AddTarget {
                    project_id: project,
                    url: "https://alpha.example.test/".into(),
                    label: String::new(),
                },
                "control.target.add",
                false,
            ),
            (
                ControlCommandV1::RemoveTarget { project_id: project, target_id: project },
                "control.target.remove",
                false,
            ),
            (
                ControlCommandV1::StartJob {
                    target: "https://alpha.example.test/".into(),
                    profile: "quick".into(),
                    modules: None,
                    skip: Vec::new(),
                },
                "control.job.start",
                true,
            ),
            (ControlCommandV1::CancelJob { id: project }, "control.job.cancel", false),
            (ControlCommandV1::ResumeJob { id: project }, "control.job.resume", true),
            (ControlCommandV1::RecoverJobs, "control.jobs.recover", false),
        ];
        for (command, expected, consumes_capacity) in commands {
            let operation = ControlOperationV1::Command(command);
            assert_eq!(control_action(&operation), expected);
            assert_eq!(consumes_job_capacity(&operation), consumes_capacity);
        }
    }

    #[test]
    fn audit_role_and_outcome_names_round_trip_exactly() {
        for (name, role) in [
            ("reader", TeamRoleV1::Reader),
            ("analyst", TeamRoleV1::Analyst),
            ("operator", TeamRoleV1::Operator),
            ("administrator", TeamRoleV1::Administrator),
        ] {
            assert_eq!(parse_role(name), Some(role));
            assert_eq!(role_name(role), name);
        }
        assert_eq!(parse_role("unknown"), None);

        for (name, outcome) in [
            ("pending", TeamAuditOutcomeV1::Pending),
            ("succeeded", TeamAuditOutcomeV1::Succeeded),
            ("denied", TeamAuditOutcomeV1::Denied),
            ("failed", TeamAuditOutcomeV1::Failed),
            ("outcome_unknown", TeamAuditOutcomeV1::OutcomeUnknown),
        ] {
            assert_eq!(parse_outcome(name), Some(outcome));
            assert_eq!(outcome_name(outcome), name);
        }
        assert_eq!(parse_outcome("unknown"), None);
    }

    #[test]
    fn request_reservations_expire_at_the_exact_cutoff() {
        let cutoff = Instant::now();
        assert!(reservation_expired(cutoff, cutoff));
        assert!(reservation_expired(
            cutoff.checked_sub(Duration::from_nanos(1)).expect("earlier"),
            cutoff,
        ));
        assert!(!reservation_expired(
            cutoff.checked_add(Duration::from_nanos(1)).expect("later"),
            cutoff,
        ));
    }

    #[test]
    fn object_roots_must_be_canonical_distinct_and_non_overlapping() {
        let first = tempfile::tempdir().expect("first root");
        let second = tempfile::tempdir().expect("second root");
        let first_root = first.path().canonicalize().expect("first canonical");
        let second_root = second.path().canonicalize().expect("second canonical");
        validate_distinct_roots(&[
            prepared_cell(first_root.clone(), "alpha", 1),
            prepared_cell(second_root, "beta", 2),
        ])
        .expect("distinct roots");

        assert!(validate_distinct_roots(&[
            prepared_cell(first_root.clone(), "alpha", 1),
            prepared_cell(first_root.clone(), "beta", 2),
        ])
        .is_err());

        let nested = first_root.join("nested");
        std::fs::create_dir(&nested).expect("nested root");
        assert!(validate_distinct_roots(&[
            prepared_cell(first_root.clone(), "alpha", 1),
            prepared_cell(nested, "beta", 2),
        ])
        .is_err());

        let noncanonical_child = first_root.join("noncanonical-child");
        std::fs::create_dir(&noncanonical_child).expect("noncanonical child");
        let noncanonical = noncanonical_child.join("..");
        assert!(validate_distinct_roots(&[prepared_cell(noncanonical, "alpha", 1)]).is_err());

        let regular_file = first_root.join("not-a-directory");
        std::fs::write(&regular_file, b"root identity changed").expect("regular file root");
        assert!(validate_distinct_roots(&[prepared_cell(regular_file, "alpha", 1)]).is_err());

        #[cfg(unix)]
        {
            let link = first_root.with_extension("team-link");
            std::os::unix::fs::symlink(&first_root, &link).expect("root symlink");
            assert!(validate_distinct_roots(&[prepared_cell(link.clone(), "alpha", 1)]).is_err());
            std::fs::remove_file(link).expect("remove root symlink");
        }
    }

    #[tokio::test]
    async fn audit_action_bounds_fail_before_database_access() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/scorchkit_audit_unit")
            .expect("lazy pool");
        let principal = TeamPrincipalV1 {
            subject: "operator".into(),
            organization_id: "org-alpha".into(),
            project_id: Uuid::from_u128(1),
            cell_id: "alpha".into(),
            role: TeamRoleV1::Administrator,
            engagement_id: Uuid::from_u128(2),
        };
        assert_eq!(
            append_audit(&pool, &principal, Uuid::from_u128(3), "", TeamAuditOutcomeV1::Failed,)
                .await
                .expect_err("empty action")
                .message,
            "team audit action is invalid"
        );
        assert_eq!(
            append_audit(
                &pool,
                &principal,
                Uuid::from_u128(3),
                &"a".repeat(129),
                TeamAuditOutcomeV1::Failed,
            )
            .await
            .expect_err("oversized action")
            .message,
            "team audit action is invalid"
        );
    }

    #[test]
    fn security_critical_service_guards_remain_explicit_and_fail_closed() {
        let source = include_str!("service.rs");
        let production = source.split("#[cfg(test)]").next().expect("production source");
        let normalized = production.split_whitespace().collect::<Vec<_>>().join(" ");
        for required in [
            "if mutation && self.audit",
            "manifest.cell_id != self.principal.cell_id || manifest.organization_id != self.principal.organization_id || manifest.project_id != self.principal.project_id || manifest.engagement_id != self.principal.engagement_id || manifest.database_identity_sha256 != self.cell.database_identity_sha256",
            "let mutation = !matches!( permission, TeamPermissionV1::ReadObject | TeamPermissionV1::ReadAudit | TeamPermissionV1::VerifyRecovery",
            "*reserved == request_id",
            "ControlQueryV1::GetProject { id } => Some(*id)",
            "ControlQueryV1::ListTargets { project_id, .. } | ControlQueryV1::ListFindings { project_id, .. } | ControlQueryV1::GetProjectReport { project_id } => Some(*project_id)",
            "ControlCommandV1::CreateProject { .. } | ControlCommandV1::DeleteProject { .. }",
            "ControlCommandV1::AddTarget { project_id, .. } | ControlCommandV1::RemoveTarget { project_id, .. } => Some(*project_id)",
            "matches!(url.scheme(), \"http\" | \"https\") && url.host_str().is_some()",
            "if active >= i64::from(self.max_active_jobs)",
            "canonical.starts_with(other) || other.starts_with(&canonical)",
        ] {
            assert!(normalized.contains(required), "missing security guard: {required}");
        }
    }
}
