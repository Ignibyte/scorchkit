//! Explicit policy-owned provider refresh outside scan-time execution.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::config::AppConfig;
use crate::engine::audit_log::subscribe_audit_log_if_enabled;
use crate::engine::error::{Result, ScorchError};
use crate::engine::events::{EventBus, ScanEvent};
use crate::engine::policy::{Capability, EffectClass, Engagement, PolicyTarget};
use crate::engine::policy_http::{build_service_client, download_to_staging, RedirectMode};
use crate::runner::subprocess::{SystemToolExecutor, ToolExecutor, ToolInvocation};

use super::adapters::{grype_config, version_output_matches};
use super::cache::{SnapshotArtifact, SnapshotManifest, SupplyChainSnapshotStore};
use super::orchestrator::GRYPE_VERSION;

const MAX_PROVIDER_DOWNLOADS: usize = 256;

/// Provider lifecycles supported by the policy-owned refresh operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupplyChainProvider {
    Osv,
    Grype,
    /// Trivy remains explicit pre-provisioned local state until safe OCI import is implemented.
    Trivy,
}

impl SupplyChainProvider {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Osv => "osv",
            Self::Grype => "grype",
            Self::Trivy => "trivy",
        }
    }
}

/// One explicit provider artifact and its expected digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDownload {
    pub url: Url,
    pub relative_path: PathBuf,
    pub sha256: String,
}

/// Complete, explicit refresh request. No scanner can derive or change these endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRefreshRequest {
    pub provider: SupplyChainProvider,
    pub snapshot_id: String,
    pub schema_version: String,
    pub downloads: Vec<ProviderDownload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_built_at: Option<DateTime<Utc>>,
    /// Requested lifetime. Provider configuration is an absolute upper bound.
    pub maximum_age_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrypeDatabaseStatus {
    schema_version: String,
    path: PathBuf,
    valid: bool,
    #[serde(default)]
    error: Option<String>,
}

/// Refresh service bound to one engagement, cache root, and clean tool configuration.
#[derive(Debug)]
pub struct ProviderRefreshService {
    engagement: Arc<Engagement>,
    config: Arc<AppConfig>,
    snapshots: SupplyChainSnapshotStore,
    executor: Arc<dyn ToolExecutor>,
}

struct StagingCleanup {
    path: PathBuf,
    armed: bool,
}

impl StagingCleanup {
    const fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

impl ProviderRefreshService {
    #[must_use]
    pub fn new(
        engagement: Arc<Engagement>,
        config: Arc<AppConfig>,
        snapshots: SupplyChainSnapshotStore,
    ) -> Self {
        Self { engagement, config, snapshots, executor: Arc::new(SystemToolExecutor) }
    }

    /// Download, validate, optionally import, and atomically promote one provider snapshot.
    // JUSTIFICATION: Refresh is a single authorization and atomic-promotion transaction; keeping
    // its ordered staging, validation, import, and audit steps together preserves that boundary.
    #[allow(clippy::too_many_lines)]
    pub async fn refresh(
        &self,
        request: &ProviderRefreshRequest,
    ) -> Result<scorchkit_core::ProviderSnapshot> {
        validate_request(request)?;
        if request.provider == SupplyChainProvider::Trivy {
            return Err(ScorchError::Config(
                "Trivy provider refresh is unavailable; import a policy-owned pre-provisioned cache"
                    .to_string(),
            ));
        }
        let audit_events = EventBus::default();
        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.config.audit_log, &audit_events);
        let local_state_decision = self.engagement.authorize(
            PolicyTarget::Code(self.snapshots.root().to_path_buf()),
            Capability::LocalState,
            EffectClass::Passive,
        );
        publish_authorization(&audit_events, "provider_cache_write", &local_state_decision);
        local_state_decision.require()?;

        let policy_maximum_age_seconds =
            provider_policy_maximum_age(&self.config, request.provider);
        let effective_maximum_age_seconds =
            request.maximum_age_seconds.min(policy_maximum_age_seconds);
        let stage = self.snapshots.create_staging(request.provider.id(), &request.snapshot_id)?;
        let mut staging_cleanup = StagingCleanup::new(stage.clone());
        create_private_directory(&stage.join("cache"))?;
        create_private_directory(&stage.join("downloads"))?;
        create_private_directory(&stage.join("work"))?;

        let mut total_downloaded_bytes = 0usize;
        for download in &request.downloads {
            let destination = stage.join(&download.relative_path);
            let parent = destination.parent().ok_or_else(|| {
                ScorchError::Config("provider download path has no parent".to_string())
            })?;
            fs::create_dir_all(parent)?;
            let provider_decision = self.engagement.authorize(
                PolicyTarget::Web(download.url.clone()),
                Capability::ProviderRefresh,
                EffectClass::Passive,
            );
            publish_authorization(&audit_events, "provider_download", &provider_decision);
            provider_decision.require()?;
            let client = build_service_client(
                Arc::clone(&self.engagement),
                &download.url,
                Capability::ProviderRefresh,
                EffectClass::Passive,
                &self.config.scan.user_agent,
                Duration::from_secs(self.config.scan.timeout_seconds),
                RedirectMode::Follow { max_redirects: 3 },
            )?;
            let downloaded = download_to_staging(
                &client,
                &download.url,
                &destination,
                self.config.supply_chain.provider_download_limit_bytes,
            )
            .await?;
            total_downloaded_bytes =
                total_downloaded_bytes.saturating_add(downloaded.bytes_written);
            if total_downloaded_bytes > self.config.supply_chain.provider_download_limit_bytes {
                return Err(ScorchError::ProviderDownloadLimit {
                    url: scorchkit_core::observation::redact_url(download.url.as_str()).0,
                    limit_bytes: self.config.supply_chain.provider_download_limit_bytes,
                });
            }
            if downloaded.sha256 != download.sha256.to_ascii_lowercase() {
                return Err(integrity_error(
                    request.provider,
                    format!("digest mismatch for {}", download.relative_path.display()),
                ));
            }
            validate_download_format(
                request.provider,
                &destination,
                self.config.supply_chain.provider_download_limit_bytes,
            )?;
        }

        if request.provider == SupplyChainProvider::Grype {
            self.import_grype_database(request, &stage, &audit_events).await?;
        }
        cleanup_refresh_state(&stage)?;
        let artifacts =
            inventory_artifacts(&stage, self.config.supply_chain.provider_download_limit_bytes)?;
        let manifest = SnapshotManifest {
            provider: request.provider.id().to_string(),
            snapshot_id: request.snapshot_id.clone(),
            schema_version: request.schema_version.clone(),
            consumer_relative_path: PathBuf::from("cache"),
            artifacts,
            upstream_built_at: request.upstream_built_at,
            checked_at: Utc::now(),
            maximum_age_seconds: effective_maximum_age_seconds,
        };
        let snapshot = self.snapshots.promote(&stage, &manifest)?;
        staging_cleanup.disarm();
        audit_events.publish(ScanEvent::Custom {
            kind: "supply_chain.cache_promoted".to_string(),
            data: serde_json::json!({
                "provider": request.provider.id(),
                "snapshot_id": request.snapshot_id,
                "state": snapshot.state,
            }),
        });
        Ok(snapshot)
    }

    async fn import_grype_database(
        &self,
        request: &ProviderRefreshRequest,
        stage: &Path,
        audit_events: &EventBus,
    ) -> Result<()> {
        let tool_decision = self.engagement.authorize(
            PolicyTarget::Code(self.snapshots.root().to_path_buf()),
            Capability::ExternalTool,
            EffectClass::Passive,
        );
        publish_authorization(audit_events, "provider_database_import", &tool_decision);
        tool_decision.require()?;
        let program = self.config.tools.get_path("grype");
        let archive = stage.join(&request.downloads[0].relative_path);
        let cache = stage.join("cache");
        let work = stage.join("work");
        let config_path = stage.join("grype-import.yaml");
        let maximum_age_seconds = request
            .maximum_age_seconds
            .min(provider_policy_maximum_age(&self.config, request.provider));
        let config = grype_config(&cache, maximum_age_seconds)?;
        write_new_synced(&config_path, config.as_bytes())?;
        let base = |args: Vec<String>| {
            ToolInvocation::strict_owned(&program, args, Duration::from_mins(5))
                .with_clean_environment()
                .with_environment("HOME", work.join("home").display().to_string())
                .with_environment("XDG_CACHE_HOME", work.join("xdg-cache").display().to_string())
                .with_environment("XDG_CONFIG_HOME", work.join("xdg-config").display().to_string())
                .with_environment("TMPDIR", work.join("tmp").display().to_string())
                .with_working_directory(&work)
        };
        for directory in ["home", "xdg-cache", "xdg-config", "tmp"] {
            create_private_directory(&work.join(directory))?;
        }
        publish_subprocess(audit_events, &program, "grype_version");
        let version = self
            .executor
            .execute(base(vec!["--version".to_string()]).with_output_limit(16 * 1024))
            .await?;
        if !version_output_matches(&version.stdout, &version.stderr, GRYPE_VERSION) {
            return Err(integrity_error(
                request.provider,
                format!("Grype version does not match the pinned {GRYPE_VERSION} contract"),
            ));
        }
        publish_subprocess(audit_events, &program, "grype_database_import");
        self.executor
            .execute(base(vec![
                "--config".to_string(),
                config_path.display().to_string(),
                "--quiet".to_string(),
                "db".to_string(),
                "import".to_string(),
                archive.display().to_string(),
            ]))
            .await?;
        publish_subprocess(audit_events, &program, "grype_database_status");
        let status = self
            .executor
            .execute(base(vec![
                "--config".to_string(),
                config_path.display().to_string(),
                "--quiet".to_string(),
                "db".to_string(),
                "status".to_string(),
                "--output".to_string(),
                "json".to_string(),
            ]))
            .await?;
        validate_grype_status(&status.stdout, &cache)?;
        write_new_synced(&cache.join("scorchkit-grype-status.json"), status.stdout.as_bytes())?;
        Ok(())
    }
}

fn validate_grype_status(status: &str, cache: &Path) -> Result<()> {
    let parsed: GrypeDatabaseStatus = serde_json::from_str(status).map_err(|error| {
        integrity_error(SupplyChainProvider::Grype, format!("invalid Grype DB status: {error}"))
    })?;
    if !parsed.valid || parsed.schema_version.trim().is_empty() {
        return Err(integrity_error(
            SupplyChainProvider::Grype,
            parsed.error.as_deref().unwrap_or("Grype database status is not valid"),
        ));
    }
    if parsed.error.as_deref().is_some_and(|error| !error.trim().is_empty()) {
        return Err(integrity_error(
            SupplyChainProvider::Grype,
            "Grype reported an error for a nominally valid database",
        ));
    }
    let canonical_cache = cache.canonicalize()?;
    let canonical_database = parsed.path.canonicalize()?;
    if !canonical_database.is_file() || !canonical_database.starts_with(&canonical_cache) {
        return Err(integrity_error(
            SupplyChainProvider::Grype,
            "Grype database status points outside its owned cache",
        ));
    }
    Ok(())
}

fn publish_authorization(
    events: &EventBus,
    operation: &str,
    decision: &crate::engine::policy::AuthorizationDecision,
) {
    let target = match &decision.target {
        PolicyTarget::Web(url) => scorchkit_core::observation::redact_url(url.as_str()).0,
        PolicyTarget::Code(path) => path.display().to_string(),
        PolicyTarget::Network(value) | PolicyTarget::Cloud(value) => {
            scorchkit_core::observation::redact_text(value)
        }
    };
    events.publish(ScanEvent::Custom {
        kind: "supply_chain.authorization".to_string(),
        data: serde_json::json!({
            "operation": operation,
            "engagement_id": decision.engagement_id,
            "target": target,
            "capability": decision.capability,
            "effect": decision.effect,
            "allowed": decision.allowed,
            "denial": decision.denial,
        }),
    });
}

fn publish_subprocess(events: &EventBus, program: &str, operation: &str) {
    events.publish(ScanEvent::Custom {
        kind: "effect.subprocess_started".to_string(),
        data: serde_json::json!({
            "operation": operation,
            "program": scorchkit_core::observation::redact_text(program),
            "capability": "external-tool",
            "effect": "passive",
        }),
    });
}

fn cleanup_refresh_state(stage: &Path) -> Result<()> {
    for directory in ["downloads", "work"] {
        let path = stage.join(directory);
        if path.exists() {
            fs::remove_dir_all(path)?;
        }
    }
    let import_config = stage.join("grype-import.yaml");
    if import_config.exists() {
        fs::remove_file(import_config)?;
    }
    Ok(())
}

fn validate_request(request: &ProviderRefreshRequest) -> Result<()> {
    if request.snapshot_id.is_empty()
        || request.schema_version.is_empty()
        || request.downloads.is_empty()
        || request.downloads.len() > MAX_PROVIDER_DOWNLOADS
        || request.maximum_age_seconds == 0
    {
        return Err(ScorchError::Config(
            "provider refresh requires snapshot, schema, and downloads".to_string(),
        ));
    }
    if request.provider == SupplyChainProvider::Grype && request.downloads.len() != 1 {
        return Err(ScorchError::Config(
            "Grype refresh requires exactly one checked database archive".to_string(),
        ));
    }
    let mut relative_paths = std::collections::BTreeSet::new();
    for download in &request.downloads {
        if download.relative_path.is_absolute()
            || download
                .relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || download.sha256.len() != 64
            || !download.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ScorchError::Config(
                "provider refresh contains an invalid artifact descriptor".to_string(),
            ));
        }
        if !relative_paths.insert(&download.relative_path) {
            return Err(ScorchError::Config(
                "provider refresh contains duplicate artifact paths".to_string(),
            ));
        }
        let expected_prefix = match request.provider {
            SupplyChainProvider::Osv => Path::new("cache/osv-scanner"),
            SupplyChainProvider::Grype => Path::new("downloads"),
            SupplyChainProvider::Trivy => Path::new("cache"),
        };
        if !download.relative_path.starts_with(expected_prefix) {
            return Err(ScorchError::Config(
                "provider artifact path is outside its owned layout".to_string(),
            ));
        }
        if request.provider == SupplyChainProvider::Osv {
            let relative = download
                .relative_path
                .strip_prefix(Path::new("cache/osv-scanner"))
                .map_err(|error| ScorchError::Config(error.to_string()))?;
            let components = relative.components().collect::<Vec<_>>();
            if components.len() != 2
                || !matches!(components[0], std::path::Component::Normal(_))
                || components[1].as_os_str() != "all.zip"
            {
                return Err(ScorchError::Config(
                    "OSV provider artifacts must use cache/osv-scanner/<ecosystem>/all.zip"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

const fn provider_policy_maximum_age(config: &AppConfig, provider: SupplyChainProvider) -> u64 {
    match provider {
        SupplyChainProvider::Osv => config.supply_chain.osv_maximum_age_seconds,
        SupplyChainProvider::Grype => config.supply_chain.grype_maximum_age_seconds,
        SupplyChainProvider::Trivy => config.supply_chain.trivy_maximum_age_seconds,
    }
}

fn validate_download_format(
    provider: SupplyChainProvider,
    path: &Path,
    maximum_archive_bytes: usize,
) -> Result<()> {
    let mut file = File::open(path)?;
    let mut prefix = [0_u8; 4];
    file.read_exact(&mut prefix).map_err(|error| {
        integrity_error(provider, format!("truncated provider artifact: {error}"))
    })?;
    let valid = match provider {
        SupplyChainProvider::Osv => {
            validate_osv_archive(path, maximum_archive_bytes)?;
            true
        }
        SupplyChainProvider::Grype => {
            if prefix == [0x28, 0xB5, 0x2F, 0xFD] {
                validate_grype_archive(path, maximum_archive_bytes)?;
                true
            } else {
                false
            }
        }
        SupplyChainProvider::Trivy => false,
    };
    if valid {
        Ok(())
    } else {
        Err(integrity_error(provider, "unexpected provider archive format"))
    }
}

fn validate_grype_archive(path: &Path, maximum_uncompressed_bytes: usize) -> Result<()> {
    const MAX_ENTRIES: usize = 4_096;

    let file = File::open(path)?;
    let decoder = zstd::stream::read::Decoder::new(file).map_err(|error| {
        integrity_error(SupplyChainProvider::Grype, format!("invalid Zstandard stream: {error}"))
    })?;
    let read_limit =
        u64::try_from(maximum_uncompressed_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bounded = decoder.take(read_limit);
    let mut file_entries = 0usize;
    {
        let mut archive = tar::Archive::new(&mut bounded);
        let entries = archive.entries().map_err(|error| {
            integrity_error(SupplyChainProvider::Grype, format!("invalid tar archive: {error}"))
        })?;
        for entry in entries {
            let mut entry = entry.map_err(|error| {
                integrity_error(SupplyChainProvider::Grype, format!("invalid tar entry: {error}"))
            })?;
            let entry_type = entry.header().entry_type();
            if entry_type.is_dir() {
                continue;
            }
            if !entry_type.is_file() {
                return Err(integrity_error(
                    SupplyChainProvider::Grype,
                    "Grype database archive contains a link or unsupported entry",
                ));
            }
            let relative_path = entry.path().map_err(|error| {
                integrity_error(
                    SupplyChainProvider::Grype,
                    format!("invalid tar entry path: {error}"),
                )
            })?;
            if relative_path.is_absolute()
                || relative_path
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(integrity_error(
                    SupplyChainProvider::Grype,
                    "Grype database archive contains an escaping path",
                ));
            }
            file_entries = file_entries.saturating_add(1);
            if file_entries > MAX_ENTRIES {
                return Err(integrity_error(
                    SupplyChainProvider::Grype,
                    "Grype database archive contains too many files",
                ));
            }
            std::io::copy(&mut entry, &mut std::io::sink())?;
        }
    }
    std::io::copy(&mut bounded, &mut std::io::sink())?;
    if file_entries == 0 || bounded.limit() == 0 {
        return Err(integrity_error(
            SupplyChainProvider::Grype,
            "Grype database archive is empty or exceeds its expansion limit",
        ));
    }
    Ok(())
}

fn validate_osv_archive(path: &Path, maximum_archive_bytes: usize) -> Result<()> {
    const MAX_ENTRIES: usize = 500_000;
    const MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_EXPANSION_MULTIPLIER: u64 = 16;

    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| integrity_error(SupplyChainProvider::Osv, error.to_string()))?;
    if archive.is_empty() || archive.len() > MAX_ENTRIES {
        return Err(integrity_error(
            SupplyChainProvider::Osv,
            "offline database has an invalid entry count",
        ));
    }
    let maximum_uncompressed = u64::try_from(maximum_archive_bytes)
        .unwrap_or(u64::MAX)
        .saturating_mul(MAX_EXPANSION_MULTIPLIER);
    let mut total_uncompressed = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| integrity_error(SupplyChainProvider::Osv, error.to_string()))?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || Path::new(&name).extension() != Some(std::ffi::OsStr::new("json"))
            || entry.size() > MAX_ENTRY_BYTES
        {
            return Err(integrity_error(
                SupplyChainProvider::Osv,
                "offline database contains an invalid advisory entry",
            ));
        }
        total_uncompressed = total_uncompressed.saturating_add(entry.size());
        if total_uncompressed > maximum_uncompressed {
            return Err(integrity_error(
                SupplyChainProvider::Osv,
                "offline database exceeds its bounded expansion limit",
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
        Read::by_ref(&mut entry).take(MAX_ENTRY_BYTES.saturating_add(1)).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ENTRY_BYTES {
            return Err(integrity_error(
                SupplyChainProvider::Osv,
                "offline advisory exceeds its entry limit",
            ));
        }
        let advisory: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            integrity_error(
                SupplyChainProvider::Osv,
                format!("offline advisory is not valid JSON: {error}"),
            )
        })?;
        let valid = advisory.get("id").and_then(serde_json::Value::as_str).is_some_and(|id| {
            !id.is_empty() && name.strip_suffix(".json").is_some_and(|stem| stem == id)
        }) && advisory
            .get("modified")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|modified| !modified.is_empty())
            && advisory.get("affected").and_then(serde_json::Value::as_array).is_some();
        if !valid {
            return Err(integrity_error(
                SupplyChainProvider::Osv,
                "offline advisory does not satisfy the OSV record contract",
            ));
        }
    }
    Ok(())
}

fn inventory_artifacts(root: &Path, maximum_total_bytes: usize) -> Result<Vec<SnapshotArtifact>> {
    let canonical_root = root.canonicalize()?;
    let mut pending = vec![canonical_root.join("cache")];
    let mut artifacts = Vec::new();
    let mut total = 0usize;
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(ScorchError::Config(
                    "provider cache inventory must not contain symlinks".to_string(),
                ));
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let metadata = entry.metadata()?;
                total = total.saturating_add(usize::try_from(metadata.len()).unwrap_or(usize::MAX));
                if total > maximum_total_bytes {
                    return Err(ScorchError::Config(
                        "provider cache inventory exceeds its byte limit".to_string(),
                    ));
                }
                let canonical = entry.path().canonicalize()?;
                if !canonical.starts_with(&canonical_root) {
                    return Err(ScorchError::Config(
                        "provider cache artifact escaped staging".to_string(),
                    ));
                }
                artifacts.push(SnapshotArtifact {
                    relative_path: canonical
                        .strip_prefix(&canonical_root)
                        .map_err(|error| ScorchError::Config(error.to_string()))?
                        .to_path_buf(),
                    sha256: sha256_file(&canonical)?,
                });
            }
        }
    }
    artifacts.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if artifacts.is_empty() {
        return Err(ScorchError::Config(
            "provider cache import produced no scanner artifacts".to_string(),
        ));
    }
    Ok(artifacts)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut hasher = Sha256::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn integrity_error(provider: SupplyChainProvider, reason: impl Into<String>) -> ScorchError {
    ScorchError::ProviderIntegrity {
        provider: provider.id().to_string(),
        reason: scorchkit_core::observation::redact_text(&reason.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::EngagementPolicy;
    use crate::engine::scope::ScopeRule;
    use crate::runner::subprocess::ToolOutput;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn valid_request(provider: SupplyChainProvider) -> ProviderRefreshRequest {
        let relative_path = match provider {
            SupplyChainProvider::Osv => "cache/osv-scanner/Rust/all.zip",
            SupplyChainProvider::Grype => "downloads/grype-db.tar.zst",
            SupplyChainProvider::Trivy => "cache/trivy.db",
        };
        ProviderRefreshRequest {
            provider,
            snapshot_id: "fixture".to_string(),
            schema_version: "v1".to_string(),
            downloads: vec![ProviderDownload {
                url: Url::parse("https://example.test/provider").expect("URL"),
                relative_path: PathBuf::from(relative_path),
                sha256: "ab".repeat(32),
            }],
            upstream_built_at: None,
            maximum_age_seconds: 60,
        }
    }

    fn write_osv_archive(path: &Path, name: &str, bytes: &[u8]) {
        let file = File::create(path).expect("OSV archive");
        let mut writer = zip::ZipWriter::new(file);
        writer.start_file(name, zip::write::SimpleFileOptions::default()).expect("start advisory");
        writer.write_all(bytes).expect("write advisory");
        writer.finish().expect("finish archive");
    }

    fn osv_archive_bytes() -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("GHSA-fixture.json", zip::write::SimpleFileOptions::default())
            .expect("start advisory");
        writer
            .write_all(br#"{"id":"GHSA-fixture","modified":"2026-08-20T00:00:00Z","affected":[]}"#)
            .expect("write advisory");
        writer.finish().expect("finish archive").into_inner()
    }

    #[tokio::test]
    async fn requests_reject_path_escape_and_trivy_refresh_before_effects() {
        let request = ProviderRefreshRequest {
            provider: SupplyChainProvider::Osv,
            snapshot_id: "fixture".to_string(),
            schema_version: "osv-v1".to_string(),
            downloads: vec![ProviderDownload {
                url: Url::parse("https://example.test/all.zip").expect("URL"),
                relative_path: PathBuf::from("../escape.zip"),
                sha256: "00".repeat(32),
            }],
            upstream_built_at: None,
            maximum_age_seconds: 60,
        };
        assert!(validate_request(&request).is_err());

        let mut duplicate = request.clone();
        duplicate.downloads[0].relative_path = PathBuf::from("cache/osv-scanner/Rust/all.zip");
        duplicate.downloads.push(duplicate.downloads[0].clone());
        assert!(validate_request(&duplicate).is_err());

        let cache = tempfile::tempdir().expect("cache");
        #[cfg(unix)]
        fs::set_permissions(cache.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let snapshots = SupplyChainSnapshotStore::open(cache.path(), 1024).expect("store");
        let service = ProviderRefreshService::new(
            Arc::new(Engagement::new("empty", EngagementPolicy::default())),
            Arc::new(AppConfig::default()),
            snapshots,
        );
        let mut trivy = request;
        trivy.provider = SupplyChainProvider::Trivy;
        trivy.downloads[0].relative_path = PathBuf::from("cache/db.tar.gz");
        assert!(matches!(service.refresh(&trivy).await, Err(ScorchError::Config(_))));
    }

    #[test]
    fn local_state_and_provider_capabilities_remain_separate() {
        let cache = tempfile::tempdir().expect("cache");
        let cache_path = cache.path().canonicalize().expect("cache path");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&cache_path).expect("cache scope"))
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive);
        let engagement = Engagement::new("fixture", policy);
        assert!(
            engagement
                .authorize(
                    PolicyTarget::Code(cache_path),
                    Capability::LocalState,
                    EffectClass::Passive
                )
                .allowed
        );
        assert!(
            !engagement
                .authorize(
                    PolicyTarget::Web(Url::parse("https://example.test").expect("URL")),
                    Capability::ProviderRefresh,
                    EffectClass::Passive
                )
                .allowed
        );
    }

    #[tokio::test]
    async fn authorization_audit_event_redacts_provider_url_secrets() {
        let endpoint =
            Url::parse("https://example.test/provider?access_token=provider-fixture-secret")
                .expect("provider URL");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("example.test").expect("provider scope"))
            .allow_capability(Capability::ProviderRefresh)
            .allow_effect(EffectClass::Passive);
        let engagement = Engagement::new("fixture", policy);
        let decision = engagement.authorize(
            PolicyTarget::Web(endpoint),
            Capability::ProviderRefresh,
            EffectClass::Passive,
        );
        let events = EventBus::default();
        let mut receiver = events.subscribe();

        publish_authorization(&events, "provider_download", &decision);

        let event = receiver.recv().await.expect("authorization event");
        let encoded = serde_json::to_string(&event).expect("serialize event");
        assert!(encoded.contains("supply_chain.authorization"));
        assert!(encoded.contains("provider_download"));
        assert!(!encoded.contains("provider-fixture-secret"));
    }

    #[test]
    fn staging_cleanup_removes_failed_refresh_state_and_preserves_promoted_state() {
        let root = tempfile::tempdir().expect("refresh root");
        let abandoned = root.path().join("abandoned");
        fs::create_dir(&abandoned).expect("abandoned stage");
        fs::write(abandoned.join("partial"), b"partial").expect("partial download");
        drop(StagingCleanup::new(abandoned.clone()));
        assert!(!abandoned.exists());

        let promoted = root.path().join("promoted");
        fs::create_dir(&promoted).expect("promoted stage");
        let mut cleanup = StagingCleanup::new(promoted.clone());
        cleanup.disarm();
        drop(cleanup);
        assert!(promoted.exists());
    }

    #[test]
    fn grype_status_requires_a_valid_database_inside_the_owned_cache() {
        let root = tempfile::tempdir().expect("Grype cache root");
        let cache = root.path().join("cache");
        fs::create_dir(&cache).expect("cache");
        let database = cache.join("vulnerability.db");
        fs::write(&database, b"fixture database").expect("database");
        let valid = serde_json::json!({
            "schemaVersion": "v6.1.3",
            "path": database,
            "valid": true,
            "error": null,
        });
        validate_grype_status(&valid.to_string(), &cache).expect("valid status");

        let invalid = serde_json::json!({
            "schemaVersion": "v6.1.3",
            "path": cache.join("vulnerability.db"),
            "valid": false,
            "error": "database is stale",
        });
        assert!(validate_grype_status(&invalid.to_string(), &cache).is_err());

        let outside = root.path().join("outside.db");
        fs::write(&outside, b"outside").expect("outside database");
        let escaped = serde_json::json!({
            "schemaVersion": "v6.1.3",
            "path": outside,
            "valid": true,
            "error": null,
        });
        assert!(validate_grype_status(&escaped.to_string(), &cache).is_err());
    }

    #[test]
    fn osv_archives_require_bounded_schema_valid_advisories() {
        let root = tempfile::tempdir().expect("archive fixture");
        let valid_path = root.path().join("valid.zip");
        let valid = File::create(&valid_path).expect("valid archive");
        let mut writer = zip::ZipWriter::new(valid);
        writer
            .start_file("GHSA-fixture.json", zip::write::SimpleFileOptions::default())
            .expect("start advisory");
        writer
            .write_all(br#"{"id":"GHSA-fixture","modified":"2026-08-20T00:00:00Z","affected":[]}"#)
            .expect("write advisory");
        writer.finish().expect("finish archive");
        validate_osv_archive(&valid_path, 1024 * 1024).expect("valid OSV archive");

        let invalid_path = root.path().join("invalid.zip");
        let invalid = File::create(&invalid_path).expect("invalid archive");
        let mut writer = zip::ZipWriter::new(invalid);
        writer
            .start_file("GHSA-fixture.json", zip::write::SimpleFileOptions::default())
            .expect("start advisory");
        writer.write_all(br#"{"id":"different"}"#).expect("write invalid advisory");
        writer.finish().expect("finish invalid archive");
        assert!(validate_osv_archive(&invalid_path, 1024 * 1024).is_err());
    }

    #[test]
    fn grype_archives_are_structurally_validated_before_import() {
        let root = tempfile::tempdir().expect("archive fixture");
        let path = root.path().join("grype-db.tar.zst");
        let file = File::create(&path).expect("Grype archive");
        let encoder = zstd::stream::write::Encoder::new(file, 1).expect("Zstandard encoder");
        let mut archive = tar::Builder::new(encoder);
        let payload = b"fixture database";
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(payload.len()).expect("payload size"));
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, "6/vulnerability.db", &payload[..])
            .expect("database entry");
        let encoder = archive.into_inner().expect("finish tar");
        encoder.finish().expect("finish Zstandard stream");

        validate_grype_archive(&path, 8 * 1024).expect("valid Grype archive");
        assert!(validate_grype_archive(&path, 512).is_err());
    }

    #[test]
    fn provider_ids_and_policy_age_limits_are_exact() {
        assert_eq!(SupplyChainProvider::Osv.id(), "osv");
        assert_eq!(SupplyChainProvider::Grype.id(), "grype");
        assert_eq!(SupplyChainProvider::Trivy.id(), "trivy");
        let mut config = AppConfig::default();
        config.supply_chain.osv_maximum_age_seconds = 11;
        config.supply_chain.grype_maximum_age_seconds = 22;
        config.supply_chain.trivy_maximum_age_seconds = 33;
        assert_eq!(provider_policy_maximum_age(&config, SupplyChainProvider::Osv), 11);
        assert_eq!(provider_policy_maximum_age(&config, SupplyChainProvider::Grype), 22);
        assert_eq!(provider_policy_maximum_age(&config, SupplyChainProvider::Trivy), 33);
    }

    #[test]
    fn refresh_request_validation_rejects_each_field_independently() {
        assert!(validate_request(&valid_request(SupplyChainProvider::Osv)).is_ok());
        assert!(validate_request(&valid_request(SupplyChainProvider::Grype)).is_ok());

        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.snapshot_id.clear();
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.schema_version.clear();
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.downloads.clear();
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.maximum_age_seconds = 0;
        assert!(validate_request(&invalid).is_err());

        let mut boundary = valid_request(SupplyChainProvider::Osv);
        boundary.downloads = (0..MAX_PROVIDER_DOWNLOADS)
            .map(|index| ProviderDownload {
                url: Url::parse(&format!("https://example.test/{index}")).unwrap(),
                relative_path: PathBuf::from(format!("cache/osv-scanner/Ecosystem{index}/all.zip")),
                sha256: "ab".repeat(32),
            })
            .collect();
        assert!(validate_request(&boundary).is_ok());
        boundary.downloads.push(ProviderDownload {
            url: Url::parse("https://example.test/overflow").unwrap(),
            relative_path: PathBuf::from("cache/osv-scanner/Overflow/all.zip"),
            sha256: "ab".repeat(32),
        });
        assert!(validate_request(&boundary).is_err());

        let mut grype = valid_request(SupplyChainProvider::Grype);
        grype.downloads.push(grype.downloads[0].clone());
        assert!(validate_request(&grype).is_err());
        let mut osv = valid_request(SupplyChainProvider::Osv);
        osv.downloads.push(ProviderDownload {
            url: Url::parse("https://example.test/Go").unwrap(),
            relative_path: PathBuf::from("cache/osv-scanner/Go/all.zip"),
            sha256: "ab".repeat(32),
        });
        assert!(validate_request(&osv).is_ok());
    }

    #[test]
    fn refresh_request_artifact_descriptor_checks_are_independent() {
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.downloads[0].relative_path = PathBuf::from("/absolute/all.zip");
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.downloads[0].relative_path = PathBuf::from("cache/osv-scanner/../all.zip");
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Grype);
        invalid.downloads[0].relative_path = PathBuf::from("downloads/../grype-db.tar.zst");
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.downloads[0].sha256 = "ab".repeat(31);
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.downloads[0].sha256 = format!("{}g", "a".repeat(63));
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.downloads[0].relative_path = PathBuf::from("downloads/Rust/all.zip");
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.downloads[0].relative_path = PathBuf::from("cache/osv-scanner/all.zip");
        assert!(validate_request(&invalid).is_err());
        let mut invalid = valid_request(SupplyChainProvider::Osv);
        invalid.downloads[0].relative_path = PathBuf::from("cache/osv-scanner/Rust/not-all.zip");
        assert!(validate_request(&invalid).is_err());
        let mut duplicate = valid_request(SupplyChainProvider::Osv);
        duplicate.downloads.push(duplicate.downloads[0].clone());
        assert!(validate_request(&duplicate).is_err());
    }

    #[test]
    fn grype_status_checks_validity_schema_error_and_path_independently() {
        let root = tempfile::tempdir().expect("Grype cache root");
        let cache = root.path().join("cache");
        fs::create_dir(&cache).expect("cache");
        let database = cache.join("vulnerability.db");
        fs::write(&database, b"fixture database").expect("database");

        let invalid_false = serde_json::json!({
            "schemaVersion":"v1","path":database,"valid":false,"error":null
        });
        assert!(validate_grype_status(&invalid_false.to_string(), &cache).is_err());
        let empty_schema = serde_json::json!({
            "schemaVersion":" ","path":database,"valid":true,"error":null
        });
        assert!(validate_grype_status(&empty_schema.to_string(), &cache).is_err());
        let nominal_error = serde_json::json!({
            "schemaVersion":"v1","path":database,"valid":true,"error":"corrupt"
        });
        assert!(validate_grype_status(&nominal_error.to_string(), &cache).is_err());
        let whitespace_error = serde_json::json!({
            "schemaVersion":"v1","path":database,"valid":true,"error":"  "
        });
        assert!(validate_grype_status(&whitespace_error.to_string(), &cache).is_ok());
        let directory_path = serde_json::json!({
            "schemaVersion":"v1","path":cache,"valid":true,"error":null
        });
        assert!(validate_grype_status(&directory_path.to_string(), &cache).is_err());
    }

    #[tokio::test]
    async fn subprocess_audit_event_preserves_operation_and_redacts_program() {
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        publish_subprocess(&events, "tool --token=fixture-secret", "grype_database_import");
        let event = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("subprocess event timeout")
            .expect("subprocess event");
        let encoded = serde_json::to_string(&event).expect("serialize event");
        assert!(encoded.contains("effect.subprocess_started"));
        assert!(encoded.contains("grype_database_import"));
        assert!(!encoded.contains("fixture-secret"));
    }

    #[test]
    fn cleanup_removes_download_work_and_import_configuration_only() {
        let root = tempfile::tempdir().expect("refresh root");
        for directory in ["downloads", "work", "cache"] {
            fs::create_dir(root.path().join(directory)).expect("refresh directory");
        }
        fs::write(root.path().join("grype-import.yaml"), b"fixture").expect("import config");
        fs::write(root.path().join("cache/database.bin"), b"preserve").expect("cache artifact");
        cleanup_refresh_state(root.path()).expect("cleanup");
        assert!(!root.path().join("downloads").exists());
        assert!(!root.path().join("work").exists());
        assert!(!root.path().join("grype-import.yaml").exists());
        assert_eq!(fs::read(root.path().join("cache/database.bin")).unwrap(), b"preserve");
    }

    #[test]
    fn provider_archive_format_checks_the_exact_grype_magic() {
        let root = tempfile::tempdir().expect("archive fixture");
        let path = root.path().join("grype-db.tar.zst");
        let file = File::create(&path).expect("Grype archive");
        let encoder = zstd::stream::write::Encoder::new(file, 1).expect("encoder");
        let mut archive = tar::Builder::new(encoder);
        let payload = b"fixture database";
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive.append_data(&mut header, "6/vulnerability.db", &payload[..]).unwrap();
        archive.into_inner().unwrap().finish().unwrap();
        validate_download_format(SupplyChainProvider::Grype, &path, 8 * 1024)
            .expect("valid Grype archive");
    }

    #[test]
    fn osv_record_contract_rejects_each_invalid_field_independently() {
        let root = tempfile::tempdir().expect("archive fixture");
        let cases = [
            ("wrong.json", br#"{"id":"GHSA-fixture","modified":"now","affected":[]}"#.as_slice()),
            (
                "GHSA-fixture.txt",
                br#"{"id":"GHSA-fixture","modified":"now","affected":[]}"#.as_slice(),
            ),
            (
                "nested/GHSA-fixture.json",
                br#"{"id":"GHSA-fixture","modified":"now","affected":[]}"#.as_slice(),
            ),
            (
                "GHSA\\fixture.json",
                br#"{"id":"GHSA-fixture","modified":"now","affected":[]}"#.as_slice(),
            ),
            ("GHSA-fixture.json", br#"{"id":"","modified":"now","affected":[]}"#.as_slice()),
            (
                "GHSA-fixture.json",
                br#"{"id":"GHSA-fixture","modified":"","affected":[]}"#.as_slice(),
            ),
            (
                "GHSA-fixture.json",
                br#"{"id":"GHSA-fixture","modified":"now","affected":{}}"#.as_slice(),
            ),
        ];
        for (index, (name, bytes)) in cases.into_iter().enumerate() {
            let path = root.path().join(format!("invalid-{index}.zip"));
            write_osv_archive(&path, name, bytes);
            assert!(validate_osv_archive(&path, 1024 * 1024).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn osv_expansion_limit_is_inclusive_and_preserves_the_multiplier() {
        let root = tempfile::tempdir().expect("archive fixture");
        let path = root.path().join("boundary.zip");
        let mut padding = String::new();
        let bytes = loop {
            let candidate = format!(
                "{{\"id\":\"GHSA-fixture\",\"modified\":\"now\",\"affected\":[],\"details\":\"{padding}\"}}"
            )
            .into_bytes();
            if candidate.len() % 16 == 0 {
                break candidate;
            }
            padding.push('x');
        };
        write_osv_archive(&path, "GHSA-fixture.json", &bytes);
        validate_osv_archive(&path, bytes.len() / 16).expect("exact expansion boundary");
        assert!(validate_osv_archive(&path, bytes.len() / 16 - 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn artifact_inventory_is_nonempty_bounded_and_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("inventory root");
        fs::create_dir(root.path().join("cache")).expect("cache");
        fs::write(root.path().join("cache/a.bin"), b"1234").expect("artifact");
        let artifacts = inventory_artifacts(root.path(), 4).expect("exact byte boundary");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].relative_path, PathBuf::from("cache/a.bin"));
        assert_eq!(artifacts[0].sha256, scorchkit_core::sha256_hex(b"1234"));
        assert!(inventory_artifacts(root.path(), 3).is_err());

        fs::remove_file(root.path().join("cache/a.bin")).unwrap();
        assert!(inventory_artifacts(root.path(), 4).is_err());
        let outside = root.path().join("outside.bin");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.path().join("cache/redirect.bin")).unwrap();
        assert!(inventory_artifacts(root.path(), 1024).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn digest_owned_write_and_private_directory_helpers_have_real_effects() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().expect("helper root");
        let file = root.path().join("artifact.bin");
        fs::write(&file, b"fixture").expect("artifact");
        assert_eq!(sha256_file(&file).unwrap(), scorchkit_core::sha256_hex(b"fixture"));

        let owned = root.path().join("owned.bin");
        write_new_synced(&owned, b"owned").expect("owned write");
        assert_eq!(fs::read(&owned).unwrap(), b"owned");
        assert!(write_new_synced(&owned, b"replacement").is_err());

        let private = root.path().join("private");
        create_private_directory(&private).expect("private directory");
        assert!(private.is_dir());
        assert_eq!(fs::metadata(&private).unwrap().mode() & 0o777, 0o700);
        fs::set_permissions(&private, PermissionsExt::from_mode(0o700)).unwrap();
        assert!(create_private_directory(&private).is_err());
    }

    #[derive(Debug, Default)]
    struct SequencedExecutor {
        outputs: Mutex<VecDeque<ToolOutput>>,
        invocations: Mutex<Vec<ToolInvocation>>,
    }

    #[async_trait::async_trait]
    impl ToolExecutor for SequencedExecutor {
        async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
            self.invocations.lock().unwrap().push(invocation);
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| ScorchError::Config("missing executor output".to_string()))
        }
    }

    fn output(stdout: String) -> ToolOutput {
        ToolOutput {
            stdout,
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::ZERO,
            resolved_program: PathBuf::from("/fixture/grype"),
        }
    }

    #[tokio::test]
    async fn grype_import_executes_version_import_and_typed_status_in_order() {
        let cache_root = tempfile::tempdir().expect("cache root");
        #[cfg(unix)]
        fs::set_permissions(cache_root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let snapshots = SupplyChainSnapshotStore::open(cache_root.path(), 1024 * 1024).unwrap();
        let cache_path = cache_root.path().canonicalize().unwrap();
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&cache_path).unwrap())
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Passive);
        let mut service = ProviderRefreshService::new(
            Arc::new(Engagement::new("fixture", policy)),
            Arc::new(AppConfig::default()),
            snapshots,
        );
        let stage = cache_root.path().join("stage");
        for directory in ["downloads", "cache", "work"] {
            fs::create_dir_all(stage.join(directory)).unwrap();
        }
        fs::write(stage.join("downloads/grype-db.tar.zst"), b"archive").unwrap();
        let database = stage.join("cache/vulnerability.db");
        fs::write(&database, b"database").unwrap();
        let status = serde_json::json!({
            "schemaVersion":"v1","path":database,"valid":true,"error":null
        })
        .to_string();
        let executor = Arc::new(SequencedExecutor {
            outputs: Mutex::new(VecDeque::from([
                output(format!("grype {GRYPE_VERSION}")),
                output(String::new()),
                output(status.clone()),
            ])),
            invocations: Mutex::new(Vec::new()),
        });
        service.executor = executor.clone();
        let events = EventBus::default();
        service
            .import_grype_database(&valid_request(SupplyChainProvider::Grype), &stage, &events)
            .await
            .expect("Grype import");
        let invocations = executor.invocations.lock().unwrap();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[0].args, ["--version"]);
        assert_eq!(invocations[0].output_limit_bytes, 16 * 1024);
        assert!(invocations[1].args.windows(2).any(|pair| pair == ["db", "import"]));
        assert!(invocations[2].args.windows(2).any(|pair| pair == ["db", "status"]));
        drop(invocations);
        assert_eq!(
            fs::read_to_string(stage.join("cache/scorchkit-grype-status.json")).unwrap(),
            status
        );
    }

    #[tokio::test]
    async fn osv_refresh_accepts_the_exact_cumulative_limit_and_matching_digests() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

        let body = osv_archive_bytes();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request).await.expect("read request");
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    server_body.len()
                );
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(&server_body).await.unwrap();
            }
        });

        let cache = tempfile::tempdir().expect("cache root");
        #[cfg(unix)]
        fs::set_permissions(cache.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let cache_path = cache.path().canonicalize().unwrap();
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&cache_path).unwrap())
            .allow_scope(ScopeRule::parse("127.0.0.1").unwrap())
            .allow_capability(Capability::LocalState)
            .allow_capability(Capability::ProviderRefresh)
            .allow_effect(EffectClass::Passive);
        let mut config = AppConfig::default();
        config.supply_chain.provider_download_limit_bytes = body.len() * 2;
        config.supply_chain.osv_maximum_age_seconds = 600;
        let snapshots = SupplyChainSnapshotStore::open(cache.path(), body.len() * 2).unwrap();
        let service = ProviderRefreshService::new(
            Arc::new(Engagement::new("OSV refresh fixture", policy)),
            Arc::new(config),
            snapshots,
        );
        let digest = scorchkit_core::sha256_hex(&body);
        let request = ProviderRefreshRequest {
            provider: SupplyChainProvider::Osv,
            snapshot_id: "osv-boundary".to_string(),
            schema_version: "osv-v1".to_string(),
            downloads: ["Rust", "Go"]
                .into_iter()
                .map(|ecosystem| ProviderDownload {
                    url: Url::parse(&format!("http://{address}/{ecosystem}/all.zip")).unwrap(),
                    relative_path: PathBuf::from(format!("cache/osv-scanner/{ecosystem}/all.zip")),
                    sha256: digest.clone(),
                })
                .collect(),
            upstream_built_at: None,
            maximum_age_seconds: 60,
        };
        let snapshot = service.refresh(&request).await.expect("OSV refresh");
        assert_eq!(snapshot.provider, "osv");
        assert_eq!(snapshot.snapshot_id, "osv-boundary");
        assert_eq!(snapshot.state, scorchkit_core::ProviderSnapshotState::Ready);
        assert!(snapshot.consumer_path.join("osv-scanner/Rust/all.zip").is_file());
        assert!(snapshot.consumer_path.join("osv-scanner/Go/all.zip").is_file());
        assert!(!snapshot.canonical_path.join("downloads").exists());
        assert!(!snapshot.canonical_path.join("work").exists());
        server.await.expect("server task");
    }

    #[test]
    fn archive_and_refresh_limits_remain_explicit_at_defense_in_depth_boundaries() {
        let production = include_str!("refresh.rs").split("#[cfg(test)]").next().unwrap();
        let compact: String = production.split_whitespace().collect();
        for invariant in [
            "download.relative_path.is_absolute()||download.relative_path.components().any(|component|!matches!(component,std::path::Component::Normal(_)))",
            "ifrelative_path.is_absolute()||relative_path.components().any(|component|!matches!(component,std::path::Component::Normal(_)))",
            "iffile_entries>MAX_ENTRIES",
            "constMAX_ENTRY_BYTES:u64=16*1024*1024;",
            "ifarchive.is_empty()||archive.len()>MAX_ENTRIES",
            "ifname.is_empty()||name.contains('/')||name.contains('\\\\')||Path::new(&name).extension()!=Some(std::ffi::OsStr::new(\"json\"))||entry.size()>MAX_ENTRY_BYTES",
            "ifu64::try_from(bytes.len()).unwrap_or(u64::MAX)>MAX_ENTRY_BYTES",
        ] {
            assert!(compact.contains(invariant), "refresh guard changed: {invariant}");
        }
    }
}
