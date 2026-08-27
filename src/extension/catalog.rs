use std::path::{Path, PathBuf};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ring::signature::{UnparsedPublicKey, ED25519};
use scorchkit_core::sha256_hex;
use scorchkit_extension::{
    ExtensionCatalogPayloadV1, ExtensionCatalogReleaseV1, ExtensionPermissionsV1,
    SignedExtensionCatalogV1, EXTENSION_CATALOG_ENVELOPE_SCHEMA_V1,
    EXTENSION_CATALOG_SIGNATURE_DOMAIN_V1, MAX_EXTENSION_CATALOG_BYTES,
    MAX_EXTENSION_CATALOG_PAYLOAD_BYTES,
};

use crate::config::ExtensionConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::{Capability, EffectClass, Engagement, PolicyTarget};
use crate::engine::scan_context::ScanContext;

use super::loader::{open_bounded, LoadedExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CatalogExecutionIdentity {
    pub approval_id: String,
    pub catalog_path: PathBuf,
    pub catalog_id: String,
    pub publisher_id: String,
    pub key_id: String,
    pub catalog_sequence: u64,
    pub catalog_checkpoint_sha256: String,
    pub payload_sha256: String,
    pub release_id: String,
    pub manifest_sha256: String,
    pub permissions_sha256: String,
    pub provenance_revision: String,
    pub provenance_build_sha256: String,
    pub conformance_report_sha256: String,
    pub network_endpoints: Vec<String>,
}

#[derive(Debug)]
pub(super) struct VerifiedCatalog {
    pub path: PathBuf,
    pub key_id: String,
    pub payload_sha256: String,
    pub payload: ExtensionCatalogPayloadV1,
}

#[derive(Debug)]
pub(super) struct VerifiedRelease {
    pub catalog_path: PathBuf,
    pub key_id: String,
    pub payload_sha256: String,
    pub payload: ExtensionCatalogPayloadV1,
    pub release: ExtensionCatalogReleaseV1,
    pub loaded: LoadedExtension,
}

pub(super) fn verify_catalog(
    config: &ExtensionConfig,
    engagement: &Engagement,
    catalog_path: &Path,
    now: DateTime<Utc>,
) -> Result<VerifiedCatalog> {
    config.validate().map_err(|reason| {
        ScorchError::Config(format!("invalid extension configuration: {reason}"))
    })?;
    let requested = absolute_path(catalog_path)?;
    if !config
        .catalogs
        .iter()
        .map(|path| absolute_path(path))
        .any(|path| path.is_ok_and(|path| path == requested))
    {
        return Err(catalog_error("catalog path is not explicitly configured"));
    }
    let (path, envelope_bytes) =
        open_bounded(catalog_path, MAX_EXTENSION_CATALOG_BYTES, &|path| {
            authorize_read(engagement, path)
        })?;
    let envelope: SignedExtensionCatalogV1 = serde_json::from_slice(&envelope_bytes)
        .map_err(|_| catalog_error("catalog envelope JSON is invalid"))?;
    if envelope.schema_version != EXTENSION_CATALOG_ENVELOPE_SCHEMA_V1 {
        return Err(catalog_error("catalog envelope schema is unsupported"));
    }
    let trust = config
        .trust_keys
        .iter()
        .find(|trust| trust.key_id == envelope.key_id)
        .ok_or_else(|| catalog_error("catalog signing key is not locally trusted"))?;
    let payload = decode_bounded(
        &envelope.payload_base64,
        MAX_EXTENSION_CATALOG_PAYLOAD_BYTES,
        "catalog payload",
    )?;
    if sha256_hex(&payload) != envelope.payload_sha256 {
        return Err(catalog_error("catalog payload digest mismatch"));
    }
    let public_key = decode_bounded(&trust.public_key_base64, 32, "catalog public key")?;
    if public_key.len() != 32 {
        return Err(catalog_error("catalog public key length is invalid"));
    }
    let signature = decode_bounded(&envelope.signature_base64, 64, "catalog signature")?;
    if signature.len() != 64 {
        return Err(catalog_error("catalog signature length is invalid"));
    }
    let mut signed =
        Vec::with_capacity(EXTENSION_CATALOG_SIGNATURE_DOMAIN_V1.len() + payload.len());
    signed.extend_from_slice(EXTENSION_CATALOG_SIGNATURE_DOMAIN_V1);
    signed.extend_from_slice(&payload);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, &signature)
        .map_err(|_| catalog_error("catalog signature verification failed"))?;
    let payload: ExtensionCatalogPayloadV1 = serde_json::from_slice(&payload)
        .map_err(|_| catalog_error("catalog payload JSON is invalid"))?;
    payload
        .validate_shape()
        .map_err(|error| catalog_error(&format!("catalog payload is invalid: {error}")))?;
    if payload.publisher_id != trust.publisher_id {
        return Err(catalog_error("catalog publisher does not match its trusted key"));
    }
    let valid_from = parse_time(&payload.valid_from)?;
    let valid_until = parse_time(&payload.valid_until)?;
    if valid_from >= valid_until || now < valid_from || now >= valid_until {
        return Err(catalog_error("catalog validity interval does not include the current time"));
    }
    for release in &payload.releases {
        let bytes = serde_json::to_vec(&release.permissions)
            .map_err(|_| catalog_error("catalog permissions cannot be encoded"))?;
        if sha256_hex(&bytes) != release.permissions_sha256 {
            return Err(catalog_error("catalog permission fingerprint mismatch"));
        }
    }
    Ok(VerifiedCatalog {
        path,
        key_id: envelope.key_id,
        payload_sha256: envelope.payload_sha256,
        payload,
    })
}

pub(super) fn verify_release(
    config: &ExtensionConfig,
    engagement: &Engagement,
    catalog_path: &Path,
    release_id: &str,
    now: DateTime<Utc>,
) -> Result<VerifiedRelease> {
    let catalog = verify_catalog(config, engagement, catalog_path, now)?;
    let release = catalog
        .payload
        .releases
        .iter()
        .find(|release| release.release_id == release_id)
        .cloned()
        .ok_or_else(|| catalog_error("catalog release identity is unavailable"))?;
    require_not_revoked(&catalog, &release.release_id, &catalog.key_id)?;
    let parent = catalog.path.parent().ok_or_else(|| catalog_error("catalog has no parent"))?;
    let manifest_path = parent.join(&release.manifest_file);
    let loaded = LoadedExtension::load_authorized(config, &manifest_path, &|path| {
        authorize_read(engagement, path)
    })?;
    loaded.require_v1_web_adapter()?;
    if sha256_hex(&loaded.manifest_bytes) != release.manifest_sha256
        || loaded.manifest.module.sha256 != release.module_sha256
        || loaded.manifest.id != release.extension_id
        || loaded.manifest.version != release.version
    {
        return Err(catalog_error("catalog release artifact identity mismatch"));
    }
    let normalized = ExtensionPermissionsV1::from_manifest(
        &loaded.manifest,
        release.permissions.network_endpoints.clone(),
    );
    if normalized != release.permissions
        || (!normalized.network_endpoints.is_empty()
            && !normalized
                .capabilities
                .contains(&scorchkit_extension::ExtensionCapabilityV1::NetworkHttp))
    {
        return Err(catalog_error("catalog permissions do not match the extension manifest"));
    }
    Ok(VerifiedRelease {
        catalog_path: catalog.path,
        key_id: catalog.key_id,
        payload_sha256: catalog.payload_sha256,
        payload: catalog.payload,
        release,
        loaded,
    })
}

pub(super) fn assert_not_revoked(context: &ScanContext, loaded: &LoadedExtension) -> Result<()> {
    let Some(identity) = &loaded.catalog_identity else {
        return Ok(());
    };
    for path in &context.config.extensions.catalogs {
        if !catalog_is_present(path)? {
            continue;
        }
        let catalog = verify_catalog(
            &context.config.extensions,
            context.active_engagement()?,
            path,
            Utc::now(),
        )?;
        if catalog.payload.catalog_id != identity.catalog_id {
            continue;
        }
        if catalog.payload.publisher_id != identity.publisher_id {
            return Err(catalog_error("catalog publisher identity changed after approval"));
        }
        match catalog.payload.sequence.cmp(&identity.catalog_sequence) {
            std::cmp::Ordering::Less => {
                return Err(catalog_error("catalog sequence regressed after approval"));
            }
            std::cmp::Ordering::Equal
                if catalog.payload_sha256 != identity.catalog_checkpoint_sha256 =>
            {
                return Err(catalog_error("catalog sequence payload equivocation was rejected"));
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {}
        }
        if let Some(reason) = revocation_reason(&catalog, &identity.release_id, &identity.key_id) {
            return Err(catalog_error(&format!("extension release is revoked: {reason}")));
        }
    }
    Ok(())
}

pub(super) fn catalog_is_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(catalog_error("configured catalog availability cannot be determined")),
    }
}

pub(super) fn require_not_revoked(
    catalog: &VerifiedCatalog,
    release_id: &str,
    key_id: &str,
) -> Result<()> {
    if let Some(reason) = revocation_reason(catalog, release_id, key_id) {
        return Err(catalog_error(&format!("extension release is revoked: {reason}")));
    }
    Ok(())
}

fn revocation_reason<'a>(
    catalog: &'a VerifiedCatalog,
    release_id: &str,
    key_id: &str,
) -> Option<&'a str> {
    catalog.payload.revocations.iter().find_map(|revocation| {
        (revocation.release_id.as_deref() == Some(release_id)
            || revocation.key_id.as_deref() == Some(key_id))
        .then_some(revocation.reason.as_str())
    })
}

pub(super) fn permission_sha256(value: &ExtensionPermissionsV1) -> Result<String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| catalog_error("extension permissions cannot be encoded"))
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| catalog_error("catalog validity timestamp is invalid"))
}

fn decode_bounded(value: &str, maximum: usize, field: &str) -> Result<Vec<u8>> {
    if value.len() > maximum.saturating_mul(2) {
        return Err(catalog_error(&format!("{field} exceeds its encoded boundary")));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| catalog_error(&format!("{field} is not valid base64")))?;
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(catalog_error(&format!("{field} exceeds its decoded boundary")));
    }
    Ok(decoded)
}

fn authorize_read(engagement: &Engagement, path: &Path) -> Result<()> {
    let target = PolicyTarget::Code(path.to_path_buf());
    engagement.authorize(target.clone(), Capability::LocalState, EffectClass::Passive).require()?;
    engagement.authorize(target, Capability::ExtensionExecute, EffectClass::Passive).require()?;
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir().map(|current| current.join(path)).map_err(ScorchError::from)
    }
}

pub(super) fn catalog_error(reason: &str) -> ScorchError {
    ScorchError::Config(format!("extension catalog: {reason}"))
}

pub(super) fn validate_module_health(loaded: &LoadedExtension) -> Result<()> {
    use wasmi::{Engine, ExternType, Linker, Module, Store};

    let engine = Engine::default();
    let module = Module::new(&engine, &loaded.module_bytes[..])
        .map_err(|_| catalog_error("extension module health validation failed"))?;
    if module.imports().next().is_some() {
        return Err(catalog_error("extension module health check rejected imports"));
    }
    let memory_count =
        module.exports().filter(|export| matches!(export.ty(), ExternType::Memory(_))).count();
    if memory_count != 1 || !matches!(module.get_export("memory"), Some(ExternType::Memory(_))) {
        return Err(catalog_error("extension module health check rejected its memory export"));
    }
    for name in ["scorchkit_abi_version", "scorchkit_reserve_input", "scorchkit_run"] {
        if !matches!(module.get_export(name), Some(ExternType::Func(_))) {
            return Err(catalog_error("extension module health check found a missing export"));
        }
    }
    let mut store = Store::new(&engine, ());
    let instance = Linker::new(&engine)
        .instantiate_and_start(&mut store, &module)
        .map_err(|_| catalog_error("extension module health startup failed"))?;
    let abi = instance
        .get_typed_func::<(), u32>(&store, "scorchkit_abi_version")
        .map_err(|_| catalog_error("extension module health ABI is invalid"))?;
    instance
        .get_typed_func::<u32, u32>(&store, "scorchkit_reserve_input")
        .map_err(|_| catalog_error("extension module health input ABI is invalid"))?;
    instance
        .get_typed_func::<u32, u64>(&store, "scorchkit_run")
        .map_err(|_| catalog_error("extension module health run ABI is invalid"))?;
    if abi.call(&mut store, ()).map_err(|_| catalog_error("extension module health ABI trapped"))?
        != scorchkit_extension::EXTENSION_ABI_V1
    {
        return Err(catalog_error("extension module health ABI is unsupported"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::scope::ScopeRule;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    #[test]
    fn bounded_decode_accepts_the_exact_encoded_precheck_boundary() {
        assert_eq!(decode_bounded("YQ==", 2, "fixture").expect("bounded decode"), b"a");
        assert!(decode_bounded("YWJj", 2, "fixture").is_err());
        assert!(decode_bounded("", 2, "fixture").is_err());
    }

    #[test]
    fn catalog_presence_distinguishes_absence_and_indeterminate_errors(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        assert!(!catalog_is_present(&directory.path().join("missing.json"))?);
        let present = directory.path().join("catalog.json");
        std::fs::write(&present, b"{}")?;
        assert!(catalog_is_present(&present)?);
        let overlong = directory.path().join("x".repeat(512));
        assert!(catalog_is_present(&overlong).is_err());
        Ok(())
    }

    #[test]
    fn catalog_reads_require_both_local_state_and_extension_authority(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("catalog.json");
        std::fs::write(&path, b"{}")?;
        let base = crate::engine::policy::EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(directory.path())?)
            .allow_effect(EffectClass::Passive);
        let extension_only = Engagement::new(
            "extension-only",
            base.clone().allow_capability(Capability::ExtensionExecute),
        );
        assert!(authorize_read(&extension_only, &path).is_err());
        let local_only =
            Engagement::new("local-only", base.clone().allow_capability(Capability::LocalState));
        assert!(authorize_read(&local_only, &path).is_err());
        let both = Engagement::new(
            "both",
            base.allow_capability(Capability::LocalState)
                .allow_capability(Capability::ExtensionExecute),
        );
        assert!(authorize_read(&both, &path).is_ok());
        Ok(())
    }

    #[test]
    fn absolute_path_preserves_absolute_inputs_and_resolves_relative_inputs(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let current = std::env::current_dir()?;
        let absolute = current.join("catalog.json");
        assert_eq!(absolute_path(&absolute)?, absolute);
        assert_eq!(absolute_path(Path::new("catalog.json"))?, current.join("catalog.json"));
        Ok(())
    }

    #[test]
    fn catalog_validity_includes_the_exact_start_instant(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("catalog.json");
        let key = Ed25519KeyPair::from_seed_unchecked(&[11_u8; 32])
            .map_err(|_| "deterministic Ed25519 fixture key was rejected")?;
        let valid_from = "2030-01-01T00:00:00Z";
        let payload = ExtensionCatalogPayloadV1 {
            schema_version: scorchkit_extension::EXTENSION_CATALOG_PAYLOAD_SCHEMA_V1.to_string(),
            catalog_id: "boundary.catalog".to_string(),
            publisher_id: "boundary.publisher".to_string(),
            sequence: 1,
            valid_from: valid_from.to_string(),
            valid_until: "2030-01-02T00:00:00Z".to_string(),
            releases: Vec::new(),
            revocations: Vec::new(),
        };
        let payload_bytes = serde_json::to_vec(&payload)?;
        let mut signed = EXTENSION_CATALOG_SIGNATURE_DOMAIN_V1.to_vec();
        signed.extend_from_slice(&payload_bytes);
        let envelope = SignedExtensionCatalogV1 {
            schema_version: EXTENSION_CATALOG_ENVELOPE_SCHEMA_V1.to_string(),
            key_id: "boundary.key".to_string(),
            payload_sha256: sha256_hex(&payload_bytes),
            payload_base64: base64::engine::general_purpose::STANDARD.encode(&payload_bytes),
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(key.sign(&signed).as_ref()),
        };
        std::fs::write(&path, serde_json::to_vec(&envelope)?)?;
        let config = ExtensionConfig {
            catalogs: vec![path.clone()],
            trust_keys: vec![crate::config::ExtensionTrustKeyConfig {
                key_id: "boundary.key".to_string(),
                publisher_id: "boundary.publisher".to_string(),
                public_key_base64: base64::engine::general_purpose::STANDARD
                    .encode(key.public_key().as_ref()),
            }],
            ..ExtensionConfig::default()
        };
        let engagement = Engagement::new(
            "catalog-boundary",
            crate::engine::policy::EngagementPolicy::default()
                .allow_scope(ScopeRule::path_prefix(directory.path())?)
                .allow_capability(Capability::LocalState)
                .allow_capability(Capability::ExtensionExecute)
                .allow_effect(EffectClass::Passive),
        );
        let instant = DateTime::parse_from_rfc3339(valid_from)?.with_timezone(&Utc);
        assert!(verify_catalog(&config, &engagement, &path, instant).is_ok());
        Ok(())
    }
}
