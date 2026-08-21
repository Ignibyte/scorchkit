use std::collections::HashSet;
#[cfg(not(target_os = "linux"))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};
use scorchkit_config::NucleiConfig;
use scorchkit_core::{canonical_json_sha256, sha256_hex, Result, ScorchError};
use scorchkit_policy::EffectClass;
use serde::{Deserialize, Serialize};

use crate::engine::scan_context::ScanContext;

use super::classifier::classify_template;
use super::NUCLEI_COLLECTION_SCHEMA_V1;

const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;
const MAX_TEMPLATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TEMPLATE_COUNT: usize = 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARTIFACT_FILES: u64 = 10_000;
const MAX_TIMEOUT_SECONDS: u64 = 60 * 60;
const MAX_RATE_PER_SECOND: u64 = 1000;
const MAX_CONCURRENCY: usize = 64;
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 120;
const WORKSPACE_FIXED_ENTRIES: u64 = 10;
const WORKSPACE_IGNORE_BYTES: u64 = 19;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NucleiCollectionManifest {
    schema_version: String,
    collection_id: String,
    version: String,
    signer: NucleiCollectionSigner,
    templates: Vec<NucleiCollectionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NucleiCollectionSigner {
    identity: String,
    certificate: String,
    certificate_sha256: String,
    signature_fragment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NucleiCollectionEntry {
    id: String,
    path: String,
    sha256: String,
    strongest_effect: EffectClass,
    reviewed_by: String,
    reviewed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct VerifiedNucleiTemplate {
    pub id: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VerifiedNucleiCollection {
    pub identity: String,
    pub signer_identity: String,
    pub certificate_bytes: Vec<u8>,
    pub strongest_effect: EffectClass,
    pub templates: Vec<VerifiedNucleiTemplate>,
}

pub fn load_collection(
    context: &ScanContext,
    configured_manifest: &Path,
    config: &NucleiConfig,
) -> Result<VerifiedNucleiCollection> {
    validate_limits(config)?;
    let mut manifest_file = open_regular_file(configured_manifest, None)?;
    context.authorize_local_state(&manifest_file.canonical_path)?;
    let manifest_bytes = read_bounded(
        &mut manifest_file.file,
        &manifest_file.canonical_path,
        config.manifest_limit_bytes,
    )?;
    let manifest: NucleiCollectionManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            ScorchError::Config(format!("invalid trusted Nuclei collection manifest: {error}"))
        })?;
    validate_manifest_header(&manifest, config)?;

    let root = manifest_file
        .canonical_path
        .parent()
        .ok_or_else(|| ScorchError::Config("Nuclei manifest has no parent directory".to_string()))?
        .canonicalize()?;
    let mut certificate_file = open_relative_file(&root, &manifest.signer.certificate)?;
    context.authorize_local_state(&certificate_file.canonical_path)?;
    let certificate_bytes = read_bounded(
        &mut certificate_file.file,
        &certificate_file.canonical_path,
        config.certificate_limit_bytes,
    )?;
    let mut owned_input_bytes = add_workspace_bytes(
        WORKSPACE_IGNORE_BYTES,
        certificate_bytes.len(),
        config.artifact_limit_bytes,
    )?;
    require_digest(
        "trusted Nuclei certificate",
        &certificate_bytes,
        &manifest.signer.certificate_sha256,
    )?;

    let mut ids = HashSet::new();
    let mut paths = HashSet::new();
    let mut templates = Vec::with_capacity(manifest.templates.len());
    let mut strongest_effect = EffectClass::Passive;
    for entry in &manifest.templates {
        validate_entry(entry)?;
        if !ids.insert(entry.id.clone()) {
            return Err(ScorchError::Config(format!(
                "trusted Nuclei collection repeats template id '{}'",
                entry.id
            )));
        }
        if !paths.insert(entry.path.clone()) {
            return Err(ScorchError::Config(format!(
                "trusted Nuclei collection repeats template path '{}'",
                entry.path
            )));
        }
        let mut template_file = open_relative_file(&root, &entry.path)?;
        context.authorize_local_state(&template_file.canonical_path)?;
        let bytes = read_bounded(
            &mut template_file.file,
            &template_file.canonical_path,
            config.template_limit_bytes,
        )?;
        owned_input_bytes =
            add_workspace_bytes(owned_input_bytes, bytes.len(), config.artifact_limit_bytes)?;
        require_digest(&format!("Nuclei template '{}'", entry.id), &bytes, &entry.sha256)?;
        require_signature_fragment(&bytes, &entry.id, &manifest.signer.signature_fragment)?;
        let classification = classify_template(&bytes, &entry.id)?;
        require_effect_floor(&entry.id, entry.strongest_effect, classification.effect_floor)?;
        strongest_effect = strongest_effect.max(entry.strongest_effect);
        templates.push(VerifiedNucleiTemplate {
            id: entry.id.clone(),
            sha256: entry.sha256.clone(),
            bytes,
        });
    }

    let identity_digest = canonical_json_sha256(
        &serde_json::to_value(&manifest)
            .map_err(|error| ScorchError::Config(format!("serialize Nuclei manifest: {error}")))?,
    );
    Ok(VerifiedNucleiCollection {
        identity: format!(
            "{}@{}:sha256:{identity_digest}",
            manifest.collection_id, manifest.version
        ),
        signer_identity: manifest.signer.identity,
        certificate_bytes,
        strongest_effect,
        templates,
    })
}

fn validate_limits(config: &NucleiConfig) -> Result<()> {
    if config.manifest_limit_bytes == 0
        || config.certificate_limit_bytes == 0
        || config.template_limit_bytes == 0
        || config.template_limit_count == 0
        || config.output_limit_bytes == 0
        || config.artifact_limit_bytes == 0
        || config.artifact_limit_files == 0
        || config.timeout_seconds == 0
        || config.rate_limit_per_second == 0
        || config.concurrency == 0
        || config.request_timeout_seconds == 0
    {
        return Err(ScorchError::Config(
            "trusted Nuclei limits, timeouts, rate, and concurrency must be positive".to_string(),
        ));
    }
    if config.manifest_limit_bytes > MAX_MANIFEST_BYTES
        || config.certificate_limit_bytes > MAX_CERTIFICATE_BYTES
        || config.template_limit_bytes > MAX_TEMPLATE_BYTES
        || config.template_limit_count > MAX_TEMPLATE_COUNT
        || config.output_limit_bytes > MAX_OUTPUT_BYTES
        || config.artifact_limit_bytes > MAX_ARTIFACT_BYTES
        || config.artifact_limit_files > MAX_ARTIFACT_FILES
        || config.timeout_seconds > MAX_TIMEOUT_SECONDS
        || config.rate_limit_per_second > MAX_RATE_PER_SECOND
        || config.concurrency > MAX_CONCURRENCY
        || config.request_timeout_seconds > MAX_REQUEST_TIMEOUT_SECONDS
    {
        return Err(ScorchError::Config(
            "trusted Nuclei configuration exceeds a hard safety limit".to_string(),
        ));
    }
    Ok(())
}

fn validate_manifest_header(
    manifest: &NucleiCollectionManifest,
    config: &NucleiConfig,
) -> Result<()> {
    if manifest.schema_version != NUCLEI_COLLECTION_SCHEMA_V1 {
        return Err(ScorchError::Config(format!(
            "unsupported Nuclei collection schema '{}'",
            manifest.schema_version
        )));
    }
    for (field, value) in [
        ("collection_id", manifest.collection_id.as_str()),
        ("version", manifest.version.as_str()),
        ("signer.identity", manifest.signer.identity.as_str()),
    ] {
        if value.is_empty() {
            return Err(ScorchError::Config(format!(
                "trusted Nuclei manifest {field} has an invalid identity"
            )));
        }
        if value.len() > 128 {
            return Err(ScorchError::Config(format!(
                "trusted Nuclei manifest {field} has an invalid identity"
            )));
        }
        if !value.bytes().all(is_identity_byte) {
            return Err(ScorchError::Config(format!(
                "trusted Nuclei manifest {field} has an invalid identity"
            )));
        }
    }
    require_sha256("certificate_sha256", &manifest.signer.certificate_sha256)?;
    if manifest.signer.signature_fragment.len() != 32 {
        return Err(ScorchError::Config(
            "trusted Nuclei signer fragment must be 32 lowercase hexadecimal characters"
                .to_string(),
        ));
    }
    if !is_lower_hex(&manifest.signer.signature_fragment) {
        return Err(ScorchError::Config(
            "trusted Nuclei signer fragment must be 32 lowercase hexadecimal characters"
                .to_string(),
        ));
    }
    if manifest.templates.is_empty() {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei collection must contain 1..={} templates",
            config.template_limit_count
        )));
    }
    if manifest.templates.len() > config.template_limit_count {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei collection must contain 1..={} templates",
            config.template_limit_count
        )));
    }
    let template_entries = u64::try_from(manifest.templates.len()).unwrap_or(u64::MAX);
    if template_entries.saturating_add(WORKSPACE_FIXED_ENTRIES) > config.artifact_limit_files {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei collection exceeds the workspace entry budget of {}",
            config.artifact_limit_files
        )));
    }
    Ok(())
}

fn add_workspace_bytes(current: u64, additional: usize, limit: u64) -> Result<u64> {
    let total = current.saturating_add(u64::try_from(additional).unwrap_or(u64::MAX));
    if total > limit {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei collection exceeds the workspace byte budget of {limit}"
        )));
    }
    Ok(total)
}

fn require_effect_floor(
    template_id: &str,
    declared: EffectClass,
    required: EffectClass,
) -> Result<()> {
    if declared < required {
        return Err(ScorchError::Config(format!(
            "Nuclei template '{template_id}' declares {declared:?} below its {required:?} behavior floor"
        )));
    }
    Ok(())
}

fn validate_entry(entry: &NucleiCollectionEntry) -> Result<()> {
    if entry.id.is_empty()
        || entry.id.len() > 192
        || !entry.id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei template id '{}' is invalid",
            entry.id
        )));
    }
    if entry.reviewed_by.trim().is_empty() || entry.reviewed_by.len() > 256 {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei template '{}' has no valid reviewer identity",
            entry.id
        )));
    }
    require_sha256(&format!("template '{}' sha256", entry.id), &entry.sha256)
}

struct OpenedNucleiInput {
    canonical_path: PathBuf,
    file: File,
}

fn open_relative_file(root: &Path, relative: &str) -> Result<OpenedNucleiInput> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei path '{}' is not a strict relative path",
            relative.display()
        )));
    }
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            unreachable!("relative components were validated")
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(ScorchError::Config(format!(
                "trusted Nuclei path '{}' contains a symbolic link",
                relative.display()
            )));
        }
    }
    open_regular_file(&current, Some(root))
}

fn open_regular_file(path: &Path, root: Option<&Path>) -> Result<OpenedNucleiInput> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei input '{}' is not a regular non-symlink file",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei input '{}' is not a regular non-symlink file",
            path.display()
        )));
    }
    let canonical = path.canonicalize()?;
    if root.is_some_and(|root| !canonical.starts_with(root)) {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei input '{}' escapes its collection root",
            path.display()
        )));
    }
    let file = open_no_follow(&canonical)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei input '{}' changed after path validation",
            path.display()
        )));
    }
    if canonical.canonicalize()? != canonical {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei input '{}' changed after path validation",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let current_metadata = fs::metadata(&canonical)?;
        if opened_metadata.dev() != current_metadata.dev() {
            return Err(ScorchError::Config(format!(
                "trusted Nuclei input '{}' was replaced during validation",
                path.display()
            )));
        }
        if opened_metadata.ino() != current_metadata.ino() {
            return Err(ScorchError::Config(format!(
                "trusted Nuclei input '{}' was replaced during validation",
                path.display()
            )));
        }
    }
    Ok(OpenedNucleiInput { canonical_path: canonical, file })
}

fn open_no_follow(path: &Path) -> Result<File> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags, ResolveFlags};

        let descriptor = rustix::fs::openat2(
            rustix::fs::ABS,
            path,
            OFlags::RDONLY.union(OFlags::CLOEXEC).union(OFlags::NOFOLLOW),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS),
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
        Ok(File::from(descriptor))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        Ok(options.open(path)?)
    }
}

fn read_bounded(file: &mut File, path: &Path, limit: usize) -> Result<Vec<u8>> {
    let read_limit = u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    Read::by_ref(file).take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei input '{}' exceeds {limit} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn require_digest(component: &str, bytes: &[u8], expected: &str) -> Result<()> {
    require_sha256(component, expected)?;
    let actual = sha256_hex(bytes);
    if actual != expected {
        return Err(ScorchError::Config(format!(
            "{component} digest mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn require_signature_fragment(bytes: &[u8], template_id: &str, expected: &str) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        ScorchError::Config(format!("Nuclei template '{template_id}' is not UTF-8"))
    })?;
    let digest =
        text.lines().rev().find_map(|line| line.trim().strip_prefix("# digest: ")).ok_or_else(
            || ScorchError::Config(format!("Nuclei template '{template_id}' is unsigned")),
        )?;
    let (signature, fragment) = digest.rsplit_once(':').ok_or_else(|| {
        ScorchError::Config(format!("Nuclei template '{template_id}' has a malformed signature"))
    })?;
    if signature.is_empty() || !is_lower_hex(signature) || signature.len() % 2 != 0 {
        return Err(ScorchError::Config(format!(
            "Nuclei template '{template_id}' has a malformed signature"
        )));
    }
    if fragment != expected {
        return Err(ScorchError::Config(format!(
            "Nuclei template '{template_id}' signer fragment is not trusted"
        )));
    }
    Ok(())
}

fn require_sha256(component: &str, digest: &str) -> Result<()> {
    if digest.len() != 64 || !is_lower_hex(digest) {
        return Err(ScorchError::Config(format!(
            "trusted Nuclei {component} must be a lowercase SHA-256"
        )));
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

const fn is_identity_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'@')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_fixture() -> NucleiCollectionManifest {
        NucleiCollectionManifest {
            schema_version: NUCLEI_COLLECTION_SCHEMA_V1.to_string(),
            collection_id: "fixture".to_string(),
            version: "1".to_string(),
            signer: NucleiCollectionSigner {
                identity: "reviewer".to_string(),
                certificate: "reviewer.crt".to_string(),
                certificate_sha256: "a".repeat(64),
                signature_fragment: "b".repeat(32),
            },
            templates: vec![NucleiCollectionEntry {
                id: "probe".to_string(),
                path: "probe.yaml".to_string(),
                sha256: "c".repeat(64),
                strongest_effect: EffectClass::ActiveSafe,
                reviewed_by: "reviewer".to_string(),
                reviewed_at: Utc::now(),
            }],
        }
    }

    #[test]
    fn signature_fragment_requires_exact_trusted_suffix() {
        let signed = b"id: probe\n# digest: aabb:0123456789abcdef0123456789abcdef\n";
        assert!(
            require_signature_fragment(signed, "probe", "0123456789abcdef0123456789abcdef").is_ok()
        );
        assert!(require_signature_fragment(signed, "probe", "ffffffffffffffffffffffffffffffff")
            .is_err());
        assert!(require_signature_fragment(b"id: probe\n", "probe", "fragment").is_err());
    }

    #[test]
    fn strict_relative_paths_reject_every_escape_shape() {
        let root = tempfile::tempdir().expect("collection root");
        fs::write(root.path().join("probe.yaml"), "id: probe").expect("template");
        assert!(open_relative_file(root.path(), "probe.yaml").is_ok());
        for path in ["", "/tmp/probe.yaml", "../probe.yaml", "a/../probe.yaml", "./probe.yaml"] {
            assert!(open_relative_file(root.path(), path).is_err(), "accepted {path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn collection_paths_reject_symlinked_files_and_parent_components() {
        let root = tempfile::tempdir().expect("collection root");
        let directory = root.path().join("templates");
        fs::create_dir(&directory).expect("templates");
        fs::write(directory.join("probe.yaml"), "id: probe").expect("template");
        std::os::unix::fs::symlink(directory.join("probe.yaml"), root.path().join("linked.yaml"))
            .expect("link");
        assert!(open_relative_file(root.path(), "linked.yaml").is_err());
        assert!(open_regular_file(&root.path().join("linked.yaml"), None).is_err());
        assert!(open_relative_file(root.path(), "templates/probe.yaml").is_ok());
    }

    #[test]
    fn regular_input_open_rejects_directories() {
        let root = tempfile::tempdir().expect("input root");
        assert!(open_regular_file(root.path(), None).is_err());
    }

    #[test]
    fn bounded_reader_preserves_exact_limit_and_rejects_one_byte_over() {
        let file = tempfile::NamedTempFile::new().expect("input");
        fs::write(file.path(), b"1234").expect("bytes");
        let mut input = open_regular_file(file.path(), None).expect("open input");
        assert_eq!(
            read_bounded(&mut input.file, &input.canonical_path, 4).expect("exact"),
            b"1234"
        );
        let mut input = open_regular_file(file.path(), None).expect("reopen input");
        assert!(read_bounded(&mut input.file, &input.canonical_path, 3).is_err());
    }

    #[test]
    fn bounded_reader_consumes_the_validated_handle_after_path_replacement() {
        let root = tempfile::tempdir().expect("input root");
        let path = root.path().join("probe.yaml");
        let original = root.path().join("original.yaml");
        fs::write(&path, b"approved bytes").expect("approved input");
        let mut input = open_regular_file(&path, Some(root.path())).expect("validated input");

        fs::rename(&path, &original).expect("retain original inode");
        fs::write(&path, b"replacement bytes").expect("replacement input");

        assert_eq!(
            read_bounded(&mut input.file, &input.canonical_path, 64).expect("same-handle read"),
            b"approved bytes"
        );
    }

    #[test]
    fn runtime_limits_require_positive_values_with_non_overridable_ceilings() {
        assert!(validate_limits(&NucleiConfig::default()).is_ok());

        let zero = NucleiConfig { concurrency: 0, ..NucleiConfig::default() };
        assert!(validate_limits(&zero).is_err());

        let excessive =
            NucleiConfig { output_limit_bytes: MAX_OUTPUT_BYTES + 1, ..NucleiConfig::default() };
        assert!(validate_limits(&excessive).is_err());

        let excessive =
            NucleiConfig { timeout_seconds: MAX_TIMEOUT_SECONDS + 1, ..NucleiConfig::default() };
        assert!(validate_limits(&excessive).is_err());

        let excessive = NucleiConfig {
            rate_limit_per_second: MAX_RATE_PER_SECOND + 1,
            ..NucleiConfig::default()
        };
        assert!(validate_limits(&excessive).is_err());
    }

    #[test]
    fn collection_inputs_observe_exact_aggregate_workspace_budgets() {
        assert_eq!(add_workspace_bytes(20, 4, 24).expect("exact byte budget"), 24);
        assert!(add_workspace_bytes(20, 5, 24).is_err());

        let manifest = manifest_fixture();
        let exact = NucleiConfig {
            artifact_limit_files: WORKSPACE_FIXED_ENTRIES + 1,
            template_limit_count: 1,
            ..NucleiConfig::default()
        };
        assert!(validate_manifest_header(&manifest, &exact).is_ok());
        let short = NucleiConfig {
            artifact_limit_files: WORKSPACE_FIXED_ENTRIES,
            ..NucleiConfig::default()
        };
        assert!(validate_manifest_header(&manifest, &short).is_err());
    }

    #[test]
    fn manifest_header_rejects_each_independent_boundary() {
        let exact = NucleiConfig { template_limit_count: 1, ..NucleiConfig::default() };
        assert!(validate_manifest_header(&manifest_fixture(), &exact).is_ok());

        let mut manifest = manifest_fixture();
        manifest.collection_id = "c".repeat(128);
        assert!(validate_manifest_header(&manifest, &exact).is_ok());

        let mut manifest = manifest_fixture();
        manifest.collection_id.clear();
        assert!(validate_manifest_header(&manifest, &exact).is_err());

        let mut manifest = manifest_fixture();
        manifest.version = "v".repeat(129);
        assert!(validate_manifest_header(&manifest, &exact).is_err());

        let mut manifest = manifest_fixture();
        manifest.signer.identity = "invalid/identity".to_string();
        assert!(validate_manifest_header(&manifest, &exact).is_err());

        let mut manifest = manifest_fixture();
        manifest.signer.signature_fragment = "b".repeat(31);
        assert!(validate_manifest_header(&manifest, &exact).is_err());

        let mut manifest = manifest_fixture();
        manifest.signer.signature_fragment = "G".repeat(32);
        assert!(validate_manifest_header(&manifest, &exact).is_err());

        let mut manifest = manifest_fixture();
        manifest.templates.clear();
        assert!(validate_manifest_header(&manifest, &exact).is_err());

        let mut manifest = manifest_fixture();
        manifest.templates.push(manifest.templates[0].clone());
        assert!(validate_manifest_header(&manifest, &exact).is_err());
    }

    #[test]
    fn declared_template_effect_cannot_understate_classified_behavior() {
        assert!(
            require_effect_floor("probe", EffectClass::Passive, EffectClass::ActiveSafe).is_err()
        );
        assert!(
            require_effect_floor("probe", EffectClass::ActiveSafe, EffectClass::ActiveSafe).is_ok()
        );
        assert!(
            require_effect_floor("probe", EffectClass::Intrusive, EffectClass::ActiveSafe).is_ok()
        );
    }
}
