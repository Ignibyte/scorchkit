use std::fs::File;
#[cfg(not(target_os = "linux"))]
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};

use scorchkit_core::sha256_hex;
use scorchkit_extension::{
    ExtensionManifestV1, MAX_EXTENSION_MODULE_BYTES, MAX_EXTENSION_TEXT_BYTES,
};

use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::{Capability, EffectClass, Engagement, PolicyTarget};
use crate::engine::scan_context::ScanContext;

const MAX_MANIFEST_BYTES: usize = MAX_EXTENSION_TEXT_BYTES * 16;

/// Exact validated manifest and module bytes retained for execution.
#[derive(Debug, Clone)]
pub struct LoadedExtension {
    pub manifest: ExtensionManifestV1,
    pub(crate) manifest_bytes: Vec<u8>,
    pub manifest_path: PathBuf,
    pub module_path: PathBuf,
    pub module_bytes: Vec<u8>,
    pub(super) catalog_identity: Option<super::catalog_host::CatalogExecutionIdentity>,
}

impl LoadedExtension {
    /// Open, authorize, validate, and retain one exact manifest/module pair.
    ///
    /// # Errors
    ///
    /// Returns an authorization, I/O, manifest, compatibility, or digest error without starting
    /// an extension worker.
    pub fn load(context: &ScanContext, manifest_path: &Path) -> Result<Self> {
        Self::load_authorized(&context.config.extensions, manifest_path, &|path| {
            context.authorize_extension_input(path)
        })
    }

    pub(crate) fn load_for_catalog(
        config: &crate::config::ExtensionConfig,
        engagement: &Engagement,
        manifest_path: &Path,
    ) -> Result<Self> {
        let loaded = Self::load_authorized(config, manifest_path, &|path| {
            let target = PolicyTarget::Code(path.to_path_buf());
            engagement
                .authorize(target.clone(), Capability::LocalState, EffectClass::Passive)
                .require()?;
            engagement
                .authorize(target, Capability::ExtensionExecute, EffectClass::Passive)
                .require()?;
            Ok(())
        })?;
        loaded.require_v1_web_adapter()?;
        Ok(loaded)
    }

    pub(crate) fn require_v1_web_adapter(&self) -> Result<()> {
        if !self.manifest.adapter.target_kinds.iter().all(|kind| {
            matches!(
                kind,
                scorchkit_core::AdapterTargetKind::WebApplication
                    | scorchkit_core::AdapterTargetKind::Api
            )
        }) || self.manifest.adapter.output_contract
            != scorchkit_core::AdapterOutputContract::Json
        {
            return Err(ScorchError::Config(
                "v1 web extension requires only web/API targets and JSON output".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn load_authorized(
        config: &crate::config::ExtensionConfig,
        manifest_path: &Path,
        authorize: &dyn Fn(&Path) -> Result<()>,
    ) -> Result<Self> {
        config.validate().map_err(|reason| {
            ScorchError::Config(format!("invalid extension configuration: {reason}"))
        })?;
        let (manifest_path, manifest_bytes) =
            open_bounded(manifest_path, MAX_MANIFEST_BYTES, authorize)?;
        let manifest: ExtensionManifestV1 = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| ScorchError::Config("invalid extension manifest JSON".to_string()))?;
        manifest
            .validate()
            .map_err(|error| ScorchError::Config(format!("invalid extension manifest: {error}")))?;
        manifest.require_compatible_engine(env!("CARGO_PKG_VERSION")).map_err(|error| {
            ScorchError::Config(format!("incompatible extension manifest: {error}"))
        })?;

        let parent = manifest_path.parent().ok_or_else(|| {
            ScorchError::Config("extension manifest has no parent directory".to_string())
        })?;
        let candidate = parent.join(&manifest.module.file);
        let module_limit = usize::try_from(MAX_EXTENSION_MODULE_BYTES).map_err(|_| {
            ScorchError::Config("extension module limit is unsupported on this host".to_string())
        })?;
        let (module_path, module_bytes) = open_bounded(&candidate, module_limit, authorize)?;
        if module_path.parent() != Some(parent) {
            return Err(ScorchError::Config(
                "extension module must remain beside its manifest".to_string(),
            ));
        }
        if sha256_hex(&module_bytes) != manifest.module.sha256 {
            return Err(ScorchError::Config("extension module digest mismatch".to_string()));
        }
        Ok(Self {
            manifest,
            manifest_bytes,
            manifest_path,
            module_path,
            module_bytes,
            catalog_identity: None,
        })
    }
}

pub(super) fn open_bounded(
    path: &Path,
    limit: usize,
    authorize: &dyn Fn(&Path) -> Result<()>,
) -> Result<(PathBuf, Vec<u8>)> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ScorchError::Config(format!("extension input '{}' is unavailable: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ScorchError::Config(format!(
            "extension input '{}' must be a regular non-symlink file",
            path.display()
        )));
    }
    let canonical = path.canonicalize()?;
    authorize(&canonical)?;
    let mut file = open_no_follow(&canonical)?;
    let opened = file.metadata()?;
    if !opened.is_file() || canonical.canonicalize()? != canonical {
        return Err(ScorchError::Config(format!(
            "extension input '{}' changed during validation",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current = std::fs::metadata(&canonical)?;
        if opened.dev() != current.dev() || opened.ino() != current.ino() {
            return Err(ScorchError::Config(format!(
                "extension input '{}' was replaced during validation",
                path.display()
            )));
        }
    }
    let read_limit = u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    Read::by_ref(&mut file).take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(ScorchError::Config(format!(
            "extension input '{}' exceeds {limit} bytes",
            path.display()
        )));
    }
    Ok((canonical, bytes))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_open_accepts_the_exact_limit_and_rejects_overflow() {
        assert_eq!(MAX_MANIFEST_BYTES, 65_536);
        let directory = tempfile::tempdir().expect("fixture directory");
        let path = directory.path().join("input.bin");
        std::fs::write(&path, b"abcd").expect("fixture file");
        assert_eq!(open_bounded(&path, 4, &|_| Ok(())).expect("exact boundary").1, b"abcd");
        assert!(open_bounded(&path, 3, &|_| Ok(()))
            .expect_err("one-byte overflow")
            .to_string()
            .contains("exceeds 3 bytes"));

        let error = open_bounded(directory.path(), 4, &|_| Ok(()))
            .expect_err("directory is not a regular file");
        assert!(error.to_string().contains("regular non-symlink file"));
    }

    #[test]
    fn bounded_open_pins_both_preopen_and_postopen_identity_guards() {
        let production =
            include_str!("loader.rs").split("#[cfg(test)]").next().expect("production source");
        let compact: String = production.split_whitespace().collect();
        assert!(compact.contains("metadata.file_type().is_symlink()||!metadata.is_file()"));
        assert!(compact.contains("!opened.is_file()||canonical.canonicalize()?!=canonical"));
        #[cfg(unix)]
        assert!(compact.contains("opened.dev()!=current.dev()||opened.ino()!=current.ino()"));
    }
}
