use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use scorchkit_core::{Result, ScorchError};
use tempfile::{Builder, TempDir};

use super::collection::VerifiedNucleiCollection;

pub const RESULT_FILE: &str = "reports/findings.jsonl";

pub struct NucleiWorkspace {
    root: TempDir,
    home: PathBuf,
    config: PathBuf,
    cache: PathBuf,
    temporary: PathBuf,
    certificate: PathBuf,
    templates: Vec<PathBuf>,
}

impl NucleiWorkspace {
    pub fn create(collection: &VerifiedNucleiCollection) -> Result<Self> {
        let root = Builder::new().prefix("scorchkit-nuclei-").tempdir()?;
        set_directory_permissions(root.path())?;
        let home = create_private_directory(root.path(), "home")?;
        let config = create_private_directory(root.path(), "config")?;
        let nuclei_config = create_private_directory(&config, "nuclei")?;
        write_private_file(&nuclei_config.join(".nuclei-ignore"), b"tags: []\nfiles: []\n")?;
        let cache = create_private_directory(root.path(), "cache")?;
        let temporary = create_private_directory(root.path(), "tmp")?;
        let template_root = create_private_directory(root.path(), "templates")?;
        create_private_directory(root.path(), "reports")?;

        let certificate = root.path().join("signer.crt");
        write_private_file(&certificate, &collection.certificate_bytes)?;
        let mut templates = Vec::with_capacity(collection.templates.len());
        for (index, template) in collection.templates.iter().enumerate() {
            let path = template_root.join(format!("template-{:03}.yaml", index + 1));
            write_private_file(&path, &template.bytes)?;
            templates.push(path);
        }
        Ok(Self { root, home, config, cache, temporary, certificate, templates })
    }

    pub fn root(&self) -> &Path {
        self.root.path()
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn config(&self) -> &Path {
        &self.config
    }

    pub fn cache(&self) -> &Path {
        &self.cache
    }

    pub fn temporary(&self) -> &Path {
        &self.temporary
    }

    pub fn certificate(&self) -> &Path {
        &self.certificate
    }

    pub fn templates(&self) -> &[PathBuf] {
        &self.templates
    }

    pub fn result_path(&self) -> PathBuf {
        self.root.path().join(RESULT_FILE)
    }

    pub fn read_results(&self, limit: usize) -> Result<Vec<u8>> {
        read_owned_artifact(self.root.path(), RESULT_FILE, limit)
    }
}

fn create_private_directory(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = root.join(relative);
    fs::create_dir(&path)?;
    set_directory_permissions(&path)?;
    Ok(path)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
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

fn read_owned_artifact(root: &Path, relative: &str, limit: usize) -> Result<Vec<u8>> {
    let canonical_root = root.canonicalize()?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|error| ScorchError::ToolOutputParse {
        tool: "nuclei".to_string(),
        reason: format!("required result artifact is unavailable: {error}"),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ScorchError::ToolOutputParse {
            tool: "nuclei".to_string(),
            reason: "required result artifact is not a regular file".to_string(),
        });
    }
    let canonical = path.canonicalize()?;
    if !canonical.starts_with(canonical_root) {
        return Err(ScorchError::ToolOutputParse {
            tool: "nuclei".to_string(),
            reason: "required result artifact escaped the owned workspace".to_string(),
        });
    }
    let mut file = File::open(canonical)?;
    let read_limit = u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    Read::by_ref(&mut file).take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(ScorchError::ToolOutputParse {
            tool: "nuclei".to_string(),
            reason: format!("required result artifact exceeds {limit} bytes"),
        });
    }
    Ok(bytes)
}

fn set_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_nuclei::collection::VerifiedNucleiTemplate;
    use scorchkit_policy::EffectClass;

    fn collection() -> VerifiedNucleiCollection {
        VerifiedNucleiCollection {
            identity: "fixture@1:sha256:abc".to_string(),
            signer_identity: "fixture".to_string(),
            certificate_bytes: b"fixture certificate".to_vec(),
            strongest_effect: EffectClass::ActiveSafe,
            templates: vec![VerifiedNucleiTemplate {
                id: "probe".to_string(),
                sha256: "b".repeat(64),
                bytes: b"id: probe".to_vec(),
            }],
        }
    }

    #[test]
    fn workspace_owns_exact_private_certificate_and_template_bytes() {
        let collection = collection();
        let workspace = NucleiWorkspace::create(&collection).expect("workspace");
        assert_eq!(fs::read(workspace.certificate()).expect("certificate"), b"fixture certificate");
        assert_eq!(fs::read(&workspace.templates()[0]).expect("template"), b"id: probe");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(workspace.root()).expect("root").permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&workspace.templates()[0]).expect("template").permissions().mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn result_artifact_requires_a_bounded_owned_regular_file() {
        let workspace = NucleiWorkspace::create(&collection()).expect("workspace");
        fs::write(workspace.result_path(), b"1234").expect("results");
        assert_eq!(workspace.read_results(4).expect("exact"), b"1234");
        assert!(workspace.read_results(3).is_err());
    }
}
