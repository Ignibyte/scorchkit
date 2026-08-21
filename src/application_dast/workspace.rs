use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use scorchkit_core::{Result, ScorchError};
use tempfile::{Builder, TempDir};

use super::schema::ValidatedDastSchema;

pub const PLAN_FILE: &str = "plan.yaml";
pub const URL_REPORT_FILE: &str = "reports/urls.txt";
pub const TRAFFIC_REPORT_FILE: &str = "reports/traffic.har";
pub const ALERT_REPORT_FILE: &str = "reports/zap-report.json";
pub const PERSONA_REPORT_FILE: &str = "reports/auth-report.json";
pub const PRE_DISCOVERY_TRACE_FILE: &str = "reports/authentication.har";

pub struct DastWorkspace {
    root: TempDir,
    home: PathBuf,
}

impl DastWorkspace {
    pub(crate) fn create() -> Result<Self> {
        let root = Builder::new().prefix("scorchkit-dast-").tempdir()?;
        set_directory_permissions(root.path())?;
        let home = root.path().join("home");
        create_private_directory(&home)?;
        create_private_directory(&root.path().join("schemas"))?;
        create_private_directory(&root.path().join("reports"))?;
        Ok(Self { root, home })
    }

    pub(crate) fn root(&self) -> &Path {
        self.root.path()
    }

    pub(crate) fn home(&self) -> &Path {
        &self.home
    }

    pub(crate) fn copy_schemas(&self, schemas: &[ValidatedDastSchema]) -> Result<Vec<PathBuf>> {
        schemas
            .iter()
            .enumerate()
            .map(|(index, schema)| {
                let extension = match schema.identity.kind {
                    scorchkit_core::ApplicationDastSchemaKind::OpenApi => "yaml",
                    scorchkit_core::ApplicationDastSchemaKind::GraphQl => "graphql",
                };
                let relative = PathBuf::from(format!(
                    "schemas/schema-{:03}.{extension}",
                    index.saturating_add(1)
                ));
                write_private_file(&self.root.path().join(&relative), &schema.bytes)?;
                Ok(relative)
            })
            .collect()
    }

    pub(crate) fn write_plan(&self, bytes: &[u8]) -> Result<PathBuf> {
        let path = self.root.path().join(PLAN_FILE);
        write_private_file(&path, bytes)?;
        Ok(path)
    }

    pub(crate) fn read_artifact(&self, relative: &str, limit: usize) -> Result<Vec<u8>> {
        let root = self.root.path().canonicalize()?;
        let path = self.root.path().join(relative);
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: format!("required artifact '{relative}' is unavailable: {error}"),
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: format!("required artifact '{relative}' is not a regular file"),
            });
        }
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&root) {
            return Err(ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: format!("required artifact '{relative}' escaped its owned workspace"),
            });
        }
        let mut file = File::open(&canonical)?;
        let read_limit = u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX);
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        Read::by_ref(&mut file).take(read_limit).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: format!("required artifact '{relative}' exceeds {limit} bytes"),
            });
        }
        Ok(bytes)
    }
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    set_directory_permissions(path)
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
    use scorchkit_core::{ApplicationDastSchemaIdentity, ApplicationDastSchemaKind};

    #[test]
    fn workspace_uses_private_owned_files() {
        let workspace = DastWorkspace::create().expect("workspace");
        let plan = workspace.write_plan(b"env: {}\n").expect("plan");
        assert_eq!(workspace.read_artifact(PLAN_FILE, 64).expect("read"), b"env: {}\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(workspace.root()).expect("root").permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(fs::metadata(plan).expect("plan").permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn workspace_copies_validated_schema_bytes_to_exact_relative_paths() {
        let workspace = DastWorkspace::create().expect("workspace");
        let schemas = [
            ValidatedDastSchema {
                bytes: b"openapi bytes".to_vec(),
                identity: ApplicationDastSchemaIdentity {
                    kind: ApplicationDastSchemaKind::OpenApi,
                    sha256: "a".repeat(64),
                    source_name: "openapi.yaml".to_string(),
                    endpoint: None,
                },
                operations: Vec::new(),
            },
            ValidatedDastSchema {
                bytes: b"graphql bytes".to_vec(),
                identity: ApplicationDastSchemaIdentity {
                    kind: ApplicationDastSchemaKind::GraphQl,
                    sha256: "b".repeat(64),
                    source_name: "schema.graphql".to_string(),
                    endpoint: Some("https://example.com/graphql".to_string()),
                },
                operations: Vec::new(),
            },
        ];

        let paths = workspace.copy_schemas(&schemas).expect("copy schemas");

        assert_eq!(
            paths,
            [PathBuf::from("schemas/schema-001.yaml"), PathBuf::from("schemas/schema-002.graphql"),]
        );
        assert_eq!(
            fs::read(workspace.root().join(&paths[0])).expect("OpenAPI copy"),
            b"openapi bytes"
        );
        assert_eq!(
            fs::read(workspace.root().join(&paths[1])).expect("GraphQL copy"),
            b"graphql bytes"
        );
    }

    #[test]
    fn artifact_reads_enforce_file_scope_and_exact_byte_limit() {
        let workspace = DastWorkspace::create().expect("workspace");
        fs::write(workspace.root().join("reports/exact.bin"), b"1234").expect("artifact");
        assert_eq!(workspace.read_artifact("reports/exact.bin", 4).expect("exact limit"), b"1234");
        assert!(workspace.read_artifact("reports/exact.bin", 3).is_err());
        assert!(matches!(
            workspace.read_artifact("reports", 32),
            Err(ScorchError::ToolOutputParse { reason, .. })
                if reason.contains("not a regular file")
        ));

        let mut outside =
            tempfile::NamedTempFile::new_in(workspace.root().parent().expect("workspace parent"))
                .expect("outside artifact");
        outside.write_all(b"outside").expect("outside bytes");
        let relative = format!(
            "../{}",
            outside.path().file_name().and_then(|value| value.to_str()).expect("outside name")
        );
        assert!(workspace.read_artifact(&relative, 32).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn artifact_reads_reject_symbolic_links() {
        let workspace = DastWorkspace::create().expect("workspace");
        let real = workspace.root().join("reports/real.bin");
        let link = workspace.root().join("reports/link.bin");
        fs::write(&real, b"artifact").expect("artifact");
        std::os::unix::fs::symlink(&real, &link).expect("artifact link");

        assert!(workspace.read_artifact("reports/link.bin", 32).is_err());
    }
}
