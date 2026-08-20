//! Explicit local supply-chain target classification and bounded lockfile discovery.

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

use scorchkit_core::{SupplyChainTarget, SupplyChainTargetKind};

use crate::engine::error::{Result, ScorchError};

const MAX_DISCOVERY_ENTRIES: usize = 200_000;
const MAX_LOCKFILES: usize = 2_048;
const SKIPPED_DIRECTORIES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "vendor",
    "dist",
    "build",
    ".gradle",
];
const SUPPORTED_LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "Gemfile.lock",
    "Pipfile.lock",
    "bun.lock",
    "bun.lockb",
    "composer.lock",
    "go.mod",
    "gradle.lockfile",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "requirements.txt",
    "yarn.lock",
];

/// Verify that an already policy-canonicalized path has the exact requested local target shape.
///
/// This function never guesses a target kind from a string or extension and cannot represent an
/// image reference, registry, daemon, socket, or remote endpoint.
pub fn authorize_local_target_shape(
    canonical_path: &Path,
    kind: SupplyChainTargetKind,
    revision: Option<String>,
) -> Result<SupplyChainTarget> {
    if !canonical_path.is_absolute() {
        return Err(invalid_target(canonical_path, "target path must already be canonical"));
    }
    let metadata = fs::metadata(canonical_path).map_err(|error| ScorchError::InvalidTarget {
        target: canonical_path.display().to_string(),
        reason: format!("cannot inspect canonical local target: {error}"),
    })?;
    let expects_directory = matches!(
        kind,
        SupplyChainTargetKind::SourceDirectory
            | SupplyChainTargetKind::DirectoryArtifact
            | SupplyChainTargetKind::OciLayout
    );
    if expects_directory != metadata.is_dir() {
        return Err(invalid_target(
            canonical_path,
            if expects_directory {
                "selected target kind requires a directory"
            } else {
                "selected target kind requires a regular file"
            },
        ));
    }
    if !expects_directory && !metadata.is_file() {
        return Err(invalid_target(canonical_path, "target must be a regular file"));
    }

    let sha256 = if metadata.is_file() {
        Some(hash_bounded_file(canonical_path, 1024 * 1024 * 1024)?)
    } else {
        None
    };
    Ok(SupplyChainTarget { kind, canonical_path: canonical_path.to_path_buf(), revision, sha256 })
}

/// Discover supported source lockfiles without following links or broadening outside the target.
pub fn discover_supported_lockfiles(canonical_root: &Path) -> Result<Vec<PathBuf>> {
    if !canonical_root.is_absolute() || !canonical_root.is_dir() {
        return Err(invalid_target(
            canonical_root,
            "lockfile discovery requires a canonical source directory",
        ));
    }
    let mut queue = VecDeque::from([canonical_root.to_path_buf()]);
    let mut lockfiles = Vec::new();
    let mut entries_seen = 0usize;

    while let Some(directory) = queue.pop_front() {
        let mut entries = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > MAX_DISCOVERY_ENTRIES {
                return Err(invalid_target(
                    canonical_root,
                    "lockfile discovery entry limit exceeded",
                ));
            }
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if file_type.is_dir() {
                if !SKIPPED_DIRECTORIES.contains(&name.as_ref()) {
                    queue.push_back(path);
                }
                continue;
            }
            if file_type.is_file() && SUPPORTED_LOCKFILES.contains(&name.as_ref()) {
                let canonical = path.canonicalize()?;
                if !canonical.starts_with(canonical_root) {
                    return Err(invalid_target(
                        canonical_root,
                        "discovered lockfile escaped the authorized source root",
                    ));
                }
                lockfiles.push(canonical);
                if lockfiles.len() > MAX_LOCKFILES {
                    return Err(invalid_target(canonical_root, "lockfile count limit exceeded"));
                }
            }
        }
    }
    lockfiles.sort();
    lockfiles.dedup();
    Ok(lockfiles)
}

fn hash_bounded_file(path: &Path, maximum_bytes: usize) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = fs::File::open(path)?;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0usize;
    let mut hasher = Sha256::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        if total > maximum_bytes {
            return Err(ScorchError::InvalidTarget {
                target: path.display().to_string(),
                reason: format!("local artifact exceeds {maximum_bytes} byte authorization limit"),
            });
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn invalid_target(path: &Path, reason: impl Into<String>) -> ScorchError {
    ScorchError::InvalidTarget { target: path.display().to_string(), reason: reason.into() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn discovery_is_recursive_deterministic_and_skips_symlinks_and_build_trees() {
        let root = tempfile::tempdir().expect("temporary source");
        fs::create_dir_all(root.path().join("nested")).expect("nested");
        fs::create_dir_all(root.path().join("target")).expect("target");
        fs::File::create(root.path().join("nested/package-lock.json")).expect("lockfile");
        fs::File::create(root.path().join("Cargo.lock")).expect("lockfile");
        fs::File::create(root.path().join("target/yarn.lock")).expect("ignored lockfile");
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            root.path().join("Cargo.lock"),
            root.path().join("nested/yarn.lock"),
        )
        .expect("symlink");

        let canonical = root.path().canonicalize().expect("canonical root");
        let discovered = discover_supported_lockfiles(&canonical).expect("discovery");
        assert_eq!(discovered.len(), 2);
        assert!(discovered[0].ends_with("Cargo.lock"));
        assert!(discovered[1].ends_with("package-lock.json"));
    }

    #[test]
    fn target_kind_is_explicit_and_file_digest_is_recorded() {
        let root = tempfile::tempdir().expect("temporary target");
        let path = root.path().join("artifact.tar");
        let mut file = fs::File::create(&path).expect("artifact");
        file.write_all(b"fixture").expect("write artifact");
        let canonical = path.canonicalize().expect("canonical artifact");

        let target = authorize_local_target_shape(
            &canonical,
            SupplyChainTargetKind::FileArtifact,
            Some("revision".to_string()),
        )
        .expect("file target");
        assert_eq!(target.sha256, Some(scorchkit_core::sha256_hex(b"fixture")));
        assert!(authorize_local_target_shape(
            &canonical,
            SupplyChainTargetKind::DirectoryArtifact,
            None
        )
        .is_err());
    }

    #[test]
    fn artifact_authorization_preserves_the_one_gibibyte_limit_expression() {
        let root = tempfile::tempdir().expect("temporary target");
        let path = root.path().join("three-megabyte.bin");
        fs::write(&path, vec![0x5a; 3 * 1024 * 1024]).expect("artifact fixture");
        let canonical = path.canonicalize().expect("canonical artifact");
        let target =
            authorize_local_target_shape(&canonical, SupplyChainTargetKind::FileArtifact, None)
                .expect("authorized artifact");
        assert_eq!(target.sha256, Some(scorchkit_core::sha256_hex(&vec![0x5a; 3 * 1024 * 1024])));
    }

    #[test]
    fn discovery_requires_an_absolute_directory_and_ignores_unsupported_files() {
        let root = tempfile::tempdir().expect("temporary source");
        fs::write(root.path().join("README.md"), "fixture").expect("unsupported file");
        let canonical = root.path().canonicalize().expect("canonical root");
        assert!(discover_supported_lockfiles(Path::new("relative")).is_err());
        assert!(discover_supported_lockfiles(&root.path().join("README.md")).is_err());
        assert!(discover_supported_lockfiles(&canonical).expect("discovery").is_empty());
    }

    #[test]
    fn discovery_accepts_the_lockfile_limit_and_rejects_one_more() {
        let root = tempfile::tempdir().expect("temporary source");
        for index in 0..=MAX_LOCKFILES {
            let directory = root.path().join(format!("d{index:04}"));
            fs::create_dir(&directory).expect("fixture directory");
            fs::write(directory.join("Cargo.lock"), "# fixture").expect("lockfile");
        }
        let canonical = root.path().canonicalize().expect("canonical root");
        assert!(discover_supported_lockfiles(&canonical).is_err());

        fs::remove_file(root.path().join(format!("d{MAX_LOCKFILES:04}/Cargo.lock")))
            .expect("remove overflow lockfile");
        assert_eq!(
            discover_supported_lockfiles(&canonical).expect("boundary discovery").len(),
            MAX_LOCKFILES
        );
    }

    #[test]
    fn bounded_target_hash_accepts_the_exact_limit_only() {
        let root = tempfile::tempdir().expect("temporary target");
        let path = root.path().join("bounded.bin");
        fs::write(&path, b"1234").expect("artifact fixture");
        assert_eq!(hash_bounded_file(&path, 4).unwrap(), scorchkit_core::sha256_hex(b"1234"));
        assert!(hash_bounded_file(&path, 3).is_err());
    }

    #[test]
    fn discovery_entry_ceiling_remains_a_strict_greater_than_boundary() {
        assert_eq!(MAX_DISCOVERY_ENTRIES, 200_000);
        let production = include_str!("target.rs").split("#[cfg(test)]").next().unwrap();
        let compact: String = production.split_whitespace().collect();
        assert!(compact.contains("ifentries_seen>MAX_DISCOVERY_ENTRIES"));
    }
}
