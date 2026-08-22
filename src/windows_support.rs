//! Small native-Windows filesystem contracts shared by scanner workspaces.
//!
//! Windows CI compiles and exercises these branches. The Linux-hosted mutation runner excludes
//! this target-only file because its mutations cannot affect a Linux executable test binary.

use std::fs;
use std::path::Path;

use crate::engine::error::{Result, ScorchError};

pub fn set_directory_permissions(path: &Path) -> Result<()> {
    fs::metadata(path)?;
    Ok(())
}

pub fn require_private_directory(path: &Path) -> Result<()> {
    fs::metadata(path)?;
    Ok(())
}

pub fn ensure_same_filesystem(left: &Path, right: &Path) -> Result<()> {
    let left = left.canonicalize()?;
    let right = right.canonicalize()?;
    if left.components().next().ne(&right.components().next()) {
        return Err(ScorchError::Config(
            "provider snapshot staging must use the cache filesystem".to_string(),
        ));
    }
    Ok(())
}
