use std::path::{Path, PathBuf};

use crate::config::ReportConfig;
use crate::engine::error::Result;
use crate::engine::scan_result::ScanResult;

/// Save a scan result as a JSON file. Returns the path to the saved file.
///
/// # Errors
///
/// Returns an error if serialization fails or the file cannot be written.
pub fn save_report(result: &ScanResult, config: &ReportConfig) -> Result<PathBuf> {
    let output_dir = &config.output_dir;
    std::fs::create_dir_all(output_dir)?;

    let filename = format!("scorchkit-{}.json", result.scan_id);
    let path = output_dir.join(&filename);

    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(&path, json)?;

    Ok(path)
}

/// Load a scan result from a JSON file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or deserialization fails.
pub fn load_report(path: &Path) -> Result<ScanResult> {
    let content = std::fs::read_to_string(path)?;
    let result: ScanResult = serde_json::from_str(&content)?;
    Ok(result)
}
