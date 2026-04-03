use std::time::{Duration, Instant};

use crate::engine::error::{Result, ScorchError};

/// Output from running an external tool.
#[derive(Debug)]
pub struct ToolOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,
}

/// Run an external tool as a subprocess, capturing stdout and stderr.
///
/// # Errors
///
/// Returns an error if the tool is not found, exits with a non-zero status, or times out.
pub async fn run_tool(tool_name: &str, args: &[&str], timeout: Duration) -> Result<ToolOutput> {
    // Check tool exists
    let which =
        tokio::process::Command::new("which").arg(tool_name).output().await.map_err(|e| {
            ScorchError::ToolFailed {
                tool: tool_name.to_string(),
                status: -1,
                stderr: e.to_string(),
            }
        })?;

    if !which.status.success() {
        return Err(ScorchError::ToolNotFound { tool: tool_name.to_string() });
    }

    let start = Instant::now();

    let result =
        tokio::time::timeout(timeout, tokio::process::Command::new(tool_name).args(args).output())
            .await;

    let duration = start.elapsed();

    match result {
        Ok(Ok(output)) => {
            let exit_code = output.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if !output.status.success() {
                return Err(ScorchError::ToolFailed {
                    tool: tool_name.to_string(),
                    status: exit_code,
                    stderr,
                });
            }

            Ok(ToolOutput { stdout, stderr, exit_code, duration })
        }
        Ok(Err(e)) => Err(ScorchError::ToolFailed {
            tool: tool_name.to_string(),
            status: -1,
            stderr: e.to_string(),
        }),
        Err(_) => Err(ScorchError::Cancelled {
            reason: format!("{tool_name} timed out after {timeout:?}"),
        }),
    }
}
