use std::io;

/// Unified error type for `ScorchKit`.
#[derive(Debug, thiserror::Error)]
pub enum ScorchError {
    #[error("HTTP error for {url}: {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("external tool '{tool}' not found in PATH")]
    ToolNotFound { tool: String },

    #[error("tool '{tool}' exited with status {status}: {stderr}")]
    ToolFailed { tool: String, status: i32, stderr: String },

    #[error("failed to parse output from '{tool}': {reason}")]
    ToolOutputParse { tool: String, reason: String },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("invalid target '{target}': {reason}")]
    InvalidTarget { target: String, reason: String },

    #[error("AI analysis failed: {0}")]
    AiAnalysis(String),

    #[error("report error: {0}")]
    Report(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("database error: {0}")]
    Database(String),

    #[error("scan cancelled: {reason}")]
    Cancelled { reason: String },
}

pub type Result<T> = std::result::Result<T, ScorchError>;
