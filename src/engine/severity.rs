use std::fmt;

use colored::Colorize;
use serde::{Deserialize, Serialize};

/// Severity levels following CVSS-style classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Return a colored string representation for terminal output.
    #[must_use]
    pub fn colored_str(self) -> String {
        match self {
            Self::Info => "INFO".blue().bold().to_string(),
            Self::Low => "LOW".green().bold().to_string(),
            Self::Medium => "MEDIUM".yellow().bold().to_string(),
            Self::High => "HIGH".red().bold().to_string(),
            Self::Critical => "CRITICAL".red().bold().on_white().to_string(),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}
