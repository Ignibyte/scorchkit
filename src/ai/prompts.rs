//! Host-facing analysis focus selection.
//!
//! Provider prompt rendering lives in `crate::ai::contracts`. This module
//! retains only the stable user-facing focus vocabulary used by CLI and MCP.

use serde::{Deserialize, Serialize};

/// Analysis focus modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisFocus {
    /// Executive summary with business impact.
    Summary,
    /// Rank findings by exploitability and attack chain potential.
    Prioritize,
    /// Detailed remediation recommendations per finding.
    Remediate,
    /// Identify likely false positives with reasoning.
    Filter,
}

impl AnalysisFocus {
    /// Parse a focus mode from a user-supplied string.
    ///
    /// Accepts common aliases and defaults to [`AnalysisFocus::Summary`] for
    /// unrecognized input.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "prioritize" | "priority" | "prio" => Self::Prioritize,
            "remediate" | "remediation" | "fix" => Self::Remediate,
            "filter" | "false-positives" | "fp" => Self::Filter,
            _ => Self::Summary,
        }
    }

    /// Human-readable label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Summary => "Executive Summary",
            Self::Prioritize => "Prioritized Risk Assessment",
            Self::Remediate => "Remediation Guide",
            Self::Filter => "False Positive Analysis",
        }
    }
}
