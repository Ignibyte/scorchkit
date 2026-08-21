use std::path::PathBuf;

use scorchkit_core::{ApplicationDastProfile, ApplicationDastSchemaKind};
use serde::{Deserialize, Serialize};

/// One digest-pinned local schema selected for application DAST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationDastSchemaRequest {
    pub kind: ApplicationDastSchemaKind,
    pub path: PathBuf,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Provider-neutral request for one isolated multi-persona application DAST assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationDastRequest {
    pub target: String,
    pub profile: ApplicationDastProfile,
    #[serde(default)]
    pub include_anonymous: bool,
    #[serde(default)]
    pub personas: Vec<String>,
    #[serde(default)]
    pub schemas: Vec<ApplicationDastSchemaRequest>,
}

impl ApplicationDastRequest {
    #[must_use]
    pub fn new(target: impl Into<String>, profile: ApplicationDastProfile) -> Self {
        Self {
            target: target.into(),
            profile,
            include_anonymous: true,
            personas: Vec::new(),
            schemas: Vec::new(),
        }
    }
}
