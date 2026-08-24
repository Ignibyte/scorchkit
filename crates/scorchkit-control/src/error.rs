//! Versioned safe error contract.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Stable v1 error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCodeV1 {
    /// The request uses an unsupported schema.
    UnsupportedSchema,
    /// The request or one field is malformed.
    InvalidRequest,
    /// A configured or requested bound is invalid or exceeded.
    LimitExceeded,
    /// A configuration layer attempted to widen an earlier ceiling.
    ConfigurationWidening,
    /// No transport-established caller is available.
    Unauthenticated,
    /// The caller is not bound to the requested engagement.
    PrincipalBindingMismatch,
    /// The active engagement is absent, disabled, expired, or mismatched.
    EngagementUnavailable,
    /// Engagement policy denied the requested operation.
    PolicyDenied,
    /// A requested resource does not exist.
    NotFound,
    /// Durable storage is not configured for this operation.
    StorageUnavailable,
    /// A canonical raw record and duplicated durable projection disagree.
    CanonicalProjectionMismatch,
    /// An event cursor predates retained replay history.
    EventCursorExpired,
    /// An event cursor is ahead of the journal.
    EventCursorFuture,
    /// A lifecycle operation conflicts with current state or revision.
    Conflict,
    /// A bounded resource is temporarily unavailable.
    Busy,
    /// An internal operation failed without exposing sensitive detail.
    Internal,
}

/// One safe, serializable control error.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlErrorV1 {
    /// Stable machine-readable code.
    pub code: ControlErrorCodeV1,
    /// Redacted operator-facing message.
    pub message: String,
    /// Whether a caller may retry without changing the request.
    pub retryable: bool,
    /// Bounded non-secret structured context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ControlErrorV1 {
    /// Create an error without structured details.
    #[must_use]
    pub fn new(code: ControlErrorCodeV1, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), retryable: false, details: None }
    }

    /// Mark the error as retryable.
    #[must_use]
    pub const fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    /// Attach bounded structured details.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl std::fmt::Display for ControlErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ControlErrorV1 {}
