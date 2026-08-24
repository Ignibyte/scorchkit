//! Versioned ordered event projections.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable event schema identity.
pub const CONTROL_EVENT_SCHEMA_V1: &str = "scorchkit.control.event/v1";

/// Event kinds emitted by the v1 application service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlEventKindV1 {
    /// A job attempt was durably created.
    JobCreated,
    /// A job revision was durably committed.
    JobChanged,
}

/// One bounded monotonically sequenced control event.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlEventV1 {
    /// Event schema identity.
    pub schema_version: String,
    /// Process-monotonic sequence.
    pub sequence: u64,
    /// Event classification.
    pub kind: ControlEventKindV1,
    /// Resource type, such as `job`.
    pub resource_type: String,
    /// Stable resource identifier.
    pub resource_id: Uuid,
    /// Resource revision represented by this event.
    pub resource_revision: u64,
    /// Commit or journal timestamp.
    pub occurred_at: DateTime<Utc>,
    /// Redacted typed payload.
    pub payload: serde_json::Value,
}

/// One finite replay page.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlEventBatchV1 {
    /// Events strictly after the requested sequence.
    pub events: Vec<ControlEventV1>,
    /// New cursor, even when the page is empty.
    pub next_sequence: u64,
    /// Whether more retained events are immediately available.
    pub has_more: bool,
}
