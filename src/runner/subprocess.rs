//! Compatibility re-exports for the extracted process boundary.

pub(crate) use scorchkit_tools::{
    is_tool_available, missing_required_tool, resolve_tool_path, spawn_owned_process,
    stop_owned_process, OwnedProcess, SystemToolExecutor,
};
pub use scorchkit_tools::{
    ArtifactBudget, EnvironmentPolicy, ExitPolicy, ToolExecutor, ToolInvocation, ToolOutput,
    DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
};
