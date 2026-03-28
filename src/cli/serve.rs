//! CLI handler for the `scorchkit serve` command.
//!
//! Starts the MCP server on stdio transport. Redirects tracing to stderr
//! since stdout is reserved for the MCP JSON-RPC channel.

use std::sync::Arc;

use crate::config::AppConfig;
use crate::engine::error::Result;

/// Start the MCP server.
///
/// Initializes tracing to stderr (stdout is the MCP channel),
/// then delegates to `mcp::server::serve()`.
///
/// # Errors
///
/// Returns an error if the database connection fails or the
/// MCP transport encounters an I/O error.
pub async fn run_serve(config: &Arc<AppConfig>) -> Result<()> {
    crate::mcp::server::serve(Arc::clone(config)).await
}
