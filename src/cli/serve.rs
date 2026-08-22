//! CLI handler for the `scorchkit serve` command.
//!
//! Starts local stdio MCP by default or the explicitly selected authenticated
//! remote transport.

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
pub async fn run_serve(config: &Arc<AppConfig>, remote: bool) -> Result<()> {
    if remote {
        crate::mcp::server::serve_remote(Arc::clone(config)).await
    } else {
        crate::mcp::server::serve(Arc::clone(config)).await
    }
}
