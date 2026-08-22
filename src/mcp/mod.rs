//! MCP server for `ScorchKit`.
//!
//! Exposes the scan engine, project management, and finding lifecycle
//! as MCP tools over stdio transport. Built on the `rmcp` crate.
//!
//! Start the server with `scorchkit serve` (requires the `mcp` feature).

pub mod contract;
pub mod instructions;
pub mod prompts;
pub mod remote;
pub mod resources;
pub mod server;
pub mod tools;
pub mod types;
