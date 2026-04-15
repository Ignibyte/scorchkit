//! `ScorchKit` — Web application security testing toolkit.
//!
//! `ScorchKit` is a modular security scanner with both DAST (Dynamic Application
//! Security Testing) and SAST (Static Application Security Testing) capabilities.
//!
//! # Quick Start
//!
//! Use the [`Engine`] facade for the simplest entry point:
//!
//! ```no_run
//! use std::sync::Arc;
//! use scorchkit::prelude::*;
//!
//! # async fn example() -> Result<()> {
//! let engine = Engine::new(Arc::new(AppConfig::default()));
//!
//! // DAST scan
//! let result = engine.scan("https://example.com").await?;
//!
//! // SAST scan
//! let code_result = engine.code_scan(std::path::Path::new(".")).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Architecture
//!
//! - **[`engine`]** — Core types: [`Finding`], [`Severity`], [`Target`],
//!   [`ScanResult`], [`engine::module_trait::ScanModule`] trait,
//!   [`engine::code_module::CodeModule`] trait
//! - **[`runner`]** — Orchestrators for concurrent module execution
//! - **[`recon`]** / **[`scanner`]** / **[`tools`]** — DAST modules
//!   (reconnaissance, vulnerability scanning, external tool wrappers)
//! - **[`sast`]** / **[`sast_tools`]** — SAST modules (built-in analyzers
//!   and external tool wrappers)
//! - **[`config`]** — TOML configuration (`AppConfig`)
//! - **[`report`]** — Output formats (terminal, JSON, HTML, SARIF)
//! - **[`facade`]** — High-level [`Engine`] for library consumers
//! - **[`prelude`]** — Convenience re-exports

pub mod agent;
pub mod ai;
pub mod cli;
#[cfg(feature = "cloud")]
pub mod cloud;
pub mod config;
pub mod engine;
pub mod facade;
#[cfg(feature = "infra")]
pub mod infra;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod prelude;
pub mod recon;
pub mod report;
pub mod runner;
pub mod sast;
pub mod sast_tools;
pub mod scanner;
#[cfg(feature = "storage")]
pub mod storage;
pub mod tools;

// Crate-root re-exports for the most common types.
// Library consumers can use `scorchkit::Finding` instead of
// `scorchkit::engine::finding::Finding`.
pub use engine::error::{Result, ScorchError};
pub use engine::finding::Finding;
pub use engine::scan_result::ScanResult;
pub use engine::severity::Severity;
pub use engine::target::Target;
pub use facade::Engine;
