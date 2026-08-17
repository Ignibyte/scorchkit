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
//! let code = std::path::Path::new(".").canonicalize()?;
//! let policy = EngagementPolicy::default()
//!     .allow_scope(ScopeRule::parse("example.com").expect("web scope"))
//!     .allow_scope(ScopeRule::path_prefix(&code)?)
//!     .allow_capability(Capability::DastScan)
//!     .allow_capability(Capability::CodeScan)
//!     .allow_capability(Capability::ExternalTool)
//!     .allow_effect(EffectClass::Intrusive)
//!     .allow_effect(EffectClass::Passive);
//! let engine = Engine::for_engagement(
//!     Arc::new(AppConfig::default()),
//!     Arc::new(Engagement::new("authorized assessment", policy)),
//! );
//!
//! // DAST scan
//! let result = engine.scan("https://example.com").await?;
//!
//! // SAST scan
//! let code_result = engine.code_scan(&code).await?;
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

#[cfg(not(unix))]
compile_error!(
    "ScorchKit currently supports Unix hosts only because external-tool process-tree isolation \
     requires Unix process groups; add a kill-on-close job-object backend before enabling Windows"
);

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

#[cfg(all(test, feature = "infra"))]
pub(crate) static TEST_ENVIRONMENT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Crate-root re-exports for the most common types.
// Library consumers can use `scorchkit::Finding` instead of
// `scorchkit::engine::finding::Finding`.
pub use engine::error::{Result, ScorchError};
pub use engine::finding::Finding;
pub use engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy, PolicyTarget};
pub use engine::scan_result::ScanResult;
pub use engine::scope::ScopeRule;
pub use engine::severity::Severity;
pub use engine::target::Target;
pub use facade::Engine;
