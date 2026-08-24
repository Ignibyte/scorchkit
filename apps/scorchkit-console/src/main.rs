//! `ScorchKit` local Rustal console entry point.

use anyhow::Result;
use scorchkit_console::config::ConsoleConfig;
use scorchkit_console::event_mirror::run_event_worker;
use scorchkit_console::{ConsoleState, build_app};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init()
        .map_err(|_| anyhow::anyhow!("console tracing is already initialized"))?;
    let state = ConsoleState::new(ConsoleConfig::from_env()?)?;
    let worker = tokio::spawn(run_event_worker(state.client(), state.mirror()));
    let result = build_app(state)?.serve().await;
    worker.abort();
    result.map_err(Into::into)
}
