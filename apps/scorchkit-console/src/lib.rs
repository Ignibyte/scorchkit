//! Optional local Rustal operator console for `ScorchKit`.

pub mod client;
pub mod config;
pub mod event_mirror;
pub mod http;
pub mod render;

pub use http::{ConsoleState, build_app};
