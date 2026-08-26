//! Optional authenticated multi-user deployment profile.

mod auth;
mod object_store;
mod recovery;
mod service;
pub mod transport;

pub use object_store::TeamObjectStore;
pub use recovery::{create_recovery_manifest, verify_recovery_manifest, RecoveryInput};
pub use service::{TeamService, TeamSession};
