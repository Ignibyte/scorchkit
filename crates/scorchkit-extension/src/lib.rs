//! Provider-neutral contracts and safe guest SDK for isolated `ScorchKit` extensions.
//!
//! This package owns no policy engine, process launcher, storage handle, transport, or provider
//! adapter. Root composition validates registrations, owns the worker, brokers effects, and
//! persists normalized output.

pub mod constants;
#[cfg(feature = "host-contract")]
pub mod manifest;
pub mod protocol;
pub mod sdk;

pub use constants::*;
#[cfg(feature = "host-contract")]
pub use manifest::{
    extension_manifest_schema_v1, ExtensionAdapterV1, ExtensionBudgetsV1, ExtensionCapabilityV1,
    ExtensionCompatibilityV1, ExtensionManifestError, ExtensionManifestV1, ExtensionModuleV1,
    ExtensionRuntimeV1,
};
pub use protocol::{
    ExtensionArtifactV1, ExtensionEffectDecisionV1, ExtensionEffectRequestV1,
    ExtensionEffectResultV1, ExtensionEffectV1, ExtensionEvidenceV1, ExtensionFailureV1,
    ExtensionFindingV1, ExtensionHttpMethodV1, ExtensionInvocationInputV1, ExtensionInvocationV1,
    ExtensionObservationV1, ExtensionOutputV1, ExtensionTurnInputV1, ExtensionTurnOutputV1,
};
pub use sdk::GuestExtension;

/// Macro implementation dependencies that remain versioned with the SDK.
#[doc(hidden)]
pub mod __private {
    pub use serde_json;
}
