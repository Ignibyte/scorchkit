//! Stable domain contracts shared by every `ScorchKit` host and scanner family.

pub mod adapter;
pub mod compliance;
pub mod compliance_framework;
pub mod correlation;
pub mod cve;
pub mod error;
pub mod events;
pub mod evidence;
pub mod finding;
pub mod risk_score;
pub mod scan_result;
pub mod service_fingerprint;
pub mod severity;
pub mod shared_data;
pub mod target;

/// Compatibility namespace used by extracted source modules and doctests.
pub mod engine {
    pub use crate::{
        adapter, compliance, compliance_framework, correlation, cve, error, events, evidence,
        finding, risk_score, scan_result, service_fingerprint, severity, shared_data, target,
    };
    pub use scorchkit_policy::{policy, scope};
}

/// Compatibility module for the unified error's policy variant.
pub mod policy {
    pub use scorchkit_policy::policy::*;
}

pub use adapter::{
    AdapterContractV1, AdapterOutputContract, AdapterParseOutcome, AdapterTargetKind,
    LifecycleStage, ProvenanceStrategy, SecurityDomain, TemporaryArtifactPolicy,
    ADAPTER_CONTRACT_V1,
};
pub use error::{Result, ScorchError};
pub use evidence::HttpEvidence;
pub use finding::Finding;
pub use scan_result::{ScanResult, ScanSummary};
pub use severity::Severity;
pub use target::Target;
