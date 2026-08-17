//! Agent-neutral engagement authorization for `ScorchKit`.
//!
//! This crate deliberately has no dependency on scanner families, storage,
//! terminal interfaces, MCP, or an agent provider.

pub mod policy;
pub mod scope;

pub use policy::{
    AuthorizationDecision, Capability, DenialReason, EffectClass, Engagement, EngagementPolicy,
    PolicyTarget, PolicyTargetError, PolicyViolation,
};
pub use scope::ScopeRule;

/// Narrow cross-package helpers used by the root composition layer.
#[doc(hidden)]
pub mod integration {
    use super::{AuthorizationDecision, Capability, EffectClass, PolicyTarget};

    /// Check that an authorization decision is the exact grant required by a sealed context.
    #[must_use]
    pub fn decision_grants_exactly(
        decision: &AuthorizationDecision,
        target: &PolicyTarget,
        capability: Capability,
        effect: EffectClass,
    ) -> bool {
        decision.grants_exactly(target, capability, effect)
    }
}
