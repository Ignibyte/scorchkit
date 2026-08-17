//! Engagement-bound HTTP client construction.
//!
//! This is the single network-policy seam for native HTTP clients. Direct
//! destinations are authorized before client construction; redirects and every
//! DNS answer are reauthorized before a connection is followed or opened.

use std::sync::Arc;
#[cfg(feature = "infra")]
use std::time::Duration;

#[cfg(feature = "infra")]
use url::Url;

#[cfg(feature = "infra")]
use super::error::{Result, ScorchError};
use super::policy::{Capability, EffectClass, Engagement, PolicyTarget};
use super::policy_network::PolicyNetwork;

/// Redirect behavior for an engagement-bound HTTP client.
#[derive(Debug, Clone, Copy)]
pub enum RedirectMode {
    /// Do not follow redirects.
    None,
    /// Follow at most the given number of authorized redirects.
    Follow { max_redirects: usize },
}

/// Attach DNS and redirect authorization to an existing client builder.
pub fn bind_builder(
    builder: reqwest::ClientBuilder,
    engagement: Arc<Engagement>,
    capability: Capability,
    effect: EffectClass,
    redirects: RedirectMode,
) -> reqwest::ClientBuilder {
    let resolver = Arc::new(PolicyNetwork::new(Arc::clone(&engagement), capability, effect));
    let builder = builder.dns_resolver(resolver);

    match redirects {
        RedirectMode::None => builder.redirect(reqwest::redirect::Policy::none()),
        RedirectMode::Follow { max_redirects } => {
            builder.redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if redirect_limit_reached(attempt.previous().len(), max_redirects) {
                    return attempt.error("too many redirects");
                }
                let decision = engagement.authorize(
                    PolicyTarget::Web(attempt.url().clone()),
                    capability,
                    effect,
                );
                if decision.allowed {
                    attempt.follow()
                } else {
                    attempt.error(format!("redirect denied by engagement policy: {decision:?}"))
                }
            }))
        }
    }
}

const fn redirect_limit_reached(previous_redirects: usize, max_redirects: usize) -> bool {
    previous_redirects >= max_redirects
}

/// Build a credential-free client for a policy-authorized service endpoint.
///
/// # Errors
///
/// Returns a target, policy, or client-construction error before the client is
/// returned.
#[cfg(feature = "infra")]
pub fn build_service_client(
    engagement: Arc<Engagement>,
    endpoint: &Url,
    capability: Capability,
    effect: EffectClass,
    user_agent: &str,
    timeout: Duration,
    redirects: RedirectMode,
) -> Result<reqwest::Client> {
    engagement.authorize(PolicyTarget::Web(endpoint.clone()), capability, effect).require()?;
    let builder = reqwest::Client::builder().user_agent(user_agent).timeout(timeout);
    bind_builder(builder, engagement, capability, effect, redirects)
        .build()
        .map_err(|error| ScorchError::Config(format!("failed to build HTTP client: {error}")))
}

#[cfg(test)]
pub fn require_resolved_target(
    engagement: &Engagement,
    target: &str,
    capability: Capability,
    effect: EffectClass,
) -> std::result::Result<(), crate::engine::policy::PolicyViolation> {
    engagement.authorize(PolicyTarget::network(target), capability, effect).require()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "infra")]
    use crate::engine::policy::EngagementPolicy;

    #[test]
    fn redirect_limit_is_inclusive_and_rejects_every_later_redirect() {
        assert!(!redirect_limit_reached(0, 1));
        assert!(redirect_limit_reached(1, 1));
        assert!(redirect_limit_reached(2, 1));
        assert!(redirect_limit_reached(0, 0));
    }

    #[cfg(feature = "infra")]
    #[test]
    fn service_client_requires_endpoint_authorization() {
        let endpoint = Url::parse("https://outside.test/api").expect("fixture endpoint");
        let engagement = Arc::new(Engagement::new("empty", EngagementPolicy::default()));

        let result = build_service_client(
            engagement,
            &endpoint,
            Capability::InfraScan,
            EffectClass::Passive,
            "scorchkit-test",
            Duration::from_secs(1),
            RedirectMode::None,
        );

        assert!(result.is_err());
    }
}
