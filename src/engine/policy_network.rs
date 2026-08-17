//! Engagement-bound native network resolution and TCP connection.
//!
//! HTTP clients use the same resolver through [`reqwest::dns::Resolve`].
//! Native DNS, TLS, and infrastructure probes call [`PolicyNetwork::resolve`]
//! or [`PolicyNetwork::connect`] so a derived hostname is authorized before
//! DNS and every returned address is authorized before a socket is opened.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::error::{Result, ScorchError};
use super::policy::{Capability, EffectClass, Engagement, PolicyTarget};

#[async_trait]
trait NetworkResolver: fmt::Debug + Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

#[derive(Debug)]
struct SystemNetworkResolver;

#[async_trait]
impl NetworkResolver for SystemNetworkResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        tokio::net::lookup_host((host, port)).await.map(Iterator::collect)
    }
}

/// Policy owner for native hostname resolution and TCP connections.
#[derive(Clone)]
pub struct PolicyNetwork {
    engagement: Arc<Engagement>,
    capability: Capability,
    effect: EffectClass,
    resolver: Arc<dyn NetworkResolver>,
}

impl fmt::Debug for PolicyNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyNetwork")
            .field("engagement_id", &self.engagement.id)
            .field("capability", &self.capability)
            .field("effect", &self.effect)
            .field("resolver", &self.resolver)
            .finish()
    }
}

impl PolicyNetwork {
    /// Bind native network work to one engagement decision class.
    #[must_use]
    pub fn new(engagement: Arc<Engagement>, capability: Capability, effect: EffectClass) -> Self {
        Self { engagement, capability, effect, resolver: Arc::new(SystemNetworkResolver) }
    }

    /// Authorize a hostname or address before using it as a native network target.
    pub fn authorize(&self, target: &str) -> Result<()> {
        let target = normalize_host(target);
        self.engagement
            .authorize(PolicyTarget::network(target), self.capability, self.effect)
            .require()?;
        Ok(())
    }

    /// Resolve a hostname within one wall-clock budget.
    ///
    /// The hostname is authorized before the resolver is called. All returned
    /// addresses are authorized as a set before any caller can connect to one.
    pub async fn resolve(
        &self,
        host: &str,
        port: u16,
        budget: Duration,
    ) -> Result<Vec<SocketAddr>> {
        timeout(budget, self.resolve_unbounded(host, port))
            .await
            .map_err(|_| timed_out("DNS resolution", host, port))?
    }

    /// Resolve and connect to an authorized address within one wall-clock budget.
    ///
    /// Connections use concrete [`SocketAddr`] values, so the operating system
    /// cannot perform a second unchecked hostname lookup between authorization
    /// and `connect`.
    pub async fn connect(&self, host: &str, port: u16, budget: Duration) -> Result<TcpStream> {
        timeout(budget, async {
            let addresses = self.resolve_unbounded(host, port).await?;
            let mut last_error = None;
            for address in addresses {
                match TcpStream::connect(address).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(ScorchError::Io(last_error.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("DNS returned no addresses for {host}:{port}"),
                )
            })))
        })
        .await
        .map_err(|_| timed_out("TCP connection", host, port))?
    }

    async fn resolve_unbounded(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let host = normalize_host(host);
        self.authorize(host)?;
        let mut addresses = self.resolver.resolve(host, port).await?;
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(ScorchError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("DNS returned no addresses for {host}:{port}"),
            )));
        }
        for address in &addresses {
            self.authorize(&address.ip().to_string())?;
        }
        Ok(addresses)
    }

    #[cfg(test)]
    fn with_resolver(mut self, resolver: Arc<dyn NetworkResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    #[cfg(test)]
    pub fn for_test_target(target: &str, capability: Capability, effect: EffectClass) -> Self {
        use super::policy::EngagementPolicy;
        use super::scope::ScopeRule;

        let target_host = normalize_host(target);
        let mut policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse(target_host).expect("test target scope"))
            .allow_scope(ScopeRule::parse("localhost").expect("localhost scope"))
            .allow_scope(ScopeRule::parse("127.0.0.1").expect("IPv4 loopback scope"))
            .allow_scope(ScopeRule::parse("::1/128").expect("IPv6 loopback scope"))
            .allow_scope(ScopeRule::parse("192.0.2.0/24").expect("fixture network scope"))
            .allow_capability(capability)
            .allow_effect(effect);
        if target_host.parse::<std::net::IpAddr>().is_err() && !target_host.contains('/') {
            policy = policy.allow_scope(
                ScopeRule::parse(&format!("*.{target_host}")).expect("derived test hostname scope"),
            );
        }
        Self::new(Arc::new(Engagement::new("native network test", policy)), capability, effect)
    }
}

impl reqwest::dns::Resolve for PolicyNetwork {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let hostname = name.as_str().to_string();
        let policy = self.clone();
        Box::pin(async move {
            let addresses = policy
                .resolve_unbounded(&hostname, 0)
                .await
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })?;
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn normalize_host(host: &str) -> &str {
    host.trim().trim_start_matches('[').trim_end_matches(']').trim_end_matches('.')
}

fn timed_out(operation: &str, host: &str, port: u16) -> ScorchError {
    ScorchError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{operation} for {host}:{port} timed out"),
    ))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::engine::policy::EngagementPolicy;
    use crate::engine::scope::ScopeRule;

    #[derive(Debug)]
    struct FixtureResolver {
        calls: AtomicUsize,
        answers: Vec<SocketAddr>,
    }

    #[async_trait]
    impl NetworkResolver for FixtureResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.answers.clone())
        }
    }

    fn policy(scopes: &[&str]) -> PolicyNetwork {
        let mut engagement_policy = EngagementPolicy::default()
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe);
        for scope in scopes {
            engagement_policy =
                engagement_policy.allow_scope(ScopeRule::parse(scope).expect("fixture scope"));
        }
        PolicyNetwork::new(
            Arc::new(Engagement::new("fixture", engagement_policy)),
            Capability::DastScan,
            EffectClass::ActiveSafe,
        )
    }

    #[test]
    fn debug_output_identifies_policy_without_dumping_the_engagement() {
        let network = policy(&["example.com"]);
        let rendered = format!("{network:?}");

        assert!(rendered.starts_with("PolicyNetwork { engagement_id: "));
        assert!(rendered.contains("capability: DastScan"));
        assert!(rendered.contains("effect: ActiveSafe"));
        assert!(rendered.contains("resolver: SystemNetworkResolver"));
        assert!(!rendered.contains("allowed_scope"));
    }

    #[tokio::test]
    async fn denied_derived_hostname_never_reaches_dns() {
        let resolver = Arc::new(FixtureResolver {
            calls: AtomicUsize::new(0),
            answers: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 80))],
        });
        let network = policy(&["example.com"]).with_resolver(resolver.clone());

        let error = network
            .resolve("admin.example.com", 80, Duration::from_secs(1))
            .await
            .expect_err("derived hostname is outside exact scope");

        assert!(matches!(error, ScorchError::Policy(_)));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn every_dns_answer_is_authorized_before_return() {
        let resolver = Arc::new(FixtureResolver {
            calls: AtomicUsize::new(0),
            answers: vec![
                SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 443),
            ],
        });
        let network = policy(&["*.example.com", "127.0.0.1"]).with_resolver(resolver.clone());

        let error = network
            .resolve("api.example.com", 443, Duration::from_secs(1))
            .await
            .expect_err("one denied address denies the complete answer set");

        assert!(matches!(error, ScorchError::Policy(_)));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn authorized_loopback_resolution_and_connection_remain_available() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let network = policy(&["localhost", "127.0.0.1", "::1/128"]);

        let stream = network
            .connect("localhost", port, Duration::from_secs(1))
            .await
            .expect("authorized loopback connection");

        assert_eq!(stream.peer_addr().unwrap().port(), port);
    }
}
