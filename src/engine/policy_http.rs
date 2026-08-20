//! Engagement-bound HTTP client construction.
//!
//! This is the single network-policy seam for native HTTP clients. Direct
//! destinations are authorized before client construction; redirects and every
//! DNS answer are reauthorized before a connection is followed or opened.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use url::Url;

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

/// Digest and size of one provider artifact written to owned staging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedProviderArtifact {
    pub bytes_written: usize,
    pub sha256: String,
}

/// Stream one response into a new staging file while enforcing the hard byte limit.
///
/// The client must come from [`build_service_client`], which binds endpoint, DNS-answer, and
/// redirect authorization to the engagement. The destination must be a separately authorized
/// same-filesystem staging path. Partial files are removed on every response or write failure.
pub async fn download_to_staging(
    client: &reqwest::Client,
    url: &Url,
    destination: &std::path::Path,
    maximum_bytes: usize,
) -> Result<DownloadedProviderArtifact> {
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|source| ScorchError::Http { url: url.to_string(), source })?
        .error_for_status()
        .map_err(|source| ScorchError::Http { url: url.to_string(), source })?;
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(maximum_bytes).unwrap_or(u64::MAX))
    {
        return Err(ScorchError::ProviderDownloadLimit {
            url: url.to_string(),
            limit_bytes: maximum_bytes,
        });
    }

    let mut file =
        tokio::fs::OpenOptions::new().write(true).create_new(true).open(destination).await?;
    let mut stream = response.bytes_stream();
    let mut hasher = Sha256::new();
    let mut bytes_written = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(source) => {
                drop(file);
                let _ = tokio::fs::remove_file(destination).await;
                return Err(ScorchError::Http { url: url.to_string(), source });
            }
        };
        bytes_written = bytes_written.saturating_add(chunk.len());
        if bytes_written > maximum_bytes {
            drop(file);
            let _ = tokio::fs::remove_file(destination).await;
            return Err(ScorchError::ProviderDownloadLimit {
                url: url.to_string(),
                limit_bytes: maximum_bytes,
            });
        }
        if let Err(error) = file.write_all(&chunk).await {
            drop(file);
            let _ = tokio::fs::remove_file(destination).await;
            return Err(ScorchError::Io(error));
        }
        hasher.update(&chunk);
    }
    if let Err(error) = file.sync_all().await {
        drop(file);
        let _ = tokio::fs::remove_file(destination).await;
        return Err(ScorchError::Io(error));
    }
    Ok(DownloadedProviderArtifact { bytes_written, sha256: format!("{:x}", hasher.finalize()) })
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
    use crate::engine::policy::EngagementPolicy;
    use crate::engine::scope::ScopeRule;

    #[test]
    fn redirect_limit_is_inclusive_and_rejects_every_later_redirect() {
        assert!(!redirect_limit_reached(0, 1));
        assert!(redirect_limit_reached(1, 1));
        assert!(redirect_limit_reached(2, 1));
        assert!(redirect_limit_reached(0, 0));
    }

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

    #[tokio::test]
    async fn bounded_provider_download_streams_and_removes_oversize_partial_files() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let body = b"bounded provider fixture".to_vec();
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).await.expect("read request");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    server_body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&server_body).await;
            }
        });

        let endpoint =
            Url::parse(&format!("http://{address}/provider.bin")).expect("provider endpoint");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("127.0.0.1").expect("loopback scope"))
            .allow_capability(Capability::ProviderRefresh)
            .allow_effect(EffectClass::Passive);
        let client = build_service_client(
            Arc::new(Engagement::new("provider fixture", policy)),
            &endpoint,
            Capability::ProviderRefresh,
            EffectClass::Passive,
            "scorchkit-test",
            Duration::from_secs(2),
            RedirectMode::None,
        )
        .expect("authorized client");
        let directory = tempfile::tempdir().expect("staging directory");
        let accepted_path = directory.path().join("accepted.bin");
        let accepted = download_to_staging(&client, &endpoint, &accepted_path, body.len())
            .await
            .expect("bounded download");
        assert_eq!(accepted.bytes_written, body.len());
        assert_eq!(accepted.sha256, scorchkit_core::sha256_hex(&body));

        let rejected_path = directory.path().join("rejected.bin");
        let rejected =
            download_to_staging(&client, &endpoint, &rejected_path, body.len() - 1).await;
        assert!(matches!(rejected, Err(ScorchError::ProviderDownloadLimit { .. })));
        assert!(!rejected_path.exists());
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn content_length_rejection_happens_before_opening_the_destination() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.expect("read request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
                )
                .await
                .expect("write response");
        });
        let endpoint = Url::parse(&format!("http://{address}/provider.bin")).unwrap();
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("127.0.0.1").unwrap())
            .allow_capability(Capability::ProviderRefresh)
            .allow_effect(EffectClass::Passive);
        let client = build_service_client(
            Arc::new(Engagement::new("provider fixture", policy)),
            &endpoint,
            Capability::ProviderRefresh,
            EffectClass::Passive,
            "scorchkit-test",
            Duration::from_secs(2),
            RedirectMode::None,
        )
        .unwrap();
        let directory = tempfile::tempdir().expect("staging directory");
        let destination = directory.path().join("already-present.bin");
        std::fs::write(&destination, b"preserve").expect("existing destination");
        let error = download_to_staging(&client, &endpoint, &destination, 4)
            .await
            .expect_err("oversized content length");
        assert!(matches!(error, ScorchError::ProviderDownloadLimit { .. }));
        assert_eq!(std::fs::read(&destination).unwrap(), b"preserve");
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn chunked_download_enforces_the_cumulative_stream_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.expect("read request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n12345\r\n0\r\n\r\n",
                )
                .await
                .expect("write response");
        });
        let endpoint = Url::parse(&format!("http://{address}/provider.bin")).unwrap();
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("127.0.0.1").unwrap())
            .allow_capability(Capability::ProviderRefresh)
            .allow_effect(EffectClass::Passive);
        let client = build_service_client(
            Arc::new(Engagement::new("provider fixture", policy)),
            &endpoint,
            Capability::ProviderRefresh,
            EffectClass::Passive,
            "scorchkit-test",
            Duration::from_secs(2),
            RedirectMode::None,
        )
        .unwrap();
        let directory = tempfile::tempdir().expect("staging directory");
        let destination = directory.path().join("chunked.bin");
        assert!(matches!(
            download_to_staging(&client, &endpoint, &destination, 4).await,
            Err(ScorchError::ProviderDownloadLimit { .. })
        ));
        assert!(!destination.exists());
        server.await.expect("server task");
    }
}
