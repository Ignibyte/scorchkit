//! Credential-safe console startup configuration.

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::header::HeaderValue;
use url::{Host, Url};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Default console listener. It is deliberately separate from the control API.
pub const DEFAULT_CONSOLE_BIND: &str = "127.0.0.1:7445";
/// Maximum accepted browser form body.
pub const MAX_FORM_BYTES: usize = 16 * 1024;
/// Maximum serialized control response retained by the client.
pub const MAX_CONTROL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum one upstream SSE frame.
pub const MAX_EVENT_FRAME_BYTES: usize = 128 * 1024;
/// Maximum mirrored event count.
pub const MAX_MIRRORED_EVENTS: usize = 256;
/// Maximum events returned to one browser replay request.
pub const MAX_BROWSER_EVENTS: usize = 64;
/// Maximum escaped HTML emitted for one console page.
pub const MAX_RENDERED_PAGE_BYTES: usize = 4 * 1024 * 1024;

/// Validated startup configuration. Secret values are never exposed by `Debug`.
#[derive(Clone)]
pub struct ConsoleConfig {
    /// Exact loopback console listener.
    pub(crate) bind: SocketAddr,
    /// Exact loopback control API base URL.
    pub(crate) control_url: Url,
    /// Exact immutable engagement binding.
    pub(crate) engagement_id: Uuid,
    /// Sensitive `Authorization` value used only by the server process.
    authorization: HeaderValue,
    /// Exact browser Host value accepted by the console.
    pub(crate) browser_host: String,
    /// Exact browser Origin accepted on mutations.
    pub(crate) browser_origin: String,
    /// Per-request upstream deadline.
    pub(crate) request_timeout: Duration,
}

impl std::fmt::Debug for ConsoleConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsoleConfig")
            .field("bind", &self.bind)
            .field("control_url", &self.control_url)
            .field("engagement_id", &self.engagement_id)
            .field("authorization", &"<redacted>")
            .field("browser_host", &self.browser_host)
            .field("browser_origin", &self.browser_origin)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl ConsoleConfig {
    /// Load the explicit control endpoint, engagement, and token from the environment.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe error before listener construction when any input is absent,
    /// malformed, exposed, or outside its fixed bound.
    pub fn from_env() -> Result<Self> {
        let bind =
            env::var("SCORCHKIT_CONSOLE_BIND").unwrap_or_else(|_| DEFAULT_CONSOLE_BIND.to_owned());
        let control_url = env::var("SCORCHKIT_CONSOLE_CONTROL_URL")
            .context("SCORCHKIT_CONSOLE_CONTROL_URL is required")?;
        let engagement = env::var("SCORCHKIT_CONSOLE_ENGAGEMENT_ID")
            .context("SCORCHKIT_CONSOLE_ENGAGEMENT_ID is required")?;
        let token_env = env::var("SCORCHKIT_CONSOLE_TOKEN_ENV")
            .context("SCORCHKIT_CONSOLE_TOKEN_ENV is required")?;
        validate_env_name(&token_env)?;
        let token = Zeroizing::new(
            env::var(&token_env)
                .map_err(|_| anyhow::anyhow!("configured console token is absent"))?,
        );
        Self::new(&bind, &control_url, &engagement, token.as_str())
    }

    /// Validate explicit values. Kept separate from environment access for complete table tests.
    ///
    /// # Errors
    ///
    /// Returns a safe error for invalid bind, URL, engagement, or bearer values.
    pub fn new(bind: &str, control_url: &str, engagement: &str, token: &str) -> Result<Self> {
        let bind: SocketAddr = bind.parse().context("console bind must be a socket address")?;
        if !bind.ip().is_loopback() || bind.port() == 0 {
            bail!("console bind must be an exact loopback address with a nonzero port");
        }
        let control_url = validate_control_url(control_url)?;
        let engagement_id =
            engagement.parse::<Uuid>().context("console engagement must be a UUID")?;
        if token.len() < 32
            || token.len() > 4_096
            || token.trim() != token
            || token.chars().any(char::is_control)
        {
            bail!("configured console token is invalid");
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| anyhow::anyhow!("configured console token is invalid"))?;
        authorization.set_sensitive(true);
        let browser_host = socket_host(bind);
        let browser_origin = format!("http://{browser_host}");
        Ok(Self {
            bind,
            control_url,
            engagement_id,
            authorization,
            browser_host,
            browser_origin,
            request_timeout: Duration::from_secs(10),
        })
    }

    /// Clone the sensitive authorization value for one server-side upstream request.
    #[must_use]
    pub fn authorization(&self) -> HeaderValue {
        self.authorization.clone()
    }
}

fn validate_env_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_uppercase() || (index > 0 && byte.is_ascii_digit())
        })
    {
        bail!("SCORCHKIT_CONSOLE_TOKEN_ENV is invalid");
    }
    Ok(())
}

fn validate_control_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("console control URL is invalid")?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("console control URL must be a credential-free loopback HTTP origin");
    }
    let address: IpAddr = match url.host().context("console control URL requires a host")? {
        Host::Ipv4(address) => address.into(),
        Host::Ipv6(address) => address.into(),
        Host::Domain(_) => bail!("console control URL host must be a literal loopback address"),
    };
    if !address.is_loopback() || url.port().is_none() {
        bail!("console control URL must be a literal loopback origin with an explicit port");
    }
    url.set_path("/");
    Ok(url)
}

fn socket_host(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(value) => value.to_string(),
        SocketAddr::V6(value) => format!("[{}]:{}", value.ip(), value.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGAGEMENT: &str = "b1382ed4-0ad0-45a2-afd6-550c0d947566";

    fn test_bearer() -> String {
        ["console", "test", "bearer", "value", "not", "secret"].join("-")
    }

    #[test]
    fn accepts_exact_ipv4_and_ipv6_loopback_origins() -> Result<()> {
        let bearer = test_bearer();
        let ipv4 =
            ConsoleConfig::new("127.0.0.1:7445", "http://127.0.0.1:7444", ENGAGEMENT, &bearer)?;
        assert_eq!(ipv4.browser_host, "127.0.0.1:7445");
        let ipv6 = ConsoleConfig::new("[::1]:7445", "http://[::1]:7444", ENGAGEMENT, &bearer)?;
        assert_eq!(ipv6.browser_origin, "http://[::1]:7445");
        Ok(())
    }

    #[test]
    fn rejects_every_exposed_or_ambiguous_endpoint_shape() {
        let bearer = test_bearer();
        for bind in ["0.0.0.0:7445", "10.0.0.1:7445", "127.0.0.1:0"] {
            assert!(
                ConsoleConfig::new(bind, "http://127.0.0.1:7444", ENGAGEMENT, &bearer).is_err()
            );
        }
        for url in [
            "https://127.0.0.1:7444",
            "http://localhost:7444",
            "http://10.0.0.1:7444",
            "http://user@127.0.0.1:7444",
            "http://127.0.0.1:7444/v1",
            "http://127.0.0.1:7444/?query=1",
            "http://127.0.0.1:7444/#fragment",
            "http://127.0.0.1",
        ] {
            assert!(
                ConsoleConfig::new("127.0.0.1:7445", url, ENGAGEMENT, &bearer).is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn bearer_boundaries_and_debug_redaction_are_exact() -> Result<()> {
        let bearer = test_bearer();
        for candidate in ["short".to_owned(), "x".repeat(31), "x".repeat(4_097)] {
            assert!(
                ConsoleConfig::new(
                    "127.0.0.1:7445",
                    "http://127.0.0.1:7444",
                    ENGAGEMENT,
                    &candidate,
                )
                .is_err()
            );
        }
        for candidate in [bearer.clone(), "x".repeat(4_096)] {
            assert!(
                ConsoleConfig::new(
                    "127.0.0.1:7445",
                    "http://127.0.0.1:7444",
                    ENGAGEMENT,
                    &candidate,
                )
                .is_ok()
            );
        }
        for candidate in [format!(" {bearer} "), format!("bad\n{bearer}")] {
            assert!(
                ConsoleConfig::new(
                    "127.0.0.1:7445",
                    "http://127.0.0.1:7444",
                    ENGAGEMENT,
                    &candidate,
                )
                .is_err()
            );
        }
        let config =
            ConsoleConfig::new("127.0.0.1:7445", "http://127.0.0.1:7444", ENGAGEMENT, &bearer)?;
        let rendered = format!("{config:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&bearer));
        Ok(())
    }
}
