//! Typed authenticated client for the versioned `ScorchKit` control API.

use std::fmt;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use scorchkit_control::{
    CONTROL_API_SCHEMA_V1, ControlCommandV1, ControlErrorV1, ControlPrincipalKindV1,
    ControlQueryV1, ControlRequestV1, ControlResponseOutcomeV1, ControlResponseV1, ControlResultV1,
};

use crate::config::{ConsoleConfig, MAX_CONTROL_RESPONSE_BYTES};

/// One validated server-side control API client.
#[derive(Clone)]
pub struct ControlClient {
    http: reqwest::Client,
    config: ConsoleConfig,
}

impl fmt::Debug for ControlClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlClient")
            .field("control_url", &self.config.control_url)
            .field("engagement_id", &self.config.engagement_id)
            .field("authorization", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ControlClient {
    /// Build a client with redirect denial and a fixed request deadline.
    ///
    /// # Errors
    ///
    /// Returns a safe error when the HTTP client cannot be constructed.
    pub fn new(config: ConsoleConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.request_timeout)
            .timeout(config.request_timeout)
            .build()
            .context("failed to construct console control client")?;
        Ok(Self { http, config })
    }

    /// Execute one read-only v1 query.
    ///
    /// # Errors
    ///
    /// Returns a validated control error or a safe transport/integrity error.
    pub async fn query(&self, query: ControlQueryV1) -> Result<ControlResultV1> {
        self.execute(ControlRequestV1::query(query, Some(self.config.engagement_id))).await
    }

    /// Execute one state-changing v1 command.
    ///
    /// # Errors
    ///
    /// Returns a validated control error or a safe transport/integrity error.
    pub async fn command(&self, command: ControlCommandV1) -> Result<ControlResultV1> {
        self.execute(ControlRequestV1::command(command, self.config.engagement_id)).await
    }

    async fn execute(&self, request: ControlRequestV1) -> Result<ControlResultV1> {
        request.validate().map_err(|_| anyhow::Error::new(LocalRequestError))?;
        let request_id = request.request_id;
        let endpoint = self.config.control_url.join("v1/control")?;
        let response = self
            .http
            .post(endpoint)
            .header(AUTHORIZATION, self.config.authorization())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|_| anyhow!("control API request failed"))?;
        if response.status().is_redirection() {
            bail!("control API redirects are not allowed");
        }
        if response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_none_or(|value| !value.trim().eq_ignore_ascii_case("application/json"))
        {
            bail!("control API response did not use JSON");
        }
        let status = response.status();
        let bytes = bounded_body(response, MAX_CONTROL_RESPONSE_BYTES).await?;
        let envelope: ControlResponseV1 = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("control API returned an invalid response envelope"))?;
        self.validate_envelope(&envelope, request_id)?;
        match envelope.result {
            ControlResponseOutcomeV1::Success(result) if status.is_success() => Ok(*result),
            ControlResponseOutcomeV1::Error(error) => Err(anyhow::Error::new(error)),
            ControlResponseOutcomeV1::Success(_) => {
                bail!("control API returned success with a non-success status")
            }
        }
    }

    fn validate_envelope(
        &self,
        response: &ControlResponseV1,
        request_id: uuid::Uuid,
    ) -> Result<()> {
        if response.schema_version != CONTROL_API_SCHEMA_V1
            || response.request_id != request_id
            || response.principal.kind != ControlPrincipalKindV1::AuthenticatedBearer
            || response.principal.engagement_id != Some(self.config.engagement_id)
        {
            bail!("control API response identity did not match the request");
        }
        Ok(())
    }

    /// Construct one authenticated upstream event-stream request after an exact cursor.
    pub fn event_request(&self, after: u64) -> reqwest::RequestBuilder {
        let mut endpoint = self.config.control_url.join("v1/events").unwrap_or_else(|_| {
            // Construction was already validated and joining this fixed relative path cannot fail.
            self.config.control_url.clone()
        });
        endpoint.query_pairs_mut().append_pair("after", &after.to_string());
        self.http
            .get(endpoint)
            .header(AUTHORIZATION, self.config.authorization())
            .header(ACCEPT, "text/event-stream")
            .timeout(self.config.request_timeout.saturating_mul(3))
    }

    /// Exact engagement expected on every response and event.
    #[must_use]
    pub const fn engagement_id(&self) -> uuid::Uuid {
        self.config.engagement_id
    }
}

pub(crate) async fn bounded_body(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|length| length > limit as u64) {
        bail!("control API response exceeded the console limit");
    }
    let mut output = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| anyhow!("control API response body failed"))?;
        let new_len = output
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("control API response exceeded the console limit"))?;
        if new_len > limit {
            bail!("control API response exceeded the console limit");
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

/// Return a typed control error when the failure came from the API.
#[must_use]
pub fn control_error(error: &anyhow::Error) -> Option<&ControlErrorV1> {
    error.downcast_ref::<ControlErrorV1>()
}

/// Report whether a request failed local contract validation before any upstream effect.
#[must_use]
pub fn local_request_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<LocalRequestError>().is_some()
}

#[derive(Debug)]
struct LocalRequestError;

impl fmt::Display for LocalRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("control request failed local validation")
    }
}

impl std::error::Error for LocalRequestError {}
