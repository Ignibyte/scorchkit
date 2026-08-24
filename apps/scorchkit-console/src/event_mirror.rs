//! Bounded mirror of the canonical authenticated control event stream.

use std::collections::VecDeque;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use futures_util::StreamExt;
use scorchkit_control::{ControlErrorCodeV1, ControlErrorV1, ControlEventV1};
use tokio::sync::RwLock;

use crate::client::{ControlClient, bounded_body};
use crate::config::{MAX_CONTROL_RESPONSE_BYTES, MAX_EVENT_FRAME_BYTES, MAX_MIRRORED_EVENTS};

const CONTROL_EVENT_SCHEMA_V1: &str = "scorchkit.control.event/v1";

/// Browser replay failure when its cursor predates the retained mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// The requested sequence is older than the newest bounded window.
    Expired { oldest: u64 },
    /// The requested sequence is ahead of the mirror.
    Future { newest: u64 },
}

/// Snapshot returned to one finite browser replay response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayBatch {
    /// Strictly newer events, in sequence order.
    pub events: Vec<ControlEventV1>,
    /// Highest accepted upstream sequence.
    pub newest: u64,
    /// Whether the upstream worker currently has an accepted connection.
    pub connected: bool,
}

#[derive(Debug, Default)]
struct MirrorState {
    events: VecDeque<ControlEventV1>,
    newest: u64,
    connected: bool,
    last_error: Option<String>,
}

/// Fixed-size, monotonic event mirror shared by the worker and Rustal routes.
#[derive(Debug, Clone)]
pub struct EventMirror {
    state: std::sync::Arc<RwLock<MirrorState>>,
    capacity: usize,
}

impl EventMirror {
    /// Construct a mirror with an explicit nonzero capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            state: std::sync::Arc::new(RwLock::new(MirrorState::default())),
            capacity: capacity.clamp(1, MAX_MIRRORED_EVENTS),
        }
    }

    /// Insert one validated, strictly monotonic event.
    ///
    /// # Errors
    ///
    /// Rejects schema drift, sequence zero, duplicates, gaps, and non-job resource identities.
    pub async fn insert(&self, event: ControlEventV1) -> Result<()> {
        if event.schema_version != CONTROL_EVENT_SCHEMA_V1
            || event.sequence == 0
            || event.resource_type != "job"
        {
            bail!("control event failed console validation");
        }
        let mut state = self.state.write().await;
        if event.sequence != state.newest.saturating_add(1) {
            bail!("control event sequence is not contiguous");
        }
        state.newest = event.sequence;
        state.events.push_back(event);
        while state.events.len() > self.capacity {
            let _ = state.events.pop_front();
        }
        state.connected = true;
        state.last_error = None;
        drop(state);
        Ok(())
    }

    async fn mark_connected(&self) {
        let mut state = self.state.write().await;
        state.connected = true;
        state.last_error = None;
    }

    async fn reset_cursor(&self, cursor: u64) {
        let mut state = self.state.write().await;
        state.events.clear();
        state.newest = cursor;
        state.connected = false;
        state.last_error = Some("event cursor reset".to_owned());
    }

    /// Record an upstream state change without retaining secret-bearing diagnostics.
    pub async fn mark_disconnected(&self, reason: &'static str) {
        let mut state = self.state.write().await;
        state.connected = false;
        state.last_error = Some(reason.to_owned());
    }

    /// Return a bounded finite replay strictly after `after`.
    ///
    /// # Errors
    ///
    /// Returns an explicit expired or future cursor instead of silently skipping events.
    pub async fn replay(&self, after: u64, limit: usize) -> Result<ReplayBatch, ReplayError> {
        let state = self.state.read().await;
        if after > state.newest {
            return Err(ReplayError::Future { newest: state.newest });
        }
        let oldest = state
            .events
            .front()
            .map_or_else(|| state.newest.saturating_add(1), |event| event.sequence);
        if after != 0 && after.saturating_add(1) < oldest {
            return Err(ReplayError::Expired { oldest });
        }
        Ok(ReplayBatch {
            events: state
                .events
                .iter()
                .filter(|event| event.sequence > after)
                .take(limit.max(1))
                .cloned()
                .collect(),
            newest: state.newest,
            connected: state.connected,
        })
    }

    /// Highest accepted upstream sequence.
    pub async fn newest(&self) -> u64 {
        self.state.read().await.newest
    }
}

impl Default for EventMirror {
    fn default() -> Self {
        Self::new(MAX_MIRRORED_EVENTS)
    }
}

/// Run the bounded upstream reconnect loop until its task is cancelled.
pub async fn run_event_worker(client: ControlClient, mirror: EventMirror) {
    let mut delay = Duration::from_millis(250);
    loop {
        let after = mirror.newest().await;
        match consume_once(&client, &mirror, after).await {
            Ok(()) => mirror.mark_disconnected("event stream ended").await,
            Err(error) => {
                tracing::warn!(
                    event = "console.event_stream.reconnect",
                    reason = %safe_event_error(&error),
                    "console event mirror reconnecting"
                );
                mirror.mark_disconnected("event stream unavailable").await;
            }
        }
        tokio::time::sleep(delay).await;
        delay = delay.saturating_mul(2).min(Duration::from_secs(5));
    }
}

async fn consume_once(client: &ControlClient, mirror: &EventMirror, after: u64) -> Result<()> {
    let response = client
        .event_request(after)
        .send()
        .await
        .map_err(|_| anyhow!("event stream request failed"))?;
    if !response.status().is_success() {
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some("application/json") {
            bail!("event stream response was rejected");
        }
        let bytes = bounded_body(response, MAX_CONTROL_RESPONSE_BYTES).await?;
        let error: ControlErrorV1 = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("event stream error response was invalid"))?;
        let cursor = reset_cursor(&error)
            .ok_or_else(|| anyhow!("control event stream request was rejected"))?;
        mirror.reset_cursor(cursor).await;
        bail!("control event cursor was reset");
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some("text/event-stream") {
        bail!("event stream response was rejected");
    }
    mirror.mark_connected().await;
    let mut decoder = SseDecoder::default();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| anyhow!("event stream body failed"))?;
        for frame in decoder.push(&chunk)? {
            match frame.event.as_str() {
                "control" => {
                    let event: ControlEventV1 = serde_json::from_str(&frame.data)
                        .map_err(|_| anyhow!("event stream control payload was invalid"))?;
                    let frame_id = frame
                        .id
                        .as_deref()
                        .ok_or_else(|| anyhow!("event stream control frame omitted an id"))?
                        .parse::<u64>()
                        .map_err(|_| anyhow!("event stream control id was invalid"))?;
                    if frame_id != event.sequence {
                        bail!("event stream id did not match its payload");
                    }
                    mirror.insert(event).await?;
                }
                "error" => {
                    let error: ControlErrorV1 = serde_json::from_str(&frame.data)
                        .map_err(|_| anyhow!("event stream error payload was invalid"))?;
                    bail!("control event stream reported {}", error.message);
                }
                "" => {}
                _ => bail!("event stream used an unsupported event type"),
            }
        }
    }
    if decoder.has_partial() {
        bail!("event stream ended with an incomplete frame");
    }
    Ok(())
}

fn reset_cursor(error: &ControlErrorV1) -> Option<u64> {
    match error.code {
        ControlErrorCodeV1::EventCursorFuture => Some(0),
        ControlErrorCodeV1::EventCursorExpired => {
            let details = error.details.as_ref()?.as_object()?;
            let oldest = details.get("oldestSequence")?.as_u64()?;
            let latest = details.get("latestSequence")?.as_u64()?;
            (oldest > 0 && oldest <= latest.saturating_add(1)).then(|| oldest - 1)
        }
        _ => None,
    }
}

fn safe_event_error(error: &anyhow::Error) -> &'static str {
    if error.to_string().contains("cursor") {
        "cursor continuity failure"
    } else {
        "upstream stream failure"
    }
}

#[derive(Debug, Default)]
struct SseDecoder {
    buffer: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SseFrame {
    event: String,
    id: Option<String>,
    data: String,
}

impl SseDecoder {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseFrame>> {
        let mut frames = Vec::new();
        for byte in chunk {
            self.buffer.push(*byte);
            if self.buffer.len() > MAX_EVENT_FRAME_BYTES {
                bail!("event stream frame exceeded the console limit");
            }
            let delimiter = if self.buffer.ends_with(b"\r\n\r\n") {
                Some(4)
            } else if self.buffer.ends_with(b"\n\n") {
                Some(2)
            } else {
                None
            };
            if let Some(delimiter) = delimiter {
                let end = self.buffer.len() - delimiter;
                let raw = self.buffer[..end].to_vec();
                self.buffer.clear();
                if let Some(frame) = parse_frame(&raw)? {
                    frames.push(frame);
                }
            }
        }
        Ok(frames)
    }

    const fn has_partial(&self) -> bool {
        !self.buffer.is_empty()
    }
}

fn parse_frame(bytes: &[u8]) -> Result<Option<SseFrame>> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| anyhow!("event stream frame was not UTF-8"))?;
    let mut event = String::new();
    let mut id = None;
    let mut data = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with(':') || line.is_empty() {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" if event.is_empty() => value.clone_into(&mut event),
            "id" if id.is_none() => id = Some(value.to_owned()),
            "data" => data.push(value),
            "event" | "id" => bail!("event stream frame repeated a singleton field"),
            _ => {}
        }
    }
    if event.is_empty() && id.is_none() && data.is_empty() {
        return Ok(None);
    }
    if data.is_empty() {
        bail!("event stream frame omitted data");
    }
    Ok(Some(SseFrame { event, id, data: data.join("\n") }))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use scorchkit_control::ControlEventKindV1;
    use uuid::Uuid;

    use super::*;

    fn event(sequence: u64) -> ControlEventV1 {
        ControlEventV1 {
            schema_version: CONTROL_EVENT_SCHEMA_V1.to_owned(),
            sequence,
            kind: ControlEventKindV1::JobChanged,
            resource_type: "job".to_owned(),
            resource_id: Uuid::nil(),
            resource_revision: sequence,
            occurred_at: Utc::now(),
            payload: serde_json::json!({"state": "running", "sequence": sequence}),
        }
    }

    #[test]
    fn fragmented_crlf_frames_decode_exactly() -> Result<()> {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"event: con").is_ok_and(|frames| frames.is_empty()));
        let frames = decoder.push(b"trol\r\nid: 7\r\ndata: {\"sequence\":7}\r\n\r\n")?;
        assert_eq!(
            frames,
            [SseFrame {
                event: "control".to_owned(),
                id: Some("7".to_owned()),
                data: "{\"sequence\":7}".to_owned(),
            }]
        );
        assert!(!decoder.has_partial());
        Ok(())
    }

    #[tokio::test]
    async fn mirror_enforces_contiguity_and_explicit_cursor_bounds() -> Result<()> {
        let mirror = EventMirror::new(2);
        assert_eq!(EventMirror::new(usize::MAX).capacity, MAX_MIRRORED_EVENTS);
        assert!(mirror.insert(event(2)).await.is_err());
        mirror.insert(event(1)).await?;
        mirror.insert(event(2)).await?;
        mirror.insert(event(3)).await?;
        mirror.insert(event(4)).await?;
        assert!(mirror.insert(event(6)).await.is_err());
        assert_eq!(mirror.replay(1, 10).await, Err(ReplayError::Expired { oldest: 3 }));
        assert_eq!(mirror.replay(5, 10).await, Err(ReplayError::Future { newest: 4 }));
        let replay = mirror.replay(3, 1).await.map_err(|_| anyhow!("replay"))?;
        assert_eq!(replay.events.iter().map(|event| event.sequence).collect::<Vec<_>>(), [4]);
        Ok(())
    }

    #[tokio::test]
    async fn mirror_resets_to_an_authenticated_retention_boundary() -> Result<()> {
        let mirror = EventMirror::new(2);
        mirror.insert(event(1)).await?;
        mirror.reset_cursor(7).await;
        let replay = mirror.replay(7, 1).await.map_err(|_| anyhow!("replay"))?;
        assert_eq!(replay.newest, 7);
        assert!(!replay.connected);
        assert!(replay.events.is_empty());
        assert!(mirror.insert(event(7)).await.is_err());
        mirror.insert(event(8)).await?;
        Ok(())
    }

    #[test]
    fn cursor_errors_have_closed_reset_rules() {
        let expired = ControlErrorV1::new(ControlErrorCodeV1::EventCursorExpired, "expired")
            .with_details(serde_json::json!({"oldestSequence": 8, "latestSequence": 10}));
        assert_eq!(reset_cursor(&expired), Some(7));
        let malformed = ControlErrorV1::new(ControlErrorCodeV1::EventCursorExpired, "expired")
            .with_details(serde_json::json!({"oldestSequence": 12, "latestSequence": 10}));
        assert_eq!(reset_cursor(&malformed), None);
        assert_eq!(
            reset_cursor(&ControlErrorV1::new(ControlErrorCodeV1::EventCursorFuture, "future",)),
            Some(0)
        );
        assert_eq!(reset_cursor(&ControlErrorV1::new(ControlErrorCodeV1::Busy, "busy")), None);
    }

    #[test]
    fn malformed_and_oversized_frames_fail_closed() {
        let mut duplicate = SseDecoder::default();
        assert!(duplicate.push(b"event: control\nevent: other\ndata: {}\n\n").is_err());
        let mut oversized = SseDecoder::default();
        assert!(oversized.push(&vec![b'x'; MAX_EVENT_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn chunk_size_does_not_replace_the_per_frame_limit() -> Result<()> {
        let data = "x".repeat(MAX_EVENT_FRAME_BYTES / 2);
        let frame = format!("event: note\ndata: {data}\n\n");
        let chunk = format!("{frame}{frame}");
        assert!(chunk.len() > MAX_EVENT_FRAME_BYTES);
        let frames = SseDecoder::default().push(chunk.as_bytes())?;
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|frame| frame.data.len() == data.len()));
        Ok(())
    }
}
