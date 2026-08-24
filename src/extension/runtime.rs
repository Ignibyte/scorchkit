use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use uuid::Uuid;

use scorchkit_extension::{
    ExtensionInvocationInputV1, ExtensionInvocationV1, ExtensionManifestV1, ExtensionTurnInputV1,
    ExtensionTurnOutputV1, MAX_EXTENSION_MODULE_BYTES,
};

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::scan_context::ScanContext;
use crate::runner::subprocess::{spawn_owned_process, stop_owned_process};

use super::broker::{broker_effect, convert_output};
use super::loader::LoadedExtension;
use super::EXTENSION_WORKER_ARGUMENT;

const WORKER_START_SCHEMA_V1: &str = "scorchkit.extension-worker-start/v1";
const MAX_WORKER_HEADER_BYTES: usize = 512 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WorkerStartV1 {
    pub schema_version: String,
    pub manifest: ExtensionManifestV1,
    pub invocation: ExtensionInvocationV1,
    pub module_bytes: u64,
}

pub(super) async fn run(
    context: &ScanContext,
    loaded: &LoadedExtension,
    worker_program: &Path,
    inputs: &[ExtensionInvocationInputV1],
) -> Result<Vec<Finding>> {
    context.authorize_extension_execution(loaded.manifest.adapter.strongest_effect)?;
    let timeout = Duration::from_millis(loaded.manifest.budgets.timeout_ms);
    let worker_started = Instant::now();
    let mut invocation = ExtensionInvocationV1::new(
        Uuid::new_v4().to_string(),
        loaded.manifest.id.clone(),
        context.target.url.as_str(),
    );
    invocation.inputs = inputs.to_vec();
    let command = worker_command(worker_program);
    let mut child = spawn_owned_process(command).map_err(|error| ScorchError::ToolFailed {
        tool: "scorchkit-extension-worker".to_string(),
        status: -1,
        stderr: error.to_string(),
    })?;
    let mut stdin = child.take_stdin().ok_or_else(|| worker_error("worker stdin unavailable"))?;
    let mut stdout =
        child.take_stdout().ok_or_else(|| worker_error("worker stdout unavailable"))?;
    let start = worker_start(loaded, &invocation)?;
    let transfer = tokio::time::timeout(timeout, async {
        write_json_frame(&mut stdin, &start, MAX_WORKER_HEADER_BYTES).await?;
        write_raw(&mut stdin, &loaded.module_bytes, MAX_EXTENSION_MODULE_BYTES).await
    })
    .await;
    match transfer {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let _ = stop_owned_process(&mut child).await;
            return Err(error);
        }
        Err(_) => {
            let _ = stop_owned_process(&mut child).await;
            return Err(ScorchError::Cancelled {
                reason: format!("extension {} exceeded its wall-time budget", loaded.manifest.id),
            });
        }
    }

    let session = async {
        let mut effect_count = 0_u32;
        let mut request_ids = std::collections::BTreeSet::new();
        loop {
            let turn: ExtensionTurnOutputV1 = read_json_frame(
                &mut stdout,
                usize::try_from(loaded.manifest.budgets.output_bytes).map_err(|_| {
                    worker_error("extension output limit is unsupported on this host")
                })?,
            )
            .await?;
            match turn {
                ExtensionTurnOutputV1::EffectRequest(request) => {
                    effect_count = effect_count.saturating_add(1);
                    if effect_count > loaded.manifest.budgets.effects {
                        return Err(worker_error("extension effect count exceeded its manifest"));
                    }
                    if !request_ids.insert(request.request_id.clone()) {
                        return Err(worker_error("extension reused an effect request identity"));
                    }
                    let result =
                        broker_effect(context, &loaded.manifest, &invocation, &request).await;
                    write_json_frame(
                        &mut stdin,
                        &ExtensionTurnInputV1::EffectResult(result),
                        usize::try_from(loaded.manifest.budgets.input_bytes).map_err(|_| {
                            worker_error("extension input limit is unsupported on this host")
                        })?,
                    )
                    .await?;
                }
                ExtensionTurnOutputV1::Complete(output) => {
                    return convert_output(context, &loaded.manifest, &invocation, output);
                }
                ExtensionTurnOutputV1::Failure(failure) => {
                    let code = crate::engine::observation::redact_text(&failure.code);
                    if code.trim().is_empty() || code.len() > 128 {
                        return Err(worker_error("extension returned an invalid failure code"));
                    }
                    return Err(worker_error(&format!(
                        "extension failed with safe code {}: {}",
                        code,
                        crate::engine::observation::redact_text(&failure.message)
                    )));
                }
            }
        }
    };

    let remaining = timeout.saturating_sub(worker_started.elapsed());
    let result = tokio::time::timeout(remaining, session).await;
    let stop_result = stop_owned_process(&mut child).await;
    match (result, stop_result) {
        (Ok(result), Ok(())) => result,
        (Ok(Err(error)), _) => Err(error),
        (Err(_), _) => Err(ScorchError::Cancelled {
            reason: format!("extension {} exceeded its wall-time budget", loaded.manifest.id),
        }),
        (Ok(Ok(_)), Err(error)) => {
            Err(worker_error(&format!("failed to clean up extension worker: {error}")))
        }
    }
}

fn worker_command(worker_program: &Path) -> Command {
    let mut command = Command::new(worker_program);
    command
        .arg(EXTENSION_WORKER_ARGUMENT)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
}

fn worker_start(
    loaded: &LoadedExtension,
    invocation: &ExtensionInvocationV1,
) -> Result<WorkerStartV1> {
    Ok(WorkerStartV1 {
        schema_version: WORKER_START_SCHEMA_V1.to_string(),
        manifest: loaded.manifest.clone(),
        invocation: invocation.clone(),
        module_bytes: u64::try_from(loaded.module_bytes.len())
            .map_err(|_| worker_error("extension module length is unsupported on this host"))?,
    })
}

fn worker_error(message: &str) -> ScorchError {
    ScorchError::ToolOutputParse {
        tool: "scorchkit-extension-worker".to_string(),
        reason: message.to_string(),
    }
}

pub(super) async fn write_json_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
    maximum: usize,
) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| worker_error("cannot encode worker frame"))?;
    if bytes.len() > maximum {
        return Err(worker_error("worker frame exceeds its byte limit"));
    }
    let length =
        u32::try_from(bytes.len()).map_err(|_| worker_error("worker frame is too large"))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub(super) async fn read_json_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
    maximum: usize,
) -> Result<T> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| worker_error("worker frame length is unsupported"))?;
    if length == 0 || length > maximum {
        return Err(worker_error("worker frame length is outside its boundary"));
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| worker_error("worker returned malformed JSON"))
}

pub(super) async fn write_raw<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    maximum: u64,
) -> Result<()> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(worker_error("raw worker payload exceeds its byte limit"));
    }
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub(super) async fn read_raw<R: AsyncRead + Unpin>(
    reader: &mut R,
    length: u64,
    maximum: u64,
) -> Result<Vec<u8>> {
    if length == 0 || length > maximum {
        return Err(worker_error("raw worker payload length is outside its boundary"));
    }
    let length = usize::try_from(length)
        .map_err(|_| worker_error("raw worker payload length is unsupported"))?;
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension::test_support;

    fn error_text(error: &ScorchError) -> String {
        error.to_string()
    }

    #[tokio::test]
    async fn framed_json_write_and_read_accept_the_limit_and_reject_both_sides() {
        assert_eq!(MAX_WORKER_HEADER_BYTES, 524_288);
        let value = serde_json::json!({"bounded": true});
        let encoded = serde_json::to_vec(&value).expect("encoded fixture");

        let (mut writer, mut reader) = tokio::io::duplex(1024);
        write_json_frame(&mut writer, &value, encoded.len()).await.expect("exact write boundary");
        let decoded: serde_json::Value =
            read_json_frame(&mut reader, encoded.len()).await.expect("exact read boundary");
        assert_eq!(decoded, value);

        let (mut writer, _) = tokio::io::duplex(1024);
        assert!(error_text(
            &write_json_frame(&mut writer, &value, encoded.len() - 1)
                .await
                .expect_err("write overflow")
        )
        .contains("frame exceeds"));

        for (length, maximum, payload) in [
            (0_u32, encoded.len(), Vec::new()),
            (
                u32::try_from(encoded.len() + 1).unwrap(),
                encoded.len(),
                vec![b' '; encoded.len() + 1],
            ),
        ] {
            let mut bytes = length.to_be_bytes().to_vec();
            bytes.extend(payload);
            let error = read_json_frame::<_, serde_json::Value>(&mut bytes.as_slice(), maximum)
                .await
                .expect_err("invalid frame boundary");
            assert!(error_text(&error).contains("outside its boundary"));
        }
    }

    #[tokio::test]
    async fn raw_io_accepts_the_exact_limit_and_rejects_zero_and_overflow_lengths() {
        let payload = b"abcd";
        let (mut writer, mut reader) = tokio::io::duplex(16);
        write_raw(&mut writer, payload, 4).await.expect("exact raw write");
        assert_eq!(read_raw(&mut reader, 4, 4).await.expect("exact raw read"), payload);

        let (mut writer, _) = tokio::io::duplex(16);
        assert!(error_text(
            &write_raw(&mut writer, payload, 3).await.expect_err("raw write overflow")
        )
        .contains("exceeds its byte limit"));
        for (length, maximum) in [(0, 4), (5, 4)] {
            let error = read_raw(&mut payload.as_slice(), length, maximum)
                .await
                .expect_err("raw read boundary");
            assert!(error_text(&error).contains("outside its boundary"));
        }
    }

    #[tokio::test]
    async fn worker_spawn_failure_preserves_the_process_error_status() {
        let directory = tempfile::tempdir().expect("worker fixture");
        let worker = directory.path().join("missing-worker");
        let error =
            run(&test_support::context(), &test_support::loaded(b"module".to_vec()), &worker, &[])
                .await
                .expect_err("missing worker must fail");
        match error {
            ScorchError::ToolFailed { status, .. } => assert_eq!(status, -1),
            other => panic!("unexpected worker error: {other}"),
        }
    }

    #[test]
    fn runtime_session_pins_effect_and_failure_boundaries() {
        let production =
            include_str!("runtime.rs").split("#[cfg(test)]").next().expect("production source");
        let compact: String = production.split_whitespace().collect();
        assert!(compact.contains("ifeffect_count>loaded.manifest.budgets.effects{"));
        assert!(compact.contains("ifcode.trim().is_empty()||code.len()>128{"));
    }
}
