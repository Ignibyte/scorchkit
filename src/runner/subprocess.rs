use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;

use crate::engine::error::{Result, ScorchError};

/// Default maximum captured bytes for each child-process output stream.
pub const DEFAULT_TOOL_OUTPUT_LIMIT_BYTES: usize = 8_388_608;

/// Sentinel used when process infrastructure fails before yielding an exit status.
const TOOL_INFRASTRUCTURE_FAILURE_STATUS: i32 = -1;

/// Whether a tool invocation requires a successful process exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitPolicy {
    /// A non-zero exit status is an infrastructure failure.
    RequireSuccess,
    /// Return captured output for any exit status.
    AllowNonZero,
}

/// Complete, owned description of one external tool execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocation {
    /// Requested executable name or path.
    pub program: String,
    /// Argument vector passed without shell interpretation.
    pub args: Vec<String>,
    /// Maximum wall-clock execution time.
    pub timeout: Duration,
    /// Exit-status handling policy.
    pub exit_policy: ExitPolicy,
    /// Maximum captured bytes for each of stdout and stderr.
    pub output_limit_bytes: usize,
    /// Optional bytes written to the child's standard input before EOF.
    pub stdin: Option<Vec<u8>>,
}

impl ToolInvocation {
    /// Build an invocation that requires a zero exit status.
    #[must_use]
    pub fn strict(program: &str, args: &[&str], timeout: Duration) -> Self {
        Self::new(program, args, timeout, ExitPolicy::RequireSuccess)
    }

    /// Build an invocation that captures normal non-zero finding exits.
    #[must_use]
    pub fn lenient(program: &str, args: &[&str], timeout: Duration) -> Self {
        Self::new(program, args, timeout, ExitPolicy::AllowNonZero)
    }

    fn new(program: &str, args: &[&str], timeout: Duration, exit_policy: ExitPolicy) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|argument| (*argument).to_string()).collect(),
            timeout,
            exit_policy,
            output_limit_bytes: DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
            stdin: None,
        }
    }

    /// Override the per-stream output limit.
    #[must_use]
    pub const fn with_output_limit(mut self, output_limit_bytes: usize) -> Self {
        self.output_limit_bytes = output_limit_bytes;
        self
    }

    /// Supply owned standard-input bytes to the child.
    #[must_use]
    pub fn with_stdin(mut self, stdin: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(stdin.into());
        self
    }
}

/// Output from running an external tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Child exit status, or `-1` when the platform supplied none.
    pub exit_code: i32,
    /// Wall-clock execution duration.
    pub duration: Duration,
    /// Canonical executable path selected for this invocation.
    pub resolved_program: PathBuf,
}

/// Injectable external-process boundary used by scan and code contexts.
#[async_trait]
pub trait ToolExecutor: Debug + Send + Sync {
    /// Execute one fully specified invocation.
    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput>;
}

/// Production executor backed by `tokio::process::Command`.
#[derive(Debug, Default)]
pub(crate) struct SystemToolExecutor;

/// RAII ownership for the process group created for one external tool.
///
/// On Unix, dropping this guard sends `SIGKILL` to the whole group, including
/// descendants that outlive or detach from the direct child. The direct child
/// still uses Tokio's `kill_on_drop` as a platform fallback.
#[derive(Debug)]
pub(crate) struct OwnedProcessGroup {
    #[cfg(unix)]
    process_group: Option<rustix::process::Pid>,
}

impl OwnedProcessGroup {
    pub(crate) fn for_child(child: &Child) -> Self {
        #[cfg(unix)]
        let process_group = child
            .id()
            .and_then(|raw| i32::try_from(raw).ok())
            .and_then(rustix::process::Pid::from_raw);
        Self {
            #[cfg(unix)]
            process_group,
        }
    }

    #[cfg(unix)]
    fn terminate(&mut self) -> std::io::Result<()> {
        let Some(process_group) = self.process_group.take() else {
            return Ok(());
        };
        match rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(error) => Err(std::io::Error::from_raw_os_error(error.raw_os_error())),
        }
    }

    #[cfg(not(unix))]
    fn terminate(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

/// Put a child in a fresh owned process group before it is spawned.
pub(crate) fn configure_owned_process_group(command: &mut tokio::process::Command) {
    #[cfg(unix)]
    {
        command.process_group(0);
    }
}

/// Terminate and reap an owned child process tree.
pub(crate) async fn stop_owned_process(
    child: &mut Child,
    process_group: &mut OwnedProcessGroup,
) -> std::io::Result<()> {
    let child_already_exited = child.try_wait()?.is_some();
    let group_result = process_group.terminate();

    #[cfg(unix)]
    match group_stop_disposition(child_already_exited, &group_result) {
        GroupStopDisposition::WaitForChild => {}
        GroupStopDisposition::ObserveExitRace => {
            // The child can exit after `try_wait` but before `killpg`. macOS may report EPERM while
            // that exited process is still being reaped. Bound the observation window so a genuine
            // permission failure on a live process cannot hang session shutdown.
            return match tokio::time::timeout(Duration::from_secs(1), child.wait()).await {
                Ok(wait_result) => {
                    reconcile_process_stop(true, group_result, wait_result.map(|_| ()))
                }
                Err(_) => group_result,
            };
        }
        GroupStopDisposition::ReturnError => return group_result,
    }

    #[cfg(not(unix))]
    if child.try_wait()?.is_none() {
        child.kill().await?;
    }

    let wait_result = child.wait().await.map(|_| ());
    reconcile_process_stop(child_already_exited, group_result, wait_result)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupStopDisposition {
    WaitForChild,
    ObserveExitRace,
    ReturnError,
}

#[cfg(unix)]
fn group_stop_disposition(
    child_already_exited: bool,
    group_result: &std::io::Result<()>,
) -> GroupStopDisposition {
    match group_result {
        Ok(()) => GroupStopDisposition::WaitForChild,
        Err(_) if child_already_exited => GroupStopDisposition::WaitForChild,
        Err(error) if ignorable_group_termination_error(true, error) => {
            GroupStopDisposition::ObserveExitRace
        }
        Err(_) => GroupStopDisposition::ReturnError,
    }
}

fn reconcile_process_stop(
    child_already_exited: bool,
    group_result: std::io::Result<()>,
    wait_result: std::io::Result<()>,
) -> std::io::Result<()> {
    match group_result {
        Ok(()) => wait_result,
        #[cfg(unix)]
        Err(error) if ignorable_group_termination_error(child_already_exited, &error) => {
            wait_result
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn ignorable_group_termination_error(child_already_exited: bool, error: &std::io::Error) -> bool {
    child_already_exited && error.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error())
}

#[async_trait]
impl ToolExecutor for SystemToolExecutor {
    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
        execute_system(invocation).await
    }
}

#[cfg(test)]
async fn run_tool_lenient(tool_name: &str, args: &[&str], timeout: Duration) -> Result<ToolOutput> {
    SystemToolExecutor.execute(ToolInvocation::lenient(tool_name, args, timeout)).await
}

#[cfg(test)]
async fn run_tool(tool_name: &str, args: &[&str], timeout: Duration) -> Result<ToolOutput> {
    SystemToolExecutor.execute(ToolInvocation::strict(tool_name, args, timeout)).await
}

/// Return whether an executable name or explicit path resolves through the
/// same rules used by [`SystemToolExecutor`].
#[must_use]
pub(crate) fn is_tool_available(tool: &str) -> bool {
    resolve_tool_path(tool).is_ok()
}

/// Return the declared executable only when a tool-backed module cannot run.
#[must_use]
pub(crate) fn missing_required_tool(
    requires_external_tool: bool,
    required_tool: Option<&str>,
) -> Option<&str> {
    if !requires_external_tool {
        return None;
    }
    required_tool.filter(|tool| !is_tool_available(tool))
}

async fn execute_system(invocation: ToolInvocation) -> Result<ToolOutput> {
    let resolved_program = resolve_tool_path(&invocation.program)?;
    let started = Instant::now();
    let mut command = tokio::process::Command::new(&resolved_program);
    command
        .args(&invocation.args)
        .stdin(if invocation.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_owned_process_group(&mut command);

    let mut child = command.spawn().map_err(|error| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: error.to_string(),
    })?;
    let mut process_group = OwnedProcessGroup::for_child(&child);
    let stdout = child.stdout.take().ok_or_else(|| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: "failed to capture stdout".to_string(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: "failed to capture stderr".to_string(),
    })?;
    let stdin = child.stdin.take();
    let stdin_bytes = invocation.stdin.clone();

    let execution =
        coordinate_child_io(&mut child, stdout, stderr, stdin, stdin_bytes, &invocation);

    let (status, stdout, stderr, stdin) = match tokio::time::timeout(invocation.timeout, execution)
        .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            let _ = stop_owned_process(&mut child, &mut process_group).await;
            return Err(error);
        }
        Err(_) => {
            let _ = stop_owned_process(&mut child, &mut process_group).await;
            return Err(ScorchError::Cancelled {
                reason: format!("{} timed out after {:?}", invocation.program, invocation.timeout),
            });
        }
    };

    stop_owned_process(&mut child, &mut process_group).await.map_err(|error| {
        ScorchError::ToolFailed {
            tool: invocation.program.clone(),
            status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
            stderr: format!("failed to clean up process tree: {error}"),
        }
    })?;

    let status = status.map_err(|error| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: error.to_string(),
    })?;
    let stdout = stdout.map_err(|error| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: error.to_string(),
    })?;
    let stderr = stderr.map_err(|error| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: error.to_string(),
    })?;
    stdin.map_err(|error| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: format!("failed to write tool stdin: {error}"),
    })?;

    let exit_code = status.code().unwrap_or(TOOL_INFRASTRUCTURE_FAILURE_STATUS);
    let stderr = String::from_utf8_lossy(&stderr.bytes).into_owned();
    if invocation.exit_policy == ExitPolicy::RequireSuccess && !status.success() {
        return Err(ScorchError::ToolFailed {
            tool: invocation.program,
            status: exit_code,
            stderr,
        });
    }

    Ok(ToolOutput {
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stderr,
        exit_code,
        duration: started.elapsed(),
        resolved_program,
    })
}

type ChildIoOutcome = (
    std::io::Result<std::process::ExitStatus>,
    std::io::Result<BoundedRead>,
    std::io::Result<BoundedRead>,
    std::io::Result<()>,
);

async fn coordinate_child_io(
    child: &mut Child,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
    stdin: Option<tokio::process::ChildStdin>,
    stdin_bytes: Option<Vec<u8>>,
    invocation: &ToolInvocation,
) -> Result<ChildIoOutcome> {
    let write_stdin = async move {
        if let (Some(mut stdin), Some(bytes)) = (stdin, stdin_bytes) {
            stdin.write_all(&bytes).await?;
            stdin.shutdown().await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let wait_child = child.wait();
    let read_stdout = read_bounded(stdout, invocation.output_limit_bytes);
    let read_stderr = read_bounded(stderr, invocation.output_limit_bytes);
    tokio::pin!(wait_child, read_stdout, read_stderr, write_stdin);

    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    let mut stdin = None;
    loop {
        tokio::select! {
            result = &mut wait_child, if status.is_none() => status = Some(result),
            result = &mut read_stdout, if stdout.is_none() => {
                reject_excess_output(&result, invocation, "stdout")?;
                stdout = Some(result);
            }
            result = &mut read_stderr, if stderr.is_none() => {
                reject_excess_output(&result, invocation, "stderr")?;
                stderr = Some(result);
            }
            result = &mut write_stdin, if stdin.is_none() => stdin = Some(result),
        }

        if status.is_some() && stdout.is_some() && stderr.is_some() && stdin.is_some() {
            return match (status.take(), stdout.take(), stderr.take(), stdin.take()) {
                (Some(status), Some(stdout), Some(stderr), Some(stdin)) => {
                    Ok((status, stdout, stderr, stdin))
                }
                _ => Err(ScorchError::ToolFailed {
                    tool: invocation.program.clone(),
                    status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
                    stderr: "internal process coordinator state was incomplete".to_string(),
                }),
            };
        }
    }
}

fn reject_excess_output(
    output: &std::io::Result<BoundedRead>,
    invocation: &ToolInvocation,
    stream: &'static str,
) -> Result<()> {
    if output.as_ref().is_ok_and(|bounded| bounded.exceeded) {
        return Err(ScorchError::ToolOutputLimit {
            tool: invocation.program.clone(),
            stream,
            limit_bytes: invocation.output_limit_bytes,
        });
    }
    Ok(())
}

struct BoundedRead {
    bytes: Vec<u8>,
    exceeded: bool,
}

async fn read_bounded<R>(reader: R, limit: usize) -> std::io::Result<BoundedRead>
where
    R: AsyncRead + Unpin,
{
    let read_limit = u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    reader.take(read_limit).read_to_end(&mut bytes).await?;
    let exceeded = bytes.len() > limit;
    bytes.truncate(limit);
    Ok(BoundedRead { bytes, exceeded })
}

/// Resolve an executable name or explicit path using the production execution rules.
///
/// # Errors
///
/// Returns [`ScorchError::ToolNotFound`] when no executable candidate exists,
/// or [`ScorchError::ToolFailed`] when a candidate cannot be canonicalized.
pub(crate) fn resolve_tool_path(tool: &str) -> Result<PathBuf> {
    let requested = Path::new(tool);
    if requested.is_absolute()
        || requested.parent().is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return validate_executable(requested, tool);
    }

    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            for candidate in executable_candidates(&directory, tool) {
                if is_executable(&candidate) {
                    return canonical_executable(&candidate, tool);
                }
            }
        }
    }

    Err(ScorchError::ToolNotFound { tool: tool.to_string() })
}

fn validate_executable(path: &Path, requested: &str) -> Result<PathBuf> {
    if is_executable(path) {
        canonical_executable(path, requested)
    } else {
        Err(ScorchError::ToolNotFound { tool: requested.to_string() })
    }
}

fn canonical_executable(path: &Path, requested: &str) -> Result<PathBuf> {
    path.canonicalize().map_err(|error| ScorchError::ToolFailed {
        tool: requested.to_string(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: error.to_string(),
    })
}

fn executable_candidates(directory: &Path, tool: &str) -> Vec<PathBuf> {
    let path_extensions = if cfg!(windows) {
        Some(
            std::env::var_os("PATHEXT")
                .unwrap_or_else(|| std::ffi::OsString::from(".COM;.EXE;.BAT;.CMD")),
        )
    } else {
        None
    };
    executable_candidates_with_extensions(directory, tool, path_extensions.as_deref())
}

fn executable_candidates_with_extensions(
    directory: &Path,
    tool: &str,
    path_extensions: Option<&std::ffi::OsStr>,
) -> Vec<PathBuf> {
    let Some(path_extensions) = path_extensions else {
        return vec![directory.join(tool)];
    };
    let requested = Path::new(tool);
    if requested.extension().is_some() {
        return vec![directory.join(requested)];
    }
    path_extensions
        .to_string_lossy()
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(|extension| directory.join(format!("{tool}{extension}")))
        .collect()
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    #[cfg(unix)]
    let unix_mode = {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode())
    };
    #[cfg(not(unix))]
    let unix_mode = None;
    executable_metadata_is_valid(metadata.is_file(), unix_mode)
}

const fn executable_metadata_is_valid(is_file: bool, unix_mode: Option<u32>) -> bool {
    is_file
        && match unix_mode {
            Some(mode) => mode & 0o111 != 0,
            None => true,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    static PROCESS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[test]
    fn process_limits_and_failure_status_are_stable() {
        assert_eq!(DEFAULT_TOOL_OUTPUT_LIMIT_BYTES, 8_388_608);
        assert_eq!(TOOL_INFRASTRUCTURE_FAILURE_STATUS, -1);
    }

    #[cfg(unix)]
    #[test]
    fn permission_error_is_ignored_only_after_the_owned_child_exits() {
        let permission = std::io::Error::from_raw_os_error(rustix::io::Errno::PERM.raw_os_error());
        let invalid = std::io::Error::from_raw_os_error(rustix::io::Errno::INVAL.raw_os_error());

        assert!(ignorable_group_termination_error(true, &permission));
        assert!(!ignorable_group_termination_error(false, &permission));
        assert!(!ignorable_group_termination_error(true, &invalid));
        assert!(!ignorable_group_termination_error(false, &invalid));
    }

    #[cfg(unix)]
    #[test]
    fn group_stop_disposition_distinguishes_exit_races_from_live_failures() {
        let permission = std::io::Error::from_raw_os_error(rustix::io::Errno::PERM.raw_os_error());
        let invalid = std::io::Error::from_raw_os_error(rustix::io::Errno::INVAL.raw_os_error());

        assert_eq!(group_stop_disposition(false, &Ok(())), GroupStopDisposition::WaitForChild);
        assert_eq!(
            group_stop_disposition(
                true,
                &Err(std::io::Error::from_raw_os_error(rustix::io::Errno::PERM.raw_os_error()))
            ),
            GroupStopDisposition::WaitForChild
        );
        assert_eq!(
            group_stop_disposition(false, &Err(permission)),
            GroupStopDisposition::ObserveExitRace
        );
        assert_eq!(group_stop_disposition(false, &Err(invalid)), GroupStopDisposition::ReturnError);
    }

    #[cfg(unix)]
    #[test]
    fn process_stop_reconciliation_preserves_non_ignorable_errors() {
        let permission_code = rustix::io::Errno::PERM.raw_os_error();
        let invalid_code = rustix::io::Errno::INVAL.raw_os_error();

        assert!(reconcile_process_stop(
            true,
            Err(std::io::Error::from_raw_os_error(permission_code)),
            Ok(())
        )
        .is_ok());

        let running_child_error = reconcile_process_stop(
            false,
            Err(std::io::Error::from_raw_os_error(permission_code)),
            Ok(()),
        )
        .expect_err("permission errors from a live child must be retained");
        assert_eq!(running_child_error.raw_os_error(), Some(permission_code));

        let different_group_error = reconcile_process_stop(
            true,
            Err(std::io::Error::from_raw_os_error(invalid_code)),
            Ok(()),
        )
        .expect_err("only the exited-child permission race is ignorable");
        assert_eq!(different_group_error.raw_os_error(), Some(invalid_code));

        let wait_error = reconcile_process_stop(
            true,
            Ok(()),
            Err(std::io::Error::from_raw_os_error(invalid_code)),
        )
        .expect_err("a successful group stop must not hide a wait failure");
        assert_eq!(wait_error.raw_os_error(), Some(invalid_code));
    }

    #[test]
    fn invocation_owns_arguments_and_applies_default_limit() {
        let invocation =
            ToolInvocation::strict("tool", &["--flag", "value"], Duration::from_secs(3));
        assert_eq!(invocation.program, "tool");
        assert_eq!(invocation.args, ["--flag", "value"]);
        assert_eq!(invocation.timeout, Duration::from_secs(3));
        assert_eq!(invocation.exit_policy, ExitPolicy::RequireSuccess);
        assert_eq!(invocation.output_limit_bytes, DEFAULT_TOOL_OUTPUT_LIMIT_BYTES);
        assert!(invocation.stdin.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn strict_and_lenient_exit_policies_are_distinct() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let args = ["-c", "printf out; printf err >&2; exit 7"];
        let strict = run_tool("sh", &args, Duration::from_secs(2)).await;
        assert!(matches!(
            strict,
            Err(ScorchError::ToolFailed {
                status: 7,
                ref stderr,
                ..
            }) if stderr == "err"
        ));

        let lenient = run_tool_lenient("sh", &args, Duration::from_secs(2))
            .await
            .unwrap_or_else(|error| panic!("lenient execution failed: {error}"));
        assert_eq!(lenient.exit_code, 7);
        assert_eq!(lenient.stdout, "out");
        assert_eq!(lenient.stderr, "err");
        assert!(lenient.resolved_program.is_absolute());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_limit_fails_closed() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let invocation =
            ToolInvocation::strict("sh", &["-c", "printf 12345"], Duration::from_secs(2))
                .with_output_limit(4);
        let result = SystemToolExecutor.execute(invocation).await;
        assert!(matches!(
            result,
            Err(ScorchError::ToolOutputLimit { stream: "stdout", limit_bytes: 4, .. })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_limit_terminates_the_process_tree_without_waiting_for_timeout() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("output-limit-descendant.pid");
        let pid_path = pid_file.to_string_lossy().into_owned();
        let command =
            "sleep 60 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; while :; do printf xxxxxxxxxxxxxxxx; done";
        let invocation = ToolInvocation::strict(
            "sh",
            &["-c", command, "scorchkit-output-limit", &pid_path],
            Duration::from_secs(5),
        )
        .with_output_limit(64);
        let started = Instant::now();
        let result = SystemToolExecutor.execute(invocation).await;

        assert!(matches!(
            result,
            Err(ScorchError::ToolOutputLimit { stream: "stdout", limit_bytes: 64, .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        let descendant = read_fixture_pid(&pid_file);
        assert_process_exits(descendant).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_at_exact_limit_is_preserved() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        // This contract measures the byte boundary, not timeout behavior. Leave enough time for
        // process startup on a loaded clean-build runner; dedicated tests below own timeout proof.
        let invocation =
            ToolInvocation::strict("sh", &["-c", "printf 1234"], Duration::from_secs(10))
                .with_output_limit(4);
        let output = SystemToolExecutor
            .execute(invocation)
            .await
            .unwrap_or_else(|error| panic!("exact-limit execution failed: {error}"));
        assert_eq!(output.stdout, "1234");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_cancels_the_child() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let result = run_tool("sh", &["-c", "sleep 1"], Duration::from_millis(20)).await;
        assert!(matches!(result, Err(ScorchError::Cancelled { .. })));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_terminates_descendant_processes() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("descendant.pid");
        let pid_path = pid_file.to_string_lossy().into_owned();
        let command = "sleep 60 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; wait";
        let result = run_tool(
            "sh",
            &["-c", command, "scorchkit-process-tree", &pid_path],
            Duration::from_millis(100),
        )
        .await;
        assert!(matches!(result, Err(ScorchError::Cancelled { .. })));

        let descendant = read_fixture_pid(&pid_file);
        assert_process_exits(descendant).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_parent_exit_still_terminates_background_descendants() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("background.pid");
        let pid_path = pid_file.to_string_lossy().into_owned();
        let command = "sleep 60 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; exit 0";
        let result = run_tool(
            "sh",
            &["-c", command, "scorchkit-process-tree", &pid_path],
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_ok(), "direct parent should exit successfully: {result:?}");

        let descendant = read_fixture_pid(&pid_file);
        assert_process_exits(descendant).await;
    }

    #[cfg(unix)]
    fn read_fixture_pid(path: &Path) -> rustix::process::Pid {
        let raw = std::fs::read_to_string(path)
            .expect("read descendant PID")
            .parse::<i32>()
            .expect("parse descendant PID");
        rustix::process::Pid::from_raw(raw).expect("positive descendant PID")
    }

    #[cfg(unix)]
    async fn assert_process_exits(pid: rustix::process::Pid) {
        for _ in 0..100 {
            if matches!(rustix::process::test_kill_process(pid), Err(rustix::io::Errno::SRCH)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("descendant process {pid:?} survived owned process-tree cleanup");
    }

    #[tokio::test]
    async fn missing_tool_is_rejected_before_spawn() {
        let result =
            run_tool("scorchkit-tool-that-does-not-exist-a571bd29", &[], Duration::from_secs(1))
                .await;
        assert!(matches!(result, Err(ScorchError::ToolNotFound { .. })));
    }

    #[test]
    fn availability_uses_the_execution_resolver() {
        let current_executable = std::env::current_exe()
            .unwrap_or_else(|error| panic!("failed to resolve current test executable: {error}"));
        assert!(is_tool_available(&current_executable.to_string_lossy()));
        assert!(!is_tool_available("scorchkit-tool-that-does-not-exist-a571bd29"));
    }

    #[test]
    fn missing_tool_selection_requires_a_declared_unavailable_executable() {
        let missing = "scorchkit-tool-that-does-not-exist-a571bd29";
        let current_executable = std::env::current_exe()
            .unwrap_or_else(|error| panic!("failed to resolve current test executable: {error}"));
        let current_executable = current_executable.to_string_lossy();

        assert_eq!(missing_required_tool(true, Some(missing)), Some(missing));
        assert_eq!(missing_required_tool(false, Some(missing)), None);
        assert_eq!(missing_required_tool(true, None), None);
        assert_eq!(missing_required_tool(true, Some(&current_executable)), None);
    }

    #[test]
    fn explicit_executable_resolves_to_its_canonical_identity() {
        let current_executable = std::env::current_exe()
            .unwrap_or_else(|error| panic!("failed to resolve current test executable: {error}"));
        let expected = current_executable
            .canonicalize()
            .unwrap_or_else(|error| panic!("failed to canonicalize current executable: {error}"));
        let resolved = resolve_tool_path(&current_executable.to_string_lossy())
            .unwrap_or_else(|error| panic!("failed to resolve current executable: {error}"));
        assert_eq!(resolved, expected);
    }

    #[test]
    fn explicit_non_executable_paths_are_rejected() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("failed to create temporary directory: {error}"));
        let file = directory.path().join("not-executable");
        std::fs::write(&file, b"fixture")
            .unwrap_or_else(|error| panic!("failed to write fixture: {error}"));

        assert!(matches!(
            resolve_tool_path(&file.to_string_lossy()),
            Err(ScorchError::ToolNotFound { .. })
        ));
        assert!(matches!(
            resolve_tool_path(&directory.path().to_string_lossy()),
            Err(ScorchError::ToolNotFound { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_relative_executable_path_is_accepted() {
        use std::os::unix::fs::PermissionsExt;

        let working_directory = std::env::current_dir()
            .unwrap_or_else(|error| panic!("failed to resolve working directory: {error}"));
        let directory = tempfile::Builder::new()
            .prefix("subprocess-relative-")
            .tempdir_in(&working_directory)
            .unwrap_or_else(|error| panic!("failed to create relative fixture: {error}"));
        let executable = directory.path().join("fixture-tool");
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n")
            .unwrap_or_else(|error| panic!("failed to write executable fixture: {error}"));
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("failed to set executable fixture mode: {error}"));
        let relative = executable
            .strip_prefix(&working_directory)
            .unwrap_or_else(|error| panic!("failed to construct relative path: {error}"));

        let resolved = resolve_tool_path(&relative.to_string_lossy())
            .unwrap_or_else(|error| panic!("failed to resolve relative executable: {error}"));
        let expected = executable
            .canonicalize()
            .unwrap_or_else(|error| panic!("failed to canonicalize fixture: {error}"));
        assert_eq!(resolved, expected);
    }

    #[test]
    fn executable_candidates_apply_platform_extensions_exactly() {
        let directory = Path::new("tools");
        assert_eq!(
            executable_candidates_with_extensions(directory, "scanner", None),
            [directory.join("scanner")]
        );

        let extensions = std::ffi::OsStr::new(".COM;.EXE;;");
        assert_eq!(
            executable_candidates_with_extensions(directory, "scanner", Some(extensions)),
            [directory.join("scanner.COM"), directory.join("scanner.EXE")]
        );
        assert_eq!(
            executable_candidates_with_extensions(directory, "scanner.exe", Some(extensions)),
            [directory.join("scanner.exe")]
        );
    }

    #[test]
    fn executable_metadata_requires_a_file_and_unix_execute_bits() {
        assert!(executable_metadata_is_valid(true, None));
        assert!(!executable_metadata_is_valid(false, None));
        assert!(executable_metadata_is_valid(true, Some(0o700)));
        assert!(!executable_metadata_is_valid(true, Some(0o600)));
        assert!(!executable_metadata_is_valid(false, Some(0o700)));
    }
}
