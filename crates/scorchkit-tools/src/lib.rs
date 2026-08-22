use std::collections::BTreeMap;
use std::fmt::{self, Debug};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::process::Child;
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

use scorchkit_core::error::{Result, ScorchError};

#[cfg(windows)]
mod windows_owned_process;
#[cfg(all(test, windows))]
use windows_owned_process::spawn_windows_owned_process_rejected;
#[cfg(windows)]
#[doc(hidden)]
pub use windows_owned_process::{spawn_owned_process, stop_owned_process, OwnedProcess};

/// Default maximum captured bytes for each child-process output stream.
pub const DEFAULT_TOOL_OUTPUT_LIMIT_BYTES: usize = 8_388_608;

/// Sentinel used when process infrastructure fails before yielding an exit status.
const TOOL_INFRASTRUCTURE_FAILURE_STATUS: i32 = -1;

/// Whether a tool invocation requires a successful process exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitPolicy {
    /// A non-zero exit status is an infrastructure failure.
    RequireSuccess,
    /// Return captured output for any exit status.
    AllowNonZero,
    /// Return captured output only for one of the explicitly accepted exit codes.
    ///
    /// Codes are sorted and deduplicated by [`ToolInvocation::accepting`]. An empty set accepts no
    /// exit status and therefore fails closed.
    AcceptedCodes(Vec<i32>),
}

/// Whether a child process inherits the parent environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentPolicy {
    /// Preserve the current process environment and apply declared overrides.
    Inherit,
    /// Clear the environment before applying declared values.
    Clear,
}

/// Complete, owned description of one external tool execution.
#[derive(Clone, PartialEq, Eq)]
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
    /// Parent-environment handling policy.
    pub environment_policy: EnvironmentPolicy,
    /// Explicit environment values applied after the inheritance policy.
    pub environment: BTreeMap<String, String>,
    /// Optional working directory for the child process.
    pub working_directory: Option<PathBuf>,
    /// Optional recursive budget for files owned by this invocation.
    pub artifact_budget: Option<ArtifactBudget>,
}

/// Recursive file-count and byte budget for one already-created owned directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactBudget {
    pub root: PathBuf,
    pub max_bytes: u64,
    pub max_files: u64,
}

impl ArtifactBudget {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, max_bytes: u64, max_files: u64) -> Self {
        Self { root: root.into(), max_bytes, max_files }
    }
}

impl Debug for ToolInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolInvocation")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("timeout", &self.timeout)
            .field("exit_policy", &self.exit_policy)
            .field("output_limit_bytes", &self.output_limit_bytes)
            .field("stdin_bytes", &self.stdin.as_ref().map(Vec::len))
            .field("environment_policy", &self.environment_policy)
            .field("environment_names", &self.environment.keys().collect::<Vec<_>>())
            .field("working_directory", &self.working_directory)
            .field("artifact_budget", &self.artifact_budget)
            .finish()
    }
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

    /// Build an invocation that accepts exactly the supplied process exit codes.
    #[must_use]
    pub fn accepting(
        program: &str,
        args: &[&str],
        timeout: Duration,
        accepted_codes: &[i32],
    ) -> Self {
        let mut accepted_codes = accepted_codes.to_vec();
        accepted_codes.sort_unstable();
        accepted_codes.dedup();
        Self::new(program, args, timeout, ExitPolicy::AcceptedCodes(accepted_codes))
    }

    /// Build a strict invocation from already-owned arguments.
    #[must_use]
    pub fn strict_owned(program: impl Into<String>, args: Vec<String>, timeout: Duration) -> Self {
        Self::new_owned(program.into(), args, timeout, ExitPolicy::RequireSuccess)
    }

    /// Build an exact-exit invocation from already-owned arguments.
    #[must_use]
    pub fn accepting_owned(
        program: impl Into<String>,
        args: Vec<String>,
        timeout: Duration,
        accepted_codes: &[i32],
    ) -> Self {
        let mut accepted_codes = accepted_codes.to_vec();
        accepted_codes.sort_unstable();
        accepted_codes.dedup();
        Self::new_owned(program.into(), args, timeout, ExitPolicy::AcceptedCodes(accepted_codes))
    }

    fn new(program: &str, args: &[&str], timeout: Duration, exit_policy: ExitPolicy) -> Self {
        Self::new_owned(
            program.to_string(),
            args.iter().map(|argument| (*argument).to_string()).collect(),
            timeout,
            exit_policy,
        )
    }

    const fn new_owned(
        program: String,
        args: Vec<String>,
        timeout: Duration,
        exit_policy: ExitPolicy,
    ) -> Self {
        Self {
            program,
            args,
            timeout,
            exit_policy,
            output_limit_bytes: DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
            stdin: None,
            environment_policy: EnvironmentPolicy::Inherit,
            environment: BTreeMap::new(),
            working_directory: None,
            artifact_budget: None,
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

    /// Clear the parent environment before applying declared values.
    #[must_use]
    pub const fn with_clean_environment(mut self) -> Self {
        self.environment_policy = EnvironmentPolicy::Clear;
        self
    }

    /// Add or replace one explicit child-process environment value.
    #[must_use]
    pub fn with_environment(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(name.into(), value.into());
        self
    }

    /// Set the working directory used by the child process.
    #[must_use]
    pub fn with_working_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(path.into());
        self
    }

    /// Monitor an already-created owned directory and stop the process on budget exhaustion.
    #[must_use]
    pub fn with_artifact_budget(mut self, budget: ArtifactBudget) -> Self {
        self.artifact_budget = Some(budget);
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
pub struct SystemToolExecutor;

/// RAII ownership for the Unix process group created for one external tool.
///
/// On Unix, dropping this guard sends `SIGKILL` to the whole group, including
/// descendants that outlive or detach from the direct child. The direct child
/// still uses Tokio's `kill_on_drop` as a platform fallback.
#[derive(Debug)]
#[doc(hidden)]
#[cfg(unix)]
pub struct OwnedProcessGroup {
    process_group: Option<rustix::process::Pid>,
}

#[cfg(unix)]
impl OwnedProcessGroup {
    #[doc(hidden)]
    pub fn for_child(child: &Child) -> Self {
        let process_group = child
            .id()
            .and_then(|raw| i32::try_from(raw).ok())
            .and_then(rustix::process::Pid::from_raw);
        Self { process_group }
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        let Some(process_group) = self.process_group.take() else {
            return Ok(());
        };
        match rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(error) => Err(std::io::Error::from_raw_os_error(error.raw_os_error())),
        }
    }
}

#[cfg(unix)]
impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

/// Put a child in a fresh owned process group before it is spawned.
#[doc(hidden)]
#[cfg(unix)]
pub fn configure_owned_process_group(command: &mut tokio::process::Command) {
    command.process_group(0);
}

/// A spawned Unix process paired with the owner for its complete descendant tree.
#[derive(Debug)]
#[doc(hidden)]
#[cfg(unix)]
pub struct OwnedProcess {
    // Rust drops fields in declaration order. Keep the process-group owner before the direct child
    // so cancellation terminates descendants before Tokio applies its direct-child fallback.
    process_group: OwnedProcessGroup,
    child: Child,
}

#[cfg(unix)]
impl OwnedProcess {
    /// Take the child's piped standard output, if configured.
    #[doc(hidden)]
    pub const fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the child's piped standard error, if configured.
    #[doc(hidden)]
    pub const fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    /// Take the child's piped standard input, if configured.
    #[doc(hidden)]
    pub const fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    /// Return the direct child's process identifier while it is available.
    #[must_use]
    #[doc(hidden)]
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    /// Observe only the direct child without waiting for descendants.
    #[doc(hidden)]
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Wait for only the direct child while retaining ownership of its descendants.
    #[doc(hidden)]
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }
}

/// Spawn a child only after configuring its Unix descendant-process owner.
#[doc(hidden)]
#[cfg(unix)]
pub fn spawn_owned_process(command: Command) -> std::io::Result<OwnedProcess> {
    let mut command = command;
    configure_owned_process_group(&mut command);
    let child = command.spawn()?;
    let process_group = OwnedProcessGroup::for_child(&child);
    Ok(OwnedProcess { process_group, child })
}

/// Terminate and reap an owned Unix child process tree.
#[doc(hidden)]
#[cfg(unix)]
pub async fn stop_owned_process(child: &mut OwnedProcess) -> std::io::Result<()> {
    let child_already_exited = child.try_wait()?.is_some();
    let group_result = child.process_group.terminate();
    match group_stop_disposition(child_already_exited, &group_result) {
        GroupStopDisposition::WaitForChild => {}
        GroupStopDisposition::ObserveExitRace => {
            // The child can exit after `try_wait` but before `killpg`. macOS may report EPERM
            // while that exited process is still being reaped. Bound the observation window so
            // a genuine permission failure on a live process cannot hang session shutdown.
            return match tokio::time::timeout(Duration::from_secs(1), child.wait()).await {
                Ok(wait_result) => {
                    reconcile_process_stop(true, group_result, wait_result.map(|_| ()))
                }
                Err(_) => group_result,
            };
        }
        GroupStopDisposition::ReturnError => return group_result,
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

#[cfg(unix)]
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

#[cfg(all(test, unix))]
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
#[doc(hidden)]
pub fn is_tool_available(tool: &str) -> bool {
    resolve_tool_path(tool).is_ok()
}

/// Return the declared executable only when a tool-backed module cannot run.
#[must_use]
#[doc(hidden)]
pub fn missing_required_tool(
    requires_external_tool: bool,
    required_tool: Option<&str>,
) -> Option<&str> {
    if !requires_external_tool {
        return None;
    }
    required_tool.filter(|tool| !is_tool_available(tool))
}

async fn execute_system(invocation: ToolInvocation) -> Result<ToolOutput> {
    execute_system_with_spawner(invocation, spawn_owned_process).await
}

async fn execute_system_with_spawner<Spawn>(
    invocation: ToolInvocation,
    spawn: Spawn,
) -> Result<ToolOutput>
where
    Spawn: FnOnce(Command) -> std::io::Result<OwnedProcess>,
{
    let resolved_program = resolve_tool_path(&invocation.program)?;
    if let Some(budget) = &invocation.artifact_budget {
        validate_artifact_root(budget)?;
        enforce_artifact_budget(&invocation.program, budget)?;
    }
    let started = Instant::now();
    let mut command = tokio::process::Command::new(&resolved_program);
    if invocation.environment_policy == EnvironmentPolicy::Clear {
        command.env_clear();
    }
    command.envs(&invocation.environment);
    if let Some(working_directory) = &invocation.working_directory {
        command.current_dir(working_directory);
    }
    command
        .args(&invocation.args)
        .stdin(if invocation.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = spawn(command).map_err(|error| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: error.to_string(),
    })?;
    let stdout = child.take_stdout().ok_or_else(|| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: "failed to capture stdout".to_string(),
    })?;
    let stderr = child.take_stderr().ok_or_else(|| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: "failed to capture stderr".to_string(),
    })?;
    let stdin = child.take_stdin();
    let stdin_bytes = invocation.stdin.clone();

    let execution =
        coordinate_child_io(&mut child, stdout, stderr, stdin, stdin_bytes, &invocation);

    let (status, stdout, stderr, stdin) = match tokio::time::timeout(invocation.timeout, execution)
        .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            let _ = stop_owned_process(&mut child).await;
            return Err(error);
        }
        Err(_) => {
            let _ = stop_owned_process(&mut child).await;
            return Err(ScorchError::Cancelled {
                reason: format!("{} timed out after {:?}", invocation.program, invocation.timeout),
            });
        }
    };
    stop_owned_process(&mut child).await.map_err(|error| ScorchError::ToolFailed {
        tool: invocation.program.clone(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: format!("failed to clean up process tree: {error}"),
    })?;
    if let Some(budget) = &invocation.artifact_budget {
        enforce_artifact_budget(&invocation.program, budget)?;
    }

    let (status, stdout, stderr) =
        collect_child_output(&invocation.program, (status, stdout, stderr, stdin))?;

    let exit_code = status.code().unwrap_or(TOOL_INFRASTRUCTURE_FAILURE_STATUS);
    let stderr = String::from_utf8_lossy(&stderr.bytes).into_owned();
    if !invocation.exit_policy.accepts(exit_code, status.success()) {
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

fn collect_child_output(
    tool: &str,
    outcome: ChildIoOutcome,
) -> Result<(std::process::ExitStatus, BoundedRead, BoundedRead)> {
    let (status, stdout, stderr, stdin) = outcome;
    let tool_failure = |error: std::io::Error| ScorchError::ToolFailed {
        tool: tool.to_string(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: error.to_string(),
    };
    let status = status.map_err(&tool_failure)?;
    let stdout = stdout.map_err(&tool_failure)?;
    let stderr = stderr.map_err(tool_failure)?;
    stdin.map_err(|error| ScorchError::ToolFailed {
        tool: tool.to_string(),
        status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
        stderr: format!("failed to write tool stdin: {error}"),
    })?;
    Ok((status, stdout, stderr))
}

impl ExitPolicy {
    fn accepts(&self, exit_code: i32, succeeded: bool) -> bool {
        match self {
            Self::RequireSuccess => succeeded,
            Self::AllowNonZero => true,
            Self::AcceptedCodes(codes) => codes.binary_search(&exit_code).is_ok(),
        }
    }
}

type ChildIoOutcome = (
    std::io::Result<std::process::ExitStatus>,
    std::io::Result<BoundedRead>,
    std::io::Result<BoundedRead>,
    std::io::Result<()>,
);

async fn coordinate_child_io(
    child: &mut OwnedProcess,
    stdout: ChildStdout,
    stderr: ChildStderr,
    stdin: Option<ChildStdin>,
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
    let mut artifact_tick = tokio::time::interval(Duration::from_millis(250));
    artifact_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
            _ = artifact_tick.tick(), if invocation.artifact_budget.is_some() => {
                if let Some(budget) = &invocation.artifact_budget {
                    enforce_artifact_budget(&invocation.program, budget)?;
                }
            }
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

fn validate_artifact_root(budget: &ArtifactBudget) -> Result<()> {
    let metadata = std::fs::symlink_metadata(&budget.root).map_err(|error| {
        ScorchError::Config(format!(
            "tool artifact root '{}' is unavailable: {error}",
            budget.root.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ScorchError::Config(format!(
            "tool artifact root '{}' must be a real directory",
            budget.root.display()
        )));
    }
    if budget.max_bytes == 0 || budget.max_files == 0 {
        return Err(ScorchError::Config(
            "tool artifact byte and file limits must be nonzero".to_string(),
        ));
    }
    Ok(())
}

fn enforce_artifact_budget(tool: &str, budget: &ArtifactBudget) -> Result<()> {
    enforce_artifact_budget_with(
        tool,
        budget,
        |directory| std::fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>(),
        |path| std::fs::symlink_metadata(path),
    )
}

fn enforce_artifact_budget_with<ReadDirectory, ReadMetadata>(
    tool: &str,
    budget: &ArtifactBudget,
    mut read_directory: ReadDirectory,
    mut read_metadata: ReadMetadata,
) -> Result<()>
where
    ReadDirectory: FnMut(&Path) -> std::io::Result<Vec<std::fs::DirEntry>>,
    ReadMetadata: FnMut(&Path) -> std::io::Result<std::fs::Metadata>,
{
    let mut pending = vec![budget.root.clone()];
    let mut bytes = 0_u64;
    let mut files = 0_u64;
    while let Some(directory) = pending.pop() {
        let entries = match read_directory(&directory) {
            Ok(entries) => entries,
            Err(error) if vanished_artifact_directory(&error, &directory, &budget.root) => {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let metadata = match read_metadata(&entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if vanished_artifact_entry(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            files = files.saturating_add(1);
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
            }
            if bytes > budget.max_bytes || files > budget.max_files {
                return Err(ScorchError::ToolArtifactLimit {
                    tool: tool.to_string(),
                    limit_bytes: budget.max_bytes,
                    limit_files: budget.max_files,
                });
            }
        }
    }
    Ok(())
}

fn vanished_artifact_directory(error: &std::io::Error, directory: &Path, root: &Path) -> bool {
    vanished_artifact_entry(error) && directory != root
}

fn vanished_artifact_entry(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
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
#[doc(hidden)]
pub fn resolve_tool_path(tool: &str) -> Result<PathBuf> {
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

    #[cfg(windows)]
    const WINDOWS_FIXTURE_TEST: &str = "tests::windows_process_fixture";
    #[cfg(windows)]
    const WINDOWS_FIXTURE_MODE: &str = "SCORCHKIT_WINDOWS_PROCESS_FIXTURE_MODE";
    #[cfg(windows)]
    const WINDOWS_FIXTURE_PID: &str = "SCORCHKIT_WINDOWS_PROCESS_FIXTURE_PID";
    #[cfg(windows)]
    const WINDOWS_FIXTURE_ARTIFACT: &str = "SCORCHKIT_WINDOWS_PROCESS_FIXTURE_ARTIFACT";
    #[cfg(windows)]
    const WINDOWS_FIXTURE_MARKER: &str = "SCORCHKIT_WINDOWS_PROCESS_FIXTURE_MARKER";

    #[cfg(windows)]
    #[test]
    fn windows_process_fixture() {
        let Ok(mode) = std::env::var(WINDOWS_FIXTURE_MODE) else {
            return;
        };
        if mode == "descendant" {
            std::thread::sleep(Duration::from_mins(1));
            return;
        }

        if mode == "marker" {
            let marker = std::env::var_os(WINDOWS_FIXTURE_MARKER)
                .map(PathBuf::from)
                .expect("marker fixture path");
            std::fs::write(marker, b"scanner work started").expect("write marker fixture");
            std::thread::sleep(Duration::from_mins(1));
            return;
        }

        let pid_path = std::env::var_os(WINDOWS_FIXTURE_PID)
            .map(PathBuf::from)
            .expect("descendant PID fixture path");
        let executable = std::env::current_exe().expect("current fixture executable");
        let mut descendant = std::process::Command::new(executable)
            .args(["--exact", WINDOWS_FIXTURE_TEST, "--nocapture"])
            .env(WINDOWS_FIXTURE_MODE, "descendant")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn descendant fixture");
        let descendant_pid = descendant.id();
        std::thread::spawn(move || {
            let _ = descendant.wait();
        });
        std::fs::write(&pid_path, descendant_pid.to_string()).expect("write descendant PID");

        match mode.as_str() {
            "success" => {}
            "failure" => panic!("forced fixture failure after descendant spawn"),
            "wait" => std::thread::sleep(Duration::from_mins(1)),
            "output" => {
                use std::io::Write as _;

                let mut stdout = std::io::stdout().lock();
                loop {
                    stdout.write_all(b"xxxxxxxxxxxxxxxx").expect("write output fixture");
                    stdout.flush().expect("flush output fixture");
                }
            }
            "artifact" => {
                use std::io::Write as _;

                let artifact = std::env::var_os(WINDOWS_FIXTURE_ARTIFACT)
                    .map(PathBuf::from)
                    .expect("artifact fixture path");
                loop {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&artifact)
                        .and_then(|mut file| file.write_all(b"xxxxxxxxxxxxxxxx"))
                        .expect("grow artifact fixture");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            other => panic!("unknown Windows process fixture mode: {other}"),
        }
    }

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
        assert_eq!(invocation.environment_policy, EnvironmentPolicy::Inherit);
        assert!(invocation.environment.is_empty());
        assert!(invocation.working_directory.is_none());
    }

    #[test]
    fn invocation_debug_omits_environment_values_and_stdin_bytes() {
        let invocation = ToolInvocation::strict("tool", &[], Duration::from_secs(3))
            .with_clean_environment()
            .with_environment("SCORCHKIT_SECRET", "arbitrary-fixture-secret")
            .with_stdin(b"private-stdin".to_vec());
        let rendered = format!("{invocation:?}");

        assert!(rendered.contains("SCORCHKIT_SECRET"));
        assert!(rendered.contains("stdin_bytes: Some(13)"));
        assert!(!rendered.contains("arbitrary-fixture-secret"));
        assert!(!rendered.contains("private-stdin"));
    }

    #[test]
    fn exact_exit_policy_is_sorted_deduplicated_and_fail_closed_when_empty() {
        let invocation =
            ToolInvocation::accepting("tool", &["--flag"], Duration::from_secs(3), &[1, 0, 1]);
        assert_eq!(invocation.exit_policy, ExitPolicy::AcceptedCodes(vec![0, 1]));
        assert!(invocation.exit_policy.accepts(0, true));
        assert!(invocation.exit_policy.accepts(1, false));
        assert!(!invocation.exit_policy.accepts(2, false));

        let none = ToolInvocation::accepting("tool", &[], Duration::from_secs(3), &[]);
        assert!(!none.exit_policy.accepts(0, true));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn invocation_applies_declared_environment_and_working_directory() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let invocation = ToolInvocation::strict(
            "sh",
            &["-c", "printf '%s|%s' \"$SCORCHKIT_INVOCATION_TEST\" \"$PWD\""],
            Duration::from_secs(2),
        )
        .with_clean_environment()
        .with_environment("SCORCHKIT_INVOCATION_TEST", "present")
        .with_working_directory(directory.path());

        let output = SystemToolExecutor
            .execute(invocation)
            .await
            .unwrap_or_else(|error| panic!("configured invocation failed: {error}"));
        let canonical_directory = directory.path().canonicalize().expect("canonical directory");
        assert_eq!(output.stdout, format!("present|{}", canonical_directory.display()));
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
    async fn artifact_limit_terminates_the_process_tree_without_waiting_for_timeout() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("artifact-limit-descendant.pid");
        let output_file = directory.path().join("growing-artifact");
        let command = "sleep 60 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; while :; do printf x >> \"$2\"; sleep 0.01; done";
        let invocation = ToolInvocation::strict(
            "sh",
            &[
                "-c",
                command,
                "scorchkit-artifact-limit",
                &pid_file.to_string_lossy(),
                &output_file.to_string_lossy(),
            ],
            Duration::from_secs(5),
        )
        .with_artifact_budget(ArtifactBudget::new(directory.path(), 16, 8));
        let started = Instant::now();
        let result = SystemToolExecutor.execute(invocation).await;

        assert!(matches!(result, Err(ScorchError::ToolArtifactLimit { limit_bytes: 16, .. })));
        assert!(started.elapsed() < Duration::from_secs(2));
        let descendant = read_fixture_pid(&pid_file);
        assert_process_exits(descendant).await;
    }

    #[cfg(unix)]
    #[test]
    fn artifact_budget_counts_non_regular_entries() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let _first = std::os::unix::net::UnixListener::bind(directory.path().join("first.sock"))
            .expect("first socket");
        let _second = std::os::unix::net::UnixListener::bind(directory.path().join("second.sock"))
            .expect("second socket");
        let budget = ArtifactBudget::new(directory.path(), u64::MAX, 1);

        assert!(matches!(
            enforce_artifact_budget("fixture", &budget),
            Err(ScorchError::ToolArtifactLimit { limit_files: 1, .. })
        ));
    }

    #[test]
    fn artifact_root_validation_rejects_each_invalid_dimension() {
        let missing = tempfile::tempdir().expect("temporary directory");
        let missing_path = missing.path().join("missing");
        let missing_budget = ArtifactBudget::new(&missing_path, 1, 1);
        assert!(validate_artifact_root(&missing_budget).is_err());

        let file_directory = tempfile::tempdir().expect("temporary directory");
        let file = file_directory.path().join("artifact-root-file");
        std::fs::write(&file, b"fixture").expect("write artifact root file");
        assert!(validate_artifact_root(&ArtifactBudget::new(&file, 1, 1)).is_err());

        let root = tempfile::tempdir().expect("temporary directory");
        assert!(validate_artifact_root(&ArtifactBudget::new(root.path(), 0, 1)).is_err());
        assert!(validate_artifact_root(&ArtifactBudget::new(root.path(), 1, 0)).is_err());
        assert!(validate_artifact_root(&ArtifactBudget::new(root.path(), 1, 1)).is_ok());
    }

    #[test]
    fn artifact_budget_uses_strict_byte_and_file_boundaries() {
        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::write(directory.path().join("fixture"), b"1234").expect("write fixture");

        assert!(enforce_artifact_budget(
            "fixture-tool",
            &ArtifactBudget::new(directory.path(), 4, 1)
        )
        .is_ok());
        assert!(enforce_artifact_budget(
            "fixture-tool",
            &ArtifactBudget::new(directory.path(), 5, 2)
        )
        .is_ok());

        assert!(matches!(
            enforce_artifact_budget(
                "fixture-tool",
                &ArtifactBudget::new(directory.path(), 3, 1)
            ),
            Err(ScorchError::ToolArtifactLimit {
                ref tool,
                limit_bytes: 3,
                limit_files: 1
            }) if tool == "fixture-tool"
        ));
        assert!(matches!(
            enforce_artifact_budget("fixture-tool", &ArtifactBudget::new(directory.path(), 4, 0)),
            Err(ScorchError::ToolArtifactLimit { limit_bytes: 4, limit_files: 0, .. })
        ));
    }

    #[test]
    fn missing_artifact_root_is_not_treated_as_a_vanished_child() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("missing");
        assert!(enforce_artifact_budget(
            "fixture-tool",
            &ArtifactBudget::new(&missing, u64::MAX, u64::MAX)
        )
        .is_err());
    }

    #[test]
    fn artifact_disappearance_predicates_distinguish_roots_children_and_other_errors() {
        let root = Path::new("artifact-root");
        let child = root.join("child");
        let not_found = std::io::Error::from(std::io::ErrorKind::NotFound);
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

        assert!(vanished_artifact_directory(&not_found, &child, root));
        assert!(!vanished_artifact_directory(&not_found, root, root));
        assert!(!vanished_artifact_directory(&denied, &child, root));
        assert!(vanished_artifact_entry(&not_found));
        assert!(!vanished_artifact_entry(&denied));
    }

    #[test]
    fn artifact_budget_tolerates_injected_vanishing_children_and_entries() {
        let directory_case = tempfile::tempdir().expect("temporary directory");
        let child = directory_case.path().join("vanishing-child");
        std::fs::create_dir(&child).expect("create child");
        let child_probe = child;
        let child_result = enforce_artifact_budget_with(
            "fixture-tool",
            &ArtifactBudget::new(directory_case.path(), u64::MAX, u64::MAX),
            |directory| {
                if directory == child_probe.as_path() {
                    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
                } else {
                    std::fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()
                }
            },
            |path| std::fs::symlink_metadata(path),
        );
        assert!(child_result.is_ok());

        let entry_case = tempfile::tempdir().expect("temporary directory");
        let entry = entry_case.path().join("vanishing-entry");
        std::fs::write(&entry, b"fixture").expect("write entry");
        let entry_probe = entry;
        let entry_result = enforce_artifact_budget_with(
            "fixture-tool",
            &ArtifactBudget::new(entry_case.path(), u64::MAX, u64::MAX),
            |directory| std::fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>(),
            |path| {
                if path == entry_probe.as_path() {
                    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
                } else {
                    std::fs::symlink_metadata(path)
                }
            },
        );
        assert!(entry_result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn artifact_budget_propagates_directory_and_metadata_permission_errors() {
        use std::os::unix::fs::PermissionsExt;

        let child_case = tempfile::tempdir().expect("temporary directory");
        let child = child_case.path().join("locked-child");
        std::fs::create_dir(&child).expect("create locked child");
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o000))
            .expect("lock child");
        let child_result = enforce_artifact_budget(
            "fixture-tool",
            &ArtifactBudget::new(child_case.path(), u64::MAX, u64::MAX),
        );
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700))
            .expect("unlock child");
        assert!(child_result.is_err());

        let metadata_case = tempfile::tempdir().expect("temporary directory");
        std::fs::write(metadata_case.path().join("entry"), b"fixture").expect("write entry");
        std::fs::set_permissions(metadata_case.path(), std::fs::Permissions::from_mode(0o400))
            .expect("remove search permission");
        let metadata_result = enforce_artifact_budget(
            "fixture-tool",
            &ArtifactBudget::new(metadata_case.path(), u64::MAX, u64::MAX),
        );
        std::fs::set_permissions(metadata_case.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore search permission");
        assert!(metadata_result.is_err());
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
    #[tokio::test]
    async fn owned_process_accessors_preserve_pipes_and_direct_child_identity() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let mut command = Command::new("sh");
        command
            .args(["-c", "IFS= read -r input; printf 'out:%s' \"$input\"; printf err >&2"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = spawn_owned_process(command).expect("spawn owned pipe fixture");
        let direct_child = child.id().expect("direct child PID");
        assert!(direct_child > 1, "direct child PID must be a real process identifier");
        let mut stdin = child.take_stdin().expect("piped stdin");
        let mut stdout = child.take_stdout().expect("piped stdout");
        let mut stderr = child.take_stderr().expect("piped stderr");

        stdin.write_all(b"fixture\n").await.expect("write fixture stdin");
        stdin.shutdown().await.expect("close fixture stdin");
        let mut stdout_bytes = Vec::new();
        stdout.read_to_end(&mut stdout_bytes).await.expect("read fixture stdout");
        let mut stderr_bytes = Vec::new();
        stderr.read_to_end(&mut stderr_bytes).await.expect("read fixture stderr");
        let status = child.wait().await.expect("wait for pipe fixture");

        assert!(status.success());
        assert_eq!(stdout_bytes, b"out:fixture");
        assert_eq!(stderr_bytes, b"err");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_owned_process_terminates_descendants_before_direct_child_fallback() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("owned-drop-descendant.pid");
        let pid_path = pid_file.to_string_lossy().into_owned();
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "sleep 60 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; wait",
                "scorchkit-owned-drop",
                pid_path.as_str(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        let child = spawn_owned_process(command).expect("spawn owned drop fixture");
        let mut descendant = None;
        for _ in 0..100 {
            if let Ok(raw) = std::fs::read_to_string(&pid_file) {
                descendant =
                    raw.trim().parse::<i32>().ok().and_then(rustix::process::Pid::from_raw);
                if descendant.is_some() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let descendant = descendant.expect("descendant PID fixture");

        drop(child);
        assert_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_executor_preserves_stdin_output_and_accepted_exit_contract() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let command = concat!(
            "set /p input=& ",
            "<nul set /p =out:!input!& ",
            "<nul set /p =err 1>&2& ",
            "exit /b 7"
        );
        let invocation = ToolInvocation::accepting(
            "cmd.exe",
            &["/D", "/V:ON", "/S", "/C", command],
            Duration::from_secs(5),
            &[7],
        )
        .with_stdin(b"input\r\n".to_vec());

        let output = SystemToolExecutor
            .execute(invocation)
            .await
            .unwrap_or_else(|error| panic!("Windows I/O fixture failed: {error}"));
        assert_eq!(output.exit_code, 7);
        assert_eq!(output.stdout, "out:input");
        assert_eq!(output.stderr, "err");
        assert!(output.resolved_program.is_absolute());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_successful_parent_exit_terminates_descendants() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let (invocation, pid_file) =
            windows_fixture_invocation("success", directory.path(), Duration::from_secs(5));

        let result = SystemToolExecutor.execute(invocation).await;
        assert!(result.is_ok(), "direct parent should exit successfully: {result:?}");
        let descendant = wait_for_windows_fixture_pid(&pid_file).await;
        assert_windows_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_nonzero_parent_exit_terminates_descendants() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let (invocation, pid_file) =
            windows_fixture_invocation("failure", directory.path(), Duration::from_secs(5));

        let result = SystemToolExecutor.execute(invocation).await;
        assert!(matches!(
            result,
            Err(ScorchError::ToolFailed { status, .. })
                if status != TOOL_INFRASTRUCTURE_FAILURE_STATUS
        ));
        let descendant = wait_for_windows_fixture_pid(&pid_file).await;
        assert_windows_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_timeout_terminates_descendants() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let (invocation, pid_file) =
            windows_fixture_invocation("wait", directory.path(), Duration::from_secs(5));

        let executor = SystemToolExecutor;
        let mut execution = Box::pin(executor.execute(invocation));
        let mut descendant = None;
        for _ in 0..500 {
            tokio::select! {
                result = &mut execution => {
                    panic!("Windows timeout fixture completed before publishing its descendant: {result:?}");
                }
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            if let Some(pid) = read_windows_fixture_pid(&pid_file) {
                descendant = Some(pid);
                break;
            }
        }
        let descendant = descendant.unwrap_or_else(|| {
            panic!("descendant PID fixture was not created at {}", pid_file.display())
        });

        let result = execution.await;
        assert!(matches!(result, Err(ScorchError::Cancelled { .. })));
        assert_windows_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_output_limit_terminates_descendants() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let (invocation, pid_file) =
            windows_fixture_invocation("output", directory.path(), Duration::from_secs(5));

        // Leave room for libtest's own preamble so the fixture publishes its descendant before
        // its deliberate infinite output crosses the executor boundary.
        let result = SystemToolExecutor.execute(invocation.with_output_limit(4_096)).await;
        assert!(matches!(
            result,
            Err(ScorchError::ToolOutputLimit { stream: "stdout", limit_bytes: 4_096, .. })
        ));
        let descendant = wait_for_windows_fixture_pid(&pid_file).await;
        assert_windows_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_artifact_limit_terminates_descendants() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let artifact = directory.path().join("growing-artifact");
        let (invocation, pid_file) =
            windows_fixture_invocation("artifact", directory.path(), Duration::from_secs(5));
        let invocation = invocation
            .with_environment(WINDOWS_FIXTURE_ARTIFACT, artifact.to_string_lossy())
            .with_artifact_budget(ArtifactBudget::new(directory.path(), 32, 8));

        let result = SystemToolExecutor.execute(invocation).await;
        assert!(matches!(result, Err(ScorchError::ToolArtifactLimit { limit_bytes: 32, .. })));
        let descendant = wait_for_windows_fixture_pid(&pid_file).await;
        assert_windows_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn dropping_windows_execution_future_terminates_descendants() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let (invocation, pid_file) =
            windows_fixture_invocation("wait", directory.path(), Duration::from_mins(1));
        let executor = SystemToolExecutor;
        let mut execution = Box::pin(executor.execute(invocation));
        let mut descendant = None;
        for _ in 0..500 {
            tokio::select! {
                result = &mut execution => {
                    panic!("Windows fixture completed before cancellation: {result:?}");
                }
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            if let Some(pid) = read_windows_fixture_pid(&pid_file) {
                descendant = Some(pid);
                break;
            }
        }
        let descendant = descendant.unwrap_or_else(|| {
            panic!("descendant PID fixture was not created at {}", pid_file.display())
        });

        drop(execution);
        assert_windows_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn explicit_windows_stop_terminates_descendants() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("explicit-stop-descendant.pid");
        let mut command = windows_fixture_command("wait", &pid_file);
        command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
        let mut child = spawn_owned_process(command).expect("spawn owned Windows fixture");
        let descendant = wait_for_windows_fixture_pid(&pid_file).await;

        stop_owned_process(&mut child).await.expect("stop owned Windows fixture");
        assert_windows_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_ownership_failure_prevents_suspended_child_work() {
        let _process_guard = PROCESS_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let marker = directory.path().join("scanner-work.marker");
        let pid_file = directory.path().join("unused.pid");
        let executable = std::env::current_exe().expect("current fixture executable");
        let invocation = ToolInvocation::strict_owned(
            executable.to_string_lossy(),
            windows_fixture_arguments(),
            Duration::from_secs(5),
        )
        .with_environment(WINDOWS_FIXTURE_MODE, "marker")
        .with_environment(WINDOWS_FIXTURE_PID, pid_file.to_string_lossy())
        .with_environment(WINDOWS_FIXTURE_MARKER, marker.to_string_lossy());

        let result =
            execute_system_with_spawner(invocation, spawn_windows_owned_process_rejected).await;
        assert!(matches!(
            result,
            Err(ScorchError::ToolFailed {
                status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
                ref stderr,
                ..
            }) if stderr.contains("forced Windows process-ownership setup failure")
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!marker.exists(), "suspended child performed work before ownership succeeded");
    }

    #[cfg(windows)]
    fn windows_fixture_invocation(
        mode: &str,
        directory: &Path,
        timeout: Duration,
    ) -> (ToolInvocation, PathBuf) {
        let pid_file = directory.join(format!("{mode}-descendant.pid"));
        let executable = std::env::current_exe().expect("current fixture executable");
        let invocation = ToolInvocation::strict_owned(
            executable.to_string_lossy(),
            windows_fixture_arguments(),
            timeout,
        )
        .with_environment(WINDOWS_FIXTURE_MODE, mode)
        .with_environment(WINDOWS_FIXTURE_PID, pid_file.to_string_lossy());
        (invocation, pid_file)
    }

    #[cfg(windows)]
    fn windows_fixture_command(mode: &str, pid_file: &Path) -> Command {
        let executable = std::env::current_exe().expect("current fixture executable");
        let mut command = Command::new(executable);
        command
            .args(windows_fixture_arguments())
            .env(WINDOWS_FIXTURE_MODE, mode)
            .env(WINDOWS_FIXTURE_PID, pid_file);
        command
    }

    #[cfg(windows)]
    fn windows_fixture_arguments() -> Vec<String> {
        vec!["--exact".to_string(), WINDOWS_FIXTURE_TEST.to_string(), "--nocapture".to_string()]
    }

    #[cfg(windows)]
    async fn wait_for_windows_fixture_pid(path: &Path) -> u32 {
        for _ in 0..500 {
            if let Some(pid) = read_windows_fixture_pid(path) {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("descendant PID fixture was not created at {}", path.display());
    }

    #[cfg(windows)]
    fn read_windows_fixture_pid(path: &Path) -> Option<u32> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    #[cfg(windows)]
    async fn assert_windows_process_exits(pid: u32) {
        for _ in 0..100 {
            if !windows_process_is_running(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("Windows descendant process {pid} survived owned process-tree cleanup");
    }

    #[cfg(windows)]
    fn windows_process_is_running(pid: u32) -> bool {
        let filter = format!("PID eq {pid}");
        let output_format = concat!("/", "F", "O");
        let output = std::process::Command::new("tasklist.exe")
            .args(["/FI", &filter, output_format, "CSV", "/NH"])
            .output()
            .expect("query Windows process state");
        assert!(output.status.success(), "tasklist failed: {output:?}");
        String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
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
