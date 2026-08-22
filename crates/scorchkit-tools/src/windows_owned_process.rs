//! Native Windows Job Object ownership for spawned external tools.
//!
//! This module is compiled and exercised by the Windows CI lane. The Linux-hosted mutation runner
//! excludes this target-only file because mutations inside `cfg(windows)` code cannot affect its
//! executable test binary.

use std::time::Duration;

#[cfg(test)]
use process_wrap::tokio::CommandWrapper;
use process_wrap::tokio::{ChildWrapper, CommandWrap, JobObject, KillOnDrop};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

/// Maximum time allowed for a terminated Job Object to report that every member exited.
const PROCESS_TREE_STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// A wrapped Tokio child whose Job Object owns its complete descendant tree.
#[derive(Debug)]
pub struct OwnedProcess {
    child: Box<dyn ChildWrapper>,
}

impl OwnedProcess {
    /// Take the child's piped standard output, if configured.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout().take()
    }

    /// Take the child's piped standard error, if configured.
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr().take()
    }

    /// Take the child's piped standard input, if configured.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin().take()
    }

    /// Return the direct child's process identifier while it is available.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    /// Observe only the direct child without waiting for descendants.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error from polling the direct child.
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.inner_mut().try_wait()
    }

    /// Wait for only the direct child while retaining ownership of its descendants.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error from waiting for the direct child.
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.inner_mut().wait().await
    }

    fn terminate_tree(&mut self) -> std::io::Result<()> {
        self.child.start_kill()
    }

    async fn wait_for_tree(&mut self) -> std::io::Result<()> {
        self.child.wait().await.map(|_| ())
    }
}

/// Spawn a child only after establishing suspended Job Object ownership.
///
/// # Errors
///
/// Returns the process creation or Job Object setup error. A child is never resumed before Job
/// assignment succeeds.
pub fn spawn_owned_process(command: Command) -> std::io::Result<OwnedProcess> {
    let mut command = CommandWrap::from(command);
    command.wrap(KillOnDrop).wrap(JobObject);
    command.spawn().map(|child| OwnedProcess { child })
}

/// Terminate and reap every process owned by the child's Job Object.
///
/// # Errors
///
/// Returns an operating-system termination/wait error or a timeout if the Job does not report all
/// members stopped within the bounded cleanup interval.
pub async fn stop_owned_process(child: &mut OwnedProcess) -> std::io::Result<()> {
    child.terminate_tree()?;
    tokio::time::timeout(PROCESS_TREE_STOP_TIMEOUT, child.wait_for_tree()).await.unwrap_or_else(
        |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Windows process tree did not stop within two seconds",
            ))
        },
    )
}

#[cfg(test)]
#[derive(Debug)]
struct RejectWindowsOwnership;

#[cfg(test)]
impl CommandWrapper for RejectWindowsOwnership {
    fn wrap_child(
        &mut self,
        _child: Box<dyn ChildWrapper>,
        _command: &CommandWrap,
    ) -> std::io::Result<Box<dyn ChildWrapper>> {
        Err(std::io::Error::other("forced Windows process-ownership setup failure"))
    }
}

#[cfg(test)]
pub fn spawn_windows_owned_process_rejected(command: Command) -> std::io::Result<OwnedProcess> {
    let mut command = CommandWrap::from(command);
    // JobObject's pre-spawn hook still creates the child suspended. The injected wrapper rejects
    // it before JobObject can assign or resume it, while KillOnDrop owns the suspended direct child.
    command.wrap(KillOnDrop).wrap(RejectWindowsOwnership).wrap(JobObject);
    command.spawn().map(|child| OwnedProcess { child })
}
