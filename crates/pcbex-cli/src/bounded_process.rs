//! Bounded subprocess execution for CLI integrations.
//!
//! This module deliberately does not interpret a command through a shell.  The
//! caller supplies an already configured [`std::process::Command`], while this
//! runner owns its standard streams, timeout, cancellation, output limits and
//! process cleanup.

use std::fmt;
use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const READ_CHUNK_BYTES: usize = 8 * 1024;
const EVENT_CHANNEL_CAPACITY: usize = 32;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Limits applied to one subprocess invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLimits {
    /// Maximum wall-clock time between spawning the process and completion.
    pub timeout: Duration,
    /// Maximum number of bytes retained from standard output.
    pub stdout_bytes: usize,
    /// Maximum number of bytes retained from standard error.
    pub stderr_bytes: usize,
}

/// Which child stream produced an error or exceeded its limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessStream {
    Stdout,
    Stderr,
}

impl fmt::Display for ProcessStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

/// Captured result of a bounded subprocess.
#[derive(Debug)]
pub struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Failure while spawning, supervising, or collecting a subprocess.
#[derive(Debug)]
pub enum ProcessError {
    InvalidTimeout {
        timeout: Duration,
    },
    Spawn(io::Error),
    Wait(io::Error),
    Read {
        stream: ProcessStream,
        source: io::Error,
    },
    Timeout {
        timeout: Duration,
    },
    Cancelled,
    StdoutLimit {
        limit: usize,
    },
    StderrLimit {
        limit: usize,
    },
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeout { timeout } => write!(
                formatter,
                "subprocess timeout must be positive and representable: {}",
                display_duration(*timeout)
            ),
            Self::Spawn(source) => write!(formatter, "spawning subprocess: {source}"),
            Self::Wait(source) => write!(formatter, "waiting for subprocess: {source}"),
            Self::Read { stream, source } => {
                write!(formatter, "reading subprocess {stream}: {source}")
            }
            Self::Timeout { timeout } => {
                write!(
                    formatter,
                    "subprocess exceeded timeout of {}",
                    display_duration(*timeout)
                )
            }
            Self::Cancelled => formatter.write_str("subprocess execution cancelled"),
            Self::StdoutLimit { limit } => {
                write!(formatter, "subprocess stdout exceeded {limit} bytes")
            }
            Self::StderrLimit { limit } => {
                write!(formatter, "subprocess stderr exceeded {limit} bytes")
            }
        }
    }
}

impl std::error::Error for ProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(source) | Self::Wait(source) => Some(source),
            Self::Read { source, .. } => Some(source),
            Self::InvalidTimeout { .. }
            | Self::Timeout { .. }
            | Self::Cancelled
            | Self::StdoutLimit { .. }
            | Self::StderrLimit { .. } => None,
        }
    }
}

#[derive(Debug)]
enum ReaderEvent {
    Data(ProcessStream, Vec<u8>),
    Eof(ProcessStream),
    Error {
        stream: ProcessStream,
        source: io::Error,
    },
    Limit(ProcessStream, usize),
}

/// Run a command with bounded, concurrently drained output.
///
/// The command is never run through a shell.  Standard input is always
/// replaced with `null`, and standard output/error are always piped and read
/// concurrently in fixed-size chunks.  On Unix, the child becomes the leader
/// of a fresh process group so a timeout or cancellation also terminates its
/// descendants.  On Windows, the optional Job Object implementation provides
/// the equivalent kill-on-close behavior once the crate's `windows-sys`
/// dependency is enabled (see [`windows_job`] below).
pub fn run_bounded(
    command: &mut Command,
    limits: ProcessLimits,
    cancellation: Option<&AtomicBool>,
) -> Result<ProcessOutput, ProcessError> {
    if cancellation.is_some_and(|cancelled| cancelled.load(Ordering::SeqCst)) {
        return Err(ProcessError::Cancelled);
    }
    if limits.timeout.is_zero() {
        return Err(ProcessError::InvalidTimeout {
            timeout: limits.timeout,
        });
    }
    let deadline =
        Instant::now()
            .checked_add(limits.timeout)
            .ok_or(ProcessError::InvalidTimeout {
                timeout: limits.timeout,
            })?;
    configure_command(command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(ProcessError::Spawn)?;

    #[cfg(windows)]
    let job = match windows_job::Job::for_child(&child) {
        Ok(job) => Some(job),
        Err(source) => {
            let cleanup = terminate_and_reap(&mut child, None);
            return Err(match cleanup {
                Ok(()) => ProcessError::Spawn(source),
                Err(cleanup) => ProcessError::Wait(cleanup),
            });
        }
    };
    #[cfg(not(windows))]
    let job = ();

    let stdout = child.stdout.take().ok_or_else(|| ProcessError::Read {
        stream: ProcessStream::Stdout,
        source: io::Error::new(io::ErrorKind::BrokenPipe, "child stdout was not piped"),
    });
    let stdout = match stdout {
        Ok(stdout) => stdout,
        Err(error) => {
            let cleanup = terminate_and_reap(&mut child, terminate_handle(&job));
            return Err(cleanup_error(error, cleanup));
        }
    };
    let stderr = child.stderr.take().ok_or_else(|| ProcessError::Read {
        stream: ProcessStream::Stderr,
        source: io::Error::new(io::ErrorKind::BrokenPipe, "child stderr was not piped"),
    });
    let stderr = match stderr {
        Ok(stderr) => stderr,
        Err(error) => {
            let cleanup = terminate_and_reap(&mut child, terminate_handle(&job));
            return Err(cleanup_error(error, cleanup));
        }
    };

    let (sender, receiver) = mpsc::sync_channel(EVENT_CHANNEL_CAPACITY);
    let stdout_reader = spawn_reader(
        stdout,
        ProcessStream::Stdout,
        limits.stdout_bytes,
        sender.clone(),
    );
    let stdout_reader = match stdout_reader {
        Ok(reader) => reader,
        Err(source) => {
            let cleanup = terminate_and_reap(&mut child, terminate_handle(&job));
            drop(receiver);
            return Err(cleanup_error(
                ProcessError::Read {
                    stream: ProcessStream::Stdout,
                    source,
                },
                cleanup,
            ));
        }
    };
    let stderr_reader = spawn_reader(stderr, ProcessStream::Stderr, limits.stderr_bytes, sender);
    let stderr_reader = match stderr_reader {
        Ok(reader) => reader,
        Err(source) => {
            let cleanup = terminate_and_reap(&mut child, terminate_handle(&job));
            drop(receiver);
            // A descendant may deliberately escape the managed process
            // group while retaining this pipe. Detach the capped reader so
            // subprocess cleanup cannot wait forever for that descendant.
            drop(stdout_reader);
            return Err(cleanup_error(
                ProcessError::Read {
                    stream: ProcessStream::Stderr,
                    source,
                },
                cleanup,
            ));
        }
    };

    let mut status = None;
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut failure = None;

    loop {
        if let Some(error) = cancellation_error(cancellation) {
            failure = Some(error);
        } else if Instant::now() >= deadline {
            failure = Some(ProcessError::Timeout {
                timeout: limits.timeout,
            });
        }

        if failure.is_none() {
            match child.try_wait() {
                Ok(Some(child_status)) => status = Some(child_status),
                Ok(None) => {}
                Err(source) => failure = Some(ProcessError::Wait(source)),
            }
        }

        while failure.is_none() {
            match receiver.try_recv() {
                Ok(event) => handle_event(
                    event,
                    &mut stdout_done,
                    &mut stderr_done,
                    &mut stdout_bytes,
                    &mut stderr_bytes,
                    &mut failure,
                ),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if !stdout_done || !stderr_done {
                        failure = Some(ProcessError::Read {
                            stream: if stdout_done {
                                ProcessStream::Stderr
                            } else {
                                ProcessStream::Stdout
                            },
                            source: io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "subprocess output reader disconnected",
                            ),
                        });
                    }
                    break;
                }
            }
        }

        if failure.is_some() || (status.is_some() && stdout_done && stderr_done) {
            break;
        }

        let wait_for = deadline
            .saturating_duration_since(Instant::now())
            .min(POLL_INTERVAL);
        match receiver.recv_timeout(wait_for) {
            Ok(event) => handle_event(
                event,
                &mut stdout_done,
                &mut stderr_done,
                &mut stdout_bytes,
                &mut stderr_bytes,
                &mut failure,
            ),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if !stdout_done || !stderr_done {
                    failure = Some(ProcessError::Read {
                        stream: if stdout_done {
                            ProcessStream::Stderr
                        } else {
                            ProcessStream::Stdout
                        },
                        source: io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "subprocess output reader disconnected",
                        ),
                    });
                }
            }
        }
    }

    if let Some(error) = failure {
        let cleanup = terminate_and_reap(&mut child, terminate_handle(&job));
        // Closing the receiver releases any blocked sends. Do not join on a
        // failure path: an adversarial descendant can escape a Unix process
        // group and retain inherited pipe descriptors. Normal completion
        // still joins both readers after EOF.
        drop(receiver);
        drop(stdout_reader);
        drop(stderr_reader);
        return Err(cleanup_error(error, cleanup));
    }

    let status = status.expect("subprocess status is set before both streams reach EOF");
    let stdout_join = stdout_reader.join();
    let stderr_join = stderr_reader.join();
    if stdout_join.is_err() {
        return Err(ProcessError::Read {
            stream: ProcessStream::Stdout,
            source: io::Error::other("stdout reader thread panicked"),
        });
    }
    if stderr_join.is_err() {
        return Err(ProcessError::Read {
            stream: ProcessStream::Stderr,
            source: io::Error::other("stderr reader thread panicked"),
        });
    }

    // A successful direct child must not be able to leave ordinary background
    // descendants running after it closes the captured streams and exits.
    terminate_remaining_descendants(&child, terminate_handle(&job));

    Ok(ProcessOutput {
        status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    })
}

fn handle_event(
    event: ReaderEvent,
    stdout_done: &mut bool,
    stderr_done: &mut bool,
    stdout_bytes: &mut Vec<u8>,
    stderr_bytes: &mut Vec<u8>,
    failure: &mut Option<ProcessError>,
) {
    match event {
        ReaderEvent::Data(stream, bytes) => match stream {
            ProcessStream::Stdout => stdout_bytes.extend(bytes),
            ProcessStream::Stderr => stderr_bytes.extend(bytes),
        },
        ReaderEvent::Eof(stream) => match stream {
            ProcessStream::Stdout => *stdout_done = true,
            ProcessStream::Stderr => *stderr_done = true,
        },
        ReaderEvent::Error { stream, source } => {
            *failure = Some(ProcessError::Read { stream, source });
        }
        ReaderEvent::Limit(stream, limit) => {
            *failure = Some(match stream {
                ProcessStream::Stdout => ProcessError::StdoutLimit { limit },
                ProcessStream::Stderr => ProcessError::StderrLimit { limit },
            });
        }
    }
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    stream: ProcessStream,
    limit: usize,
    sender: SyncSender<ReaderEvent>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("pcbex-{stream}-reader"))
        .spawn(move || {
            let mut buffer = [0u8; READ_CHUNK_BYTES];
            let mut total = 0usize;
            loop {
                let remaining = limit.saturating_sub(total);
                let read_size = READ_CHUNK_BYTES.min(remaining.saturating_add(1)).max(1);
                match reader.read(&mut buffer[..read_size]) {
                    Ok(0) => {
                        let _ = sender.send(ReaderEvent::Eof(stream));
                        return;
                    }
                    Ok(read) if read > remaining => {
                        let _ = sender.send(ReaderEvent::Limit(stream, limit));
                        return;
                    }
                    Ok(read) => {
                        total = total.saturating_add(read);
                        if sender
                            .send(ReaderEvent::Data(stream, buffer[..read].to_vec()))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                    Err(source) => {
                        let _ = sender.send(ReaderEvent::Error { stream, source });
                        return;
                    }
                }
            }
        })
}

fn cancellation_error(cancellation: Option<&AtomicBool>) -> Option<ProcessError> {
    cancellation
        .is_some_and(|cancelled| cancelled.load(Ordering::SeqCst))
        .then_some(ProcessError::Cancelled)
}

fn cleanup_error(original: ProcessError, cleanup: io::Result<()>) -> ProcessError {
    match cleanup {
        Ok(()) => original,
        Err(source) => ProcessError::Wait(source),
    }
}

#[cfg(unix)]
fn configure_command(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // `process_group(0)` is the safe std API for making the child the leader
    // of a new process group.  Descendants inherit that group automatically.
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_command(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_handle(_job: &()) -> Option<&()> {
    None
}

#[cfg(windows)]
fn terminate_handle(job: &Option<windows_job::Job>) -> Option<&windows_job::Job> {
    job.as_ref()
}

#[cfg(not(any(unix, windows)))]
fn terminate_handle(_job: &()) -> Option<&()> {
    None
}

#[cfg(windows)]
fn terminate_and_reap(child: &mut Child, job: Option<&windows_job::Job>) -> io::Result<()> {
    if let Some(job) = job {
        windows_job::terminate(job);
    }
    let _ = child.kill();
    child.wait().map(|_| ())
}

#[cfg(unix)]
fn terminate_and_reap(child: &mut Child, _job: Option<&()>) -> io::Result<()> {
    let process_group = -(child.id() as i32);
    // A process that already exited may make kill(2) report ESRCH; wait()
    // below still performs the required reap in that case.
    let group_killed = unsafe { kill_process_group(process_group) };
    if group_killed.is_err() {
        let _ = child.kill();
    }
    child.wait().map(|_| ())
}

#[cfg(not(any(unix, windows)))]
fn terminate_and_reap(child: &mut Child, _job: Option<&()>) -> io::Result<()> {
    let _ = child.kill();
    child.wait().map(|_| ())
}

#[cfg(windows)]
fn terminate_remaining_descendants(_child: &Child, job: Option<&windows_job::Job>) {
    if let Some(job) = job {
        windows_job::terminate(job);
    }
}

#[cfg(unix)]
fn terminate_remaining_descendants(child: &Child, _job: Option<&()>) {
    let process_group = -(child.id() as i32);
    let _ = unsafe { kill_process_group(process_group) };
}

#[cfg(not(any(unix, windows)))]
fn terminate_remaining_descendants(_child: &Child, _job: Option<&()>) {}

#[cfg(unix)]
unsafe fn kill_process_group(process_group: i32) -> io::Result<()> {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    if unsafe { kill(process_group, SIGKILL) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn display_duration(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        format!("{}.{:03}s", duration.as_secs(), duration.subsec_millis())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

#[cfg(windows)]
mod windows_job {
    //! Windows Job Object implementation.
    //!
    //! The crate enables the Foundation, Security, JobObjects, and Threading
    //! portions of `windows-sys` for this target-specific implementation.

    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
    };

    pub struct Job(HANDLE);

    impl Job {
        pub fn for_child(child: &Child) -> io::Result<Self> {
            let process = child.as_raw_handle() as HANDLE;
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(last_error());
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
            limits.BasicLimitInformation = JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                ..unsafe { zeroed() }
            };
            let configured = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if configured == 0 {
                unsafe { CloseHandle(job) };
                return Err(last_error());
            }
            let assigned = unsafe { AssignProcessToJobObject(job, process) };
            if assigned == 0 {
                unsafe { CloseHandle(job) };
                return Err(last_error());
            }
            Ok(Self(job))
        }
    }

    pub fn terminate(job: &Job) {
        unsafe {
            let _ = TerminateJobObject(job.0, 1);
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn last_error() -> io::Error {
        io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    #[cfg(unix)]
    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    fn limits(timeout: Duration, stdout_bytes: usize, stderr_bytes: usize) -> ProcessLimits {
        ProcessLimits {
            timeout,
            stdout_bytes,
            stderr_bytes,
        }
    }

    #[cfg(unix)]
    #[test]
    fn captures_stdout_and_stderr_concurrently() {
        let mut command = shell("printf out; printf err >&2");
        let output = run_bounded(&mut command, limits(Duration::from_secs(1), 3, 3), None)
            .expect("bounded command succeeds");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    #[cfg(unix)]
    #[test]
    fn preserves_nonzero_exit_status() {
        let mut command = shell("exit 7");
        let output = run_bounded(&mut command, limits(Duration::from_secs(1), 32, 32), None)
            .expect("nonzero exit is still a captured result");
        assert_eq!(output.status.code(), Some(7));
    }

    #[cfg(unix)]
    #[test]
    fn enforces_timeout() {
        let mut command = shell("sleep 2");
        let error = run_bounded(
            &mut command,
            limits(Duration::from_millis(40), 32, 32),
            None,
        )
        .expect_err("sleep should time out");
        assert!(matches!(error, ProcessError::Timeout { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn enforces_stdout_limit() {
        let mut command = shell("printf 12345");
        let error = run_bounded(&mut command, limits(Duration::from_secs(1), 4, 32), None)
            .expect_err("stdout should exceed the limit");
        assert!(matches!(error, ProcessError::StdoutLimit { limit: 4 }));
    }

    #[cfg(unix)]
    #[test]
    fn enforces_stderr_limit() {
        let mut command = shell("printf 12345 >&2");
        let error = run_bounded(&mut command, limits(Duration::from_secs(1), 32, 4), None)
            .expect_err("stderr should exceed the limit");
        assert!(matches!(error, ProcessError::StderrLimit { limit: 4 }));
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_terminates_child() {
        let cancelled = AtomicBool::new(false);
        let mut command = shell("sleep 2");
        let error = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(40));
                cancelled.store(true, Ordering::SeqCst);
            });
            run_bounded(
                &mut command,
                limits(Duration::from_secs(2), 32, 32),
                Some(&cancelled),
            )
        })
        .expect_err("cancelled command should not run to completion");
        assert!(matches!(error, ProcessError::Cancelled));
    }

    #[cfg(unix)]
    #[test]
    fn pre_cancelled_command_is_not_spawned() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let marker = directory.path().join("spawned");
        let mut command = shell("printf spawned > \"$1\"");
        command.arg("pcbex-test").arg(&marker);
        let cancelled = AtomicBool::new(true);
        let error = run_bounded(
            &mut command,
            limits(Duration::from_secs(1), 32, 32),
            Some(&cancelled),
        )
        .expect_err("pre-cancelled command must not spawn");
        assert!(matches!(error, ProcessError::Cancelled));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn zero_timeout_is_rejected_before_spawn() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let marker = directory.path().join("spawned");
        let mut command = shell("printf spawned > \"$1\"");
        command.arg("pcbex-test").arg(&marker);
        let error = run_bounded(&mut command, limits(Duration::ZERO, 32, 32), None)
            .expect_err("zero timeout must be rejected");
        assert!(matches!(error, ProcessError::InvalidTimeout { .. }));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn overflowing_timeout_is_rejected_before_spawn() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let marker = directory.path().join("spawned");
        let mut command = shell("printf spawned > \"$1\"");
        command.arg("pcbex-test").arg(&marker);
        let error = run_bounded(&mut command, limits(Duration::MAX, 32, 32), None)
            .expect_err("unrepresentable timeout must be rejected");
        assert!(matches!(error, ProcessError::InvalidTimeout { .. }));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_grandchild_process_group() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let marker = directory.path().join("grandchild-marker");
        let marker_arg = marker.to_string_lossy().into_owned();
        let mut command = shell("(sleep 1; printf leaked > \"$1\") & wait");
        command.arg("pcbex-test").arg(&marker_arg);
        let error = run_bounded(
            &mut command,
            limits(Duration::from_millis(50), 32, 32),
            None,
        )
        .expect_err("waiting shell should time out");
        assert!(matches!(error, ProcessError::Timeout { .. }));
        thread::sleep(Duration::from_millis(1_200));
        assert!(
            !marker.exists(),
            "grandchild outlived process-group cleanup"
        );
        let _ = fs::remove_file(marker);
    }

    #[cfg(unix)]
    #[test]
    fn successful_child_cannot_leave_background_descendant() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let marker = directory.path().join("background-marker");
        let marker_arg = marker.to_string_lossy().into_owned();
        let mut command = shell("(sleep 1; printf leaked > \"$1\") >/dev/null 2>&1 &");
        command.arg("pcbex-test").arg(&marker_arg);
        let output = run_bounded(&mut command, limits(Duration::from_secs(1), 32, 32), None)
            .expect("direct child succeeds");
        assert!(output.status.success());
        thread::sleep(Duration::from_millis(1_200));
        assert!(
            !marker.exists(),
            "successful child left a background descendant running"
        );
    }
}
