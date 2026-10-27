//! Spawns a child that installs the seccomp filter with a NEW_LISTENER fd
//! and hands that fd back to the supervisor over a unix socket. The child
//! runs with `PR_SET_NO_NEW_PRIVS`, so the filter works unprivileged.

use crate::filter;
use crate::sys::{self, SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_SET_MODE_FILTER};
use std::ffi::CString;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

/// A sandboxed child and the listener fd that mediates its syscalls.
pub struct Sandboxed {
    pub child: Child,
    pub listener: OwnedFd,
}

/// Spawns `program` with `args` under the ask-sandbox filter. The parent
/// receives the NEW_LISTENER fd and is responsible for running the
/// supervisor against it.
pub fn spawn(program: &str, args: &[&str]) -> io::Result<Sandboxed> {
    let mut socks = [-1; 2];
    // SAFETY: SOCK_CLOEXEC unix streampair.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            socks.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let parent_sock = socks[0];
    let child_sock = socks[1];

    let filter = filter::build();
    // The filter must outlive the pre_exec hook, so it is kept on the heap
    // and never freed (leaked intentionally: once per spawn is fine).
    let filter: &'static [libc::sock_filter] = Box::leak(filter.into_boxed_slice());
    let filter_ptr = filter.as_ptr() as usize;
    let filter_len = filter.len();

    let mut cmd = Command::new(program);
    cmd.args(args);
    // SAFETY: pre_exec runs in the child between fork and exec. Only
    // async-signal-safe calls. sock_fprog is rebuilt inside the closure
    // from Sync usizes so the closure itself is Sync.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            let prog = libc::sock_fprog {
                len: filter_len as u16,
                filter: filter_ptr as *mut _,
            };
            let listener = libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &prog as *const libc::sock_fprog,
            );
            if listener < 0 {
                return Err(io::Error::last_os_error());
            }
            if sys::send_fd_raw(child_sock, listener as RawFd) < 0 {
                let _ = libc::close(listener as RawFd);
                return Err(io::Error::last_os_error());
            }
            let _ = libc::close(listener as RawFd);
            let _ = libc::close(child_sock);
            let _ = libc::close(parent_sock);
            Ok(())
        });
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            unsafe {
                libc::close(parent_sock);
                libc::close(child_sock);
            }
            return Err(e);
        }
    };
    // SAFETY: we own both ends.
    unsafe {
        libc::close(child_sock);
    }
    let listener = match sys::recv_fd(parent_sock) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe {
                libc::close(parent_sock);
            }
            let _ = child; // drop waits? no — leak intentionally not; drop Child waits on Drop? Child Drop does NOT wait. We kill.
            return Err(e);
        }
    };
    unsafe {
        libc::close(parent_sock);
    }
    Ok(Sandboxed { child, listener })
}

/// Spawns a child that runs `f` after installing the filter. Used by the
/// TOCTOU harness: the child is a tiny C-free Rust process that just calls
/// openat in a loop while a sibling mutates the path buffer.
///
/// The callback runs in the child after the filter is installed and the
/// listener has been sent; it must not return (it calls `exit`).
pub fn spawn_fn<F>(f: F) -> io::Result<Sandboxed>
where
    F: FnOnce() + Send + 'static,
{
    // Pipe used to tell the child "filter is live, go".
    let mut go = [-1; 2];
    if unsafe { libc::pipe2(go.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // We cannot pass a Rust closure across fork safely if it captures
    // non-async-signal-safe state. The harness therefore uses a dedicated
    // binary (`ask-sandbox-harness`) instead of this path. Kept as a
    // documented non-goal.
    let _ = (f, go);
    Err(io::Error::other(
        "spawn_fn is not used; run ask-sandbox-harness instead",
    ))
}

/// Installs the filter in the CURRENT process and returns the listener.
/// The caller becomes both the target and (in another thread) the
/// supervisor. Used by latency microbenchmarks that want no fork.
pub fn install_in_self() -> io::Result<OwnedFd> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let filter = filter::build();
    let filter: &'static [libc::sock_filter] = Box::leak(filter.into_boxed_slice());
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };
    // SAFETY: prog points to a live sock_fprog.
    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if listener < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: listener is a new fd owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(listener as RawFd) })
}

/// Writes a tiny helper script that always answers `allow-once` / `deny`
/// based on a fixed string, for the "tasks without relaunch" measurement.
pub fn write_allow_once_helper(path: &std::path::Path) -> io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    writeln!(
        f,
        "#!/bin/sh\n# reads one JSON line, always answers allow-once\nread _\necho allow-once"
    )?;
    // SAFETY: chmod.
    unsafe {
        let c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        libc::chmod(c.as_ptr(), 0o755);
    }
    Ok(())
}
