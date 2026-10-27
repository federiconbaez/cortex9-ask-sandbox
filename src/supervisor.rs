//! The supervisor loop: receive a notification, copy its arguments exactly
//! once, decide, perform the operation against a supervisor-held directory
//! fd, and inject the resulting fd. No decision is ever answered with
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, so the kernel never re-reads a user
//! pointer the target could have mutated.

use crate::filter::{self, Class};
use crate::policy::{Access, Policy, Verdict};
use crate::sys::{self, OpenHow, SeccompNotif, SeccompNotifResp};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Counters the harness and the CLI read back.
#[derive(Default, Debug)]
pub struct Stats {
    pub handled: AtomicU64,
    pub injected: AtomicU64,
    pub denied: AtomicU64,
    pub emulated_meta: AtomicU64,
    /// Operations the supervisor let through that, after its own resolution,
    /// landed OUTSIDE every policy root. Must stay 0: it is the escape count.
    pub escapes: AtomicU64,
}

impl Stats {
    pub fn get(a: &AtomicU64) -> u64 {
        a.load(Ordering::Relaxed)
    }
    fn inc(a: &AtomicU64) {
        a.fetch_add(1, Ordering::Relaxed);
    }
}

/// A policy root the supervisor pins as an O_PATH directory fd at startup.
/// All resolution happens beneath one of these fds with RESOLVE_BENEATH, so
/// a path the target supplies can never climb out with `..` or a symlink.
pub struct Root {
    pub path: PathBuf,
    pub fd: OwnedFd,
    pub access: Access,
}

pub struct Supervisor {
    listener: OwnedFd,
    roots: Vec<Root>,
    policy: Policy,
    stats: Arc<Stats>,
    /// When true, emulate-class syscalls are answered with CONTINUE instead
    /// of being performed by the supervisor. This is the INSECURE mode kept
    /// only as a negative control for the harness; never a policy path.
    continue_negative_control: bool,
}

/// How one notification was handled, for tests and tracing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Handled {
    Injected { path: PathBuf, verdict: Verdict },
    MetadataEmulated,
    Denied { errno: i32 },
    Continued,
    TargetGone,
}

impl Supervisor {
    pub fn new(
        listener: OwnedFd,
        roots: Vec<Root>,
        policy: Policy,
        stats: Arc<Stats>,
    ) -> io::Result<Self> {
        sys::check_notif_sizes()?;
        Ok(Self {
            listener,
            roots,
            policy,
            stats,
            continue_negative_control: false,
        })
    }

    pub fn set_continue_negative_control(&mut self, on: bool) {
        self.continue_negative_control = on;
    }

    pub fn listener_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    /// Runs until `stop` is set or the listener returns ENOTCONN.
    pub fn run_until(&mut self, stop: &std::sync::atomic::AtomicBool) -> io::Result<()> {
        while !stop.load(Ordering::Relaxed) {
            let fd = self.listener.as_raw_fd();
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let pr = unsafe { libc::poll(&mut pfd, 1, 50) };
            if pr < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            if pr == 0 {
                continue;
            }
            let notif = match sys::notif_recv(fd) {
                Ok(n) => n,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) if e.raw_os_error() == Some(libc::ENOTCONN) => return Ok(()),
                Err(e) => return Err(e),
            };
            let _ = self.handle(&notif);
        }
        Ok(())
    }

    /// Runs until the listener returns ENOTCONN (all targets gone).
    pub fn run(&mut self) -> io::Result<()> {
        let never = std::sync::atomic::AtomicBool::new(false);
        self.run_until(&never)
    }

    /// Handles exactly one notification. Public so the harness can drive it.
    pub fn handle(&mut self, notif: &SeccompNotif) -> io::Result<Handled> {
        Stats::inc(&self.stats.handled);
        let nr = notif.data.nr as i64;
        let class = filter::class_of(nr).unwrap_or(Class::Deny);
        let name = filter::name_of(nr);

        if class == Class::Emulate && self.continue_negative_control {
            // INSECURE control path (classic TOCTOU):
            // 1. copy the path once and decide;
            // 2. if it looked allowed, CONTINUE so the kernel re-fetches
            //    the user pointer — a sibling thread may have changed it.
            // Used only to prove the harness detects escapes.
            let path_idx = Self::path_arg_index(nr);
            let looks_allowed = match sys::read_cstr(notif.pid, notif.data.args[path_idx]) {
                Ok(raw) => {
                    let p = PathBuf::from(sys::os(&raw));
                    self.roots.iter().any(|r| p.starts_with(&r.path))
                }
                Err(_) => false,
            };
            if looks_allowed {
                let resp = SeccompNotifResp {
                    id: notif.id,
                    val: 0,
                    error: 0,
                    flags: sys::SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                };
                self.send(&resp)?;
                return Ok(Handled::Continued);
            }
            self.deny(notif, libc::EACCES)?;
            Stats::inc(&self.stats.denied);
            return Ok(Handled::Denied {
                errno: libc::EACCES,
            });
        }

        match class {
            Class::Emulate => self.emulate(notif, name),
            Class::Deny => {
                self.deny(notif, libc::EPERM)?;
                Ok(Handled::Denied { errno: libc::EPERM })
            }
            // NullPathOnly and Unmediated never notify; they are resolved in
            // the cBPF program. Reaching here means a filter bug: fail closed.
            _ => {
                self.deny(notif, libc::EPERM)?;
                Ok(Handled::Denied { errno: libc::EPERM })
            }
        }
    }

    fn emulate(&mut self, notif: &SeccompNotif, name: &'static str) -> io::Result<Handled> {
        let nr = notif.data.nr as i64;

        // ---- the single copy of the user pointer ----
        let path_idx = Self::path_arg_index(nr);
        let raw = match sys::read_cstr(notif.pid, notif.data.args[path_idx]) {
            Ok(b) => b,
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(libc::EFAULT);
                self.deny(notif, errno)?;
                return Ok(Handled::Denied { errno });
            }
        };
        // From here on only `raw` is used; the target's buffer is never read
        // again, and the kernel never re-reads it either.

        // Only open-family syscalls are fully emulated with ADDFD. The other
        // Emulate entries (mkdir/unlink/rename) are answered with EPERM so
        // CONTINUE is never used; the TOCTOU surface for them is closed even
        // if the operation itself is not yet performed by the supervisor.
        if !Self::is_open_family(nr) {
            self.deny(notif, libc::EPERM)?;
            Stats::inc(&self.stats.denied);
            return Ok(Handled::Denied { errno: libc::EPERM });
        }

        let (flags, mode) = Self::open_flags(nr, notif)?;
        let access = Self::access_of(flags);
        let decision_path = PathBuf::from(sys::os(&raw));

        // Resolve against a pinned root. Relative paths are rejected: the
        // target's cwd is not trusted.
        let root_info = self
            .pick_root(&decision_path)
            .map(|r| (r.path.clone(), r.fd.as_raw_fd()));
        let Some((root_path, root_fd)) = root_info else {
            // Outside every root: refuse. An allow-once grant for a brand-new
            // path would need a new pinned root; that is out of scope.
            let _ = self.policy.check(name, &decision_path, access, notif.pid);
            Stats::inc(&self.stats.denied);
            self.deny(notif, libc::EACCES)?;
            return Ok(Handled::Denied {
                errno: libc::EACCES,
            });
        };

        let verdict = self.policy.check(name, &decision_path, access, notif.pid);
        if !verdict.allowed() {
            self.deny(notif, libc::EACCES)?;
            Stats::inc(&self.stats.denied);
            return Ok(Handled::Denied {
                errno: libc::EACCES,
            });
        }

        let rel = decision_path.strip_prefix(&root_path).unwrap();
        let leaf = if rel.as_os_str().is_empty() {
            sys::cstring(b".")?
        } else {
            sys::cstring(rel.as_os_str().as_encoded_bytes())?
        };

        let how = OpenHow {
            flags: flags & !(libc::O_NOFOLLOW as u64),
            mode,
            resolve: sys::RESOLVE_BENEATH | sys::RESOLVE_NO_MAGICLINKS,
        };
        let fd = match sys::openat2(root_fd, &leaf, how) {
            Ok(fd) => fd,
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(libc::ENOENT);
                self.deny(notif, errno)?;
                return Ok(Handled::Denied { errno });
            }
        };

        // Defence in depth: the fd the supervisor holds must still be under
        // a root (catches resolution bugs and /proc tricks).
        if let Ok(real) = sys::fd_path(&fd) {
            if !self.under_any_root(&real) {
                Stats::inc(&self.stats.escapes);
                self.deny(notif, libc::EACCES)?;
                return Ok(Handled::Denied {
                    errno: libc::EACCES,
                });
            }
        }

        if !sys::notif_id_valid(self.listener.as_raw_fd(), notif.id) {
            return Ok(Handled::TargetGone);
        }
        sys::notif_addfd_send(self.listener.as_raw_fd(), notif.id, fd.as_raw_fd(), true)?;
        Stats::inc(&self.stats.injected);
        Ok(Handled::Injected {
            path: decision_path,
            verdict,
        })
    }

    fn pick_root(&self, path: &Path) -> Option<&Root> {
        if !path.is_absolute() {
            return None;
        }
        self.roots
            .iter()
            .filter(|r| path.starts_with(&r.path))
            .max_by_key(|r| r.path.as_os_str().len())
    }

    fn under_any_root(&self, p: &Path) -> bool {
        self.roots.iter().any(|r| p.starts_with(&r.path))
    }

    fn path_arg_index(nr: i64) -> usize {
        if nr == libc::SYS_open || nr == libc::SYS_creat || nr == libc::SYS_truncate {
            0
        } else {
            1
        }
    }

    fn is_open_family(nr: i64) -> bool {
        matches!(
            nr,
            libc::SYS_open | libc::SYS_openat | libc::SYS_openat2 | libc::SYS_creat
        )
    }

    /// Copies the open flags (and mode) from the notification. For openat2
    /// the flags live in a userland `open_how`; they are read once here.
    fn open_flags(nr: i64, notif: &SeccompNotif) -> io::Result<(u64, u64)> {
        if nr == libc::SYS_openat2 {
            let mut how = OpenHow::default();
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(
                    (&mut how as *mut OpenHow).cast::<u8>(),
                    std::mem::size_of::<OpenHow>(),
                )
            };
            sys::read_mem(notif.pid, notif.data.args[2], bytes)?;
            Ok((how.flags, how.mode))
        } else if nr == libc::SYS_creat {
            Ok((
                (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64,
                notif.data.args[1],
            ))
        } else if nr == libc::SYS_open {
            Ok((notif.data.args[1], notif.data.args[2]))
        } else {
            // openat
            Ok((notif.data.args[2], notif.data.args[3]))
        }
    }

    fn access_of(flags: u64) -> Access {
        let acc = flags as i32 & libc::O_ACCMODE;
        if acc == libc::O_WRONLY
            || acc == libc::O_RDWR
            || (flags as i32 & (libc::O_CREAT | libc::O_TRUNC)) != 0
        {
            Access::Write
        } else {
            Access::Read
        }
    }

    fn deny(&self, notif: &SeccompNotif, errno: i32) -> io::Result<()> {
        let resp = SeccompNotifResp {
            id: notif.id,
            val: 0,
            error: -errno,
            flags: 0,
        };
        self.send(&resp)
    }

    fn send(&self, resp: &SeccompNotifResp) -> io::Result<()> {
        match sys::notif_send(self.listener.as_raw_fd(), resp) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Opens the policy roots as O_PATH directory fds. Paths are canonicalised
/// so `starts_with` later matches what the kernel reports via /proc/self/fd.
pub fn pin_roots(rules: &[crate::policy::Rule]) -> io::Result<Vec<Root>> {
    let mut roots = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for r in rules {
        let canon = std::fs::canonicalize(&r.root).unwrap_or_else(|_| r.root.clone());
        if !seen.insert(canon.clone()) {
            continue;
        }
        let c = sys::cstring(canon.as_os_str().as_encoded_bytes())?;
        let fd = sys::open_path(&c, libc::O_PATH | libc::O_DIRECTORY)?;
        roots.push(Root {
            path: canon,
            fd,
            access: r.access,
        });
    }
    if roots.is_empty() {
        return Err(io::Error::other("policy has no usable roots"));
    }
    Ok(roots)
}

#[allow(dead_code)]
fn _keep_cstring(_: CString) {}
