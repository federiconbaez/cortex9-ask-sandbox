//! Raw kernel interfaces: seccomp user notifications, openat2, process memory
//! reads and fd passing. Everything here is a thin, checked wrapper over a
//! syscall; policy lives elsewhere.

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// `struct seccomp_data` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// `struct seccomp_notif`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// `struct seccomp_notif_resp`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// `struct seccomp_notif_addfd`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

/// `struct seccomp_notif_sizes`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct SeccompNotifSizes {
    notif: u16,
    resp: u16,
    data: u16,
}

/// `struct open_how` (version 0, 24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

const fn ioc(dir: u64, nr: u64, size: usize) -> u64 {
    (dir << 30) | ((size as u64) << 16) | ((b'!' as u64) << 8) | nr
}
const IOC_W: u64 = 1;
const IOC_RW: u64 = 3;

pub const NOTIF_RECV: u64 = ioc(IOC_RW, 0, size_of::<SeccompNotif>());
pub const NOTIF_SEND: u64 = ioc(IOC_RW, 1, size_of::<SeccompNotifResp>());
pub const NOTIF_ID_VALID: u64 = ioc(IOC_W, 2, size_of::<u64>());
pub const NOTIF_ADDFD: u64 = ioc(IOC_W, 3, size_of::<SeccompNotifAddfd>());

pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
pub const SECCOMP_GET_NOTIF_SIZES: u32 = 3;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u32 = 1 << 5;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;

/// Maximum path length read from the target (PATH_MAX, including the NUL).
pub const PATH_MAX: usize = 4096;

fn cvt(r: libc::c_long) -> io::Result<libc::c_long> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// Checks that the running kernel uses the same notification struct sizes
/// as this crate. A mismatch would make every ioctl read garbage.
pub fn check_notif_sizes() -> io::Result<()> {
    let mut sizes = SeccompNotifSizes::default();
    // SAFETY: SECCOMP_GET_NOTIF_SIZES writes a seccomp_notif_sizes.
    cvt(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut SeccompNotifSizes,
        )
    })?;
    if sizes.notif as usize != size_of::<SeccompNotif>()
        || sizes.resp as usize != size_of::<SeccompNotifResp>()
        || sizes.data as usize != size_of::<SeccompData>()
    {
        return Err(io::Error::other(format!(
            "kernel notif sizes {sizes:?} differ from compiled sizes"
        )));
    }
    Ok(())
}

/// Receives one notification. Blocks until one is available.
pub fn notif_recv(listener: RawFd) -> io::Result<SeccompNotif> {
    let mut n = SeccompNotif::default();
    // SAFETY: the buffer is a zeroed seccomp_notif as the kernel requires.
    let r = unsafe { libc::ioctl(listener, NOTIF_RECV as _, &mut n as *mut SeccompNotif) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n)
}

/// Sends a response. ENOENT means the target died or was interrupted.
pub fn notif_send(listener: RawFd, resp: &SeccompNotifResp) -> io::Result<()> {
    // SAFETY: resp points to a valid seccomp_notif_resp.
    let r = unsafe { libc::ioctl(listener, NOTIF_SEND as _, resp as *const SeccompNotifResp) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// True if the notification `id` is still pending (the target thread is
/// still blocked in that syscall, so its tid was not recycled).
pub fn notif_id_valid(listener: RawFd, id: u64) -> bool {
    // SAFETY: the kernel reads one u64.
    unsafe { libc::ioctl(listener, NOTIF_ID_VALID as _, &id as *const u64) == 0 }
}

/// Installs `fd` into the target and completes the syscall with the new fd
/// number as its return value (SECCOMP_ADDFD_FLAG_SEND, atomic).
pub fn notif_addfd_send(listener: RawFd, id: u64, fd: RawFd, cloexec: bool) -> io::Result<i32> {
    let a = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: fd as u32,
        newfd: 0,
        newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
    };
    // SAFETY: a is a valid seccomp_notif_addfd.
    let r = unsafe { libc::ioctl(listener, NOTIF_ADDFD as _, &a as *const SeccompNotifAddfd) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(r)
}

/// Reads `buf.len()` bytes at `addr` from thread `tid`.
pub fn read_mem(tid: u32, addr: u64, buf: &mut [u8]) -> io::Result<()> {
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: local iovec covers buf exactly.
    let n = unsafe { libc::process_vm_readv(tid as libc::pid_t, &local, 1, &remote, 1, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != buf.len() {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    Ok(())
}

/// Reads a NUL-terminated string (at most PATH_MAX bytes) from the target,
/// one page-bounded chunk at a time so a string near an unmapped page still
/// reads. Returns the bytes without the NUL. This is the ONLY copy of the
/// path the supervisor ever uses.
pub fn read_cstr(tid: u32, addr: u64) -> io::Result<Vec<u8>> {
    if addr == 0 {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    let mut out = Vec::with_capacity(256);
    let mut cur = addr;
    let mut chunk = [0u8; PATH_MAX];
    while out.len() < PATH_MAX {
        let to_page = 4096 - (cur as usize & 4095);
        let want = to_page.min(PATH_MAX - out.len());
        read_mem(tid, cur, &mut chunk[..want])?;
        if let Some(p) = chunk[..want].iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..p]);
            return Ok(out);
        }
        out.extend_from_slice(&chunk[..want]);
        cur += want as u64;
    }
    Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG))
}

pub fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// openat2(2) with explicit resolve flags. The returned fd is always
/// O_CLOEXEC in the supervisor.
pub fn openat2(dirfd: RawFd, path: &CStr, how: OpenHow) -> io::Result<OwnedFd> {
    let mut how = how;
    how.flags |= libc::O_CLOEXEC as u64;
    // SAFETY: how is a valid open_how of size_of::<OpenHow>().
    let fd = cvt(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const OpenHow,
            size_of::<OpenHow>(),
        )
    })?;
    // SAFETY: fd was just returned by the kernel and is owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Plain open(2) of a supervisor-side path (used for /proc magic links).
pub fn open_path(path: &CStr, flags: i32) -> io::Result<OwnedFd> {
    // SAFETY: path is NUL-terminated.
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by the kernel.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Path the kernel reports for an fd the supervisor holds.
pub fn fd_path(fd: &OwnedFd) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

pub fn os(bytes: &[u8]) -> &OsStr {
    OsStr::from_bytes(bytes)
}

/// Reads `Key:\tvalue` from /proc/<tid>/status.
pub fn proc_status_field(tid: u32, key: &str) -> io::Result<String> {
    let s = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(v) = rest.strip_prefix(':') {
                return Ok(v.trim().to_string());
            }
        }
    }
    Err(io::Error::from_raw_os_error(libc::ENOENT))
}

/// Sends one fd over a unix socket with SCM_RIGHTS. Async-signal-safe (only
/// syscalls, no allocation), so it can run in a pre_exec hook.
///
/// # Safety
/// `sock` and `fd` must be valid descriptors.
pub unsafe fn send_fd_raw(sock: RawFd, fd: RawFd) -> libc::c_int {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u64; 4];
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as _;
    let cmsg = libc::CMSG_FIRSTHDR(&msg);
    (*cmsg).cmsg_level = libc::SOL_SOCKET;
    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
    (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
    std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
    if libc::sendmsg(sock, &msg, 0) < 0 {
        -1
    } else {
        0
    }
}

/// Receives one fd sent with [`send_fd_raw`].
pub fn recv_fd(sock: RawFd) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u64; 4];
    // SAFETY: zeroed msghdr is valid; buffers outlive the call.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as _;
        let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(io::Error::other(
                "no SCM_RIGHTS in message (child failed to install filter)",
            ));
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>());
        Ok(OwnedFd::from_raw_fd(fd))
    }
}
