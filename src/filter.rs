//! The seccomp filter and the classified syscall corpus.
//!
//! Every syscall the filter names belongs to one class. The class decides
//! what the cBPF program returns before any userspace code runs:
//!
//! * [`Class::Emulate`]: `SECCOMP_RET_USER_NOTIF`. The supervisor copies the
//!   arguments once, decides, and performs the operation itself. It never
//!   answers with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, so the kernel never
//!   re-reads a user pointer after the decision.
//! * [`Class::Deny`]: `SECCOMP_RET_ERRNO(EPERM)` in the filter itself.
//! * [`Class::NullPathOnly`]: allowed only when the path pointer is NULL
//!   (checked on the register value, which a sibling thread cannot change).
//! * [`Class::Unmediated`]: path-taking syscalls that are allowed straight
//!   through. They are listed so the gap is explicit, not hidden.
//!
//! Syscalls not listed are allowed (fd-based or pointer-free).

use crate::sys;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    Emulate,
    Deny,
    NullPathOnly,
    Unmediated,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Entry {
    pub name: &'static str,
    #[serde(skip)]
    pub nr: i64,
    pub class: Class,
    pub why: &'static str,
}

macro_rules! e {
    ($name:ident, $class:ident, $why:expr) => {
        Entry {
            name: stringify!($name),
            nr: paste_nr!($name),
            class: Class::$class,
            why: $why,
        }
    };
}
macro_rules! paste_nr {
    (open) => {
        libc::SYS_open
    };
    (openat) => {
        libc::SYS_openat
    };
    (openat2) => {
        libc::SYS_openat2
    };
    (creat) => {
        libc::SYS_creat
    };
    (mkdir) => {
        libc::SYS_mkdir
    };
    (mkdirat) => {
        libc::SYS_mkdirat
    };
    (unlink) => {
        libc::SYS_unlink
    };
    (unlinkat) => {
        libc::SYS_unlinkat
    };
    (rmdir) => {
        libc::SYS_rmdir
    };
    (rename) => {
        libc::SYS_rename
    };
    (renameat) => {
        libc::SYS_renameat
    };
    (renameat2) => {
        libc::SYS_renameat2
    };
    (link) => {
        libc::SYS_link
    };
    (linkat) => {
        libc::SYS_linkat
    };
    (symlink) => {
        libc::SYS_symlink
    };
    (symlinkat) => {
        libc::SYS_symlinkat
    };
    (truncate) => {
        libc::SYS_truncate
    };
    (chmod) => {
        libc::SYS_chmod
    };
    (fchmodat) => {
        libc::SYS_fchmodat
    };
    (chown) => {
        libc::SYS_chown
    };
    (lchown) => {
        libc::SYS_lchown
    };
    (fchownat) => {
        libc::SYS_fchownat
    };
    (mknodat) => {
        libc::SYS_mknodat
    };
    (open_by_handle_at) => {
        libc::SYS_open_by_handle_at
    };
    (utimensat) => {
        libc::SYS_utimensat
    };
    (execve) => {
        libc::SYS_execve
    };
    (newfstatat) => {
        libc::SYS_newfstatat
    };
    (statx) => {
        libc::SYS_statx
    };
    (faccessat2) => {
        libc::SYS_faccessat2
    };
    (readlinkat) => {
        libc::SYS_readlinkat
    };
}

/// The 30-syscall corpus. Order is stable; tests and the README table are
/// generated from it.
pub const CORPUS: [Entry; 30] = [
    e!(
        open,
        Emulate,
        "path + flags; supervisor opens and injects the fd"
    ),
    e!(
        openat,
        Emulate,
        "path + dirfd; supervisor opens and injects the fd"
    ),
    e!(
        openat2,
        Emulate,
        "open_how is copied once; target resolve flags are kept"
    ),
    e!(creat, Emulate, "open(O_CREAT|O_WRONLY|O_TRUNC)"),
    e!(
        mkdir,
        Emulate,
        "supervisor runs mkdirat on a resolved parent fd"
    ),
    e!(
        mkdirat,
        Emulate,
        "supervisor runs mkdirat on a resolved parent fd"
    ),
    e!(
        unlink,
        Emulate,
        "supervisor runs unlinkat on a resolved parent fd"
    ),
    e!(
        unlinkat,
        Emulate,
        "supervisor runs unlinkat on a resolved parent fd"
    ),
    e!(
        rmdir,
        Emulate,
        "unlinkat(AT_REMOVEDIR) on a resolved parent fd"
    ),
    e!(rename, Emulate, "renameat2 between two resolved parent fds"),
    e!(
        renameat,
        Emulate,
        "renameat2 between two resolved parent fds"
    ),
    e!(
        renameat2,
        Emulate,
        "renameat2 between two resolved parent fds; flags kept"
    ),
    e!(
        link,
        Deny,
        "a hard link can expose an outside inode inside a root"
    ),
    e!(
        linkat,
        Deny,
        "a hard link can expose an outside inode inside a root"
    ),
    e!(
        symlink,
        Deny,
        "not emulated yet; symlinks are resolved beneath anyway"
    ),
    e!(
        symlinkat,
        Deny,
        "not emulated yet; symlinks are resolved beneath anyway"
    ),
    e!(
        truncate,
        Deny,
        "path-based write; ftruncate on an fd stays allowed"
    ),
    e!(
        chmod,
        Deny,
        "path-based metadata write; fchmod stays allowed"
    ),
    e!(
        fchmodat,
        Deny,
        "path-based metadata write; fchmod stays allowed"
    ),
    e!(chown, Deny, "path-based metadata write"),
    e!(lchown, Deny, "path-based metadata write"),
    e!(
        fchownat,
        Deny,
        "path-based metadata write; also covers fchown via AT_EMPTY_PATH"
    ),
    e!(mknodat, Deny, "device/FIFO creation"),
    e!(
        open_by_handle_at,
        Deny,
        "opens by file handle, bypassing path policy"
    ),
    e!(
        utimensat,
        NullPathOnly,
        "utimensat(fd, NULL) (futimens) allowed; paths denied"
    ),
    e!(
        execve,
        Unmediated,
        "cannot be emulated; binaries outside roots can run"
    ),
    e!(
        newfstatat,
        Unmediated,
        "metadata of outside paths is visible, not content"
    ),
    e!(
        statx,
        Unmediated,
        "metadata of outside paths is visible, not content"
    ),
    e!(
        faccessat2,
        Unmediated,
        "existence/permission bits of outside paths visible"
    ),
    e!(
        readlinkat,
        Unmediated,
        "symlink targets outside roots are readable"
    ),
];

/// Extra syscalls denied by the filter that are not part of the corpus
/// (privileged or sandbox-escaping operations).
pub const EXTRA_DENY: [i64; 14] = [
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_ptrace,
    libc::SYS_process_vm_writev,
    libc::SYS_bpf,
    libc::SYS_mknod,
    libc::SYS_name_to_handle_at,
    libc::SYS_kexec_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_fsopen,
];

pub fn class_of(nr: i64) -> Option<Class> {
    CORPUS.iter().find(|e| e.nr == nr).map(|e| e.class)
}

pub fn name_of(nr: i64) -> &'static str {
    CORPUS
        .iter()
        .find(|e| e.nr == nr)
        .map(|e| e.name)
        .unwrap_or("?")
}

const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

/// Builds the cBPF program. Only x86_64 is supported; any other audit arch
/// (including the x32 ABI) kills the process.
pub fn build() -> Vec<libc::sock_filter> {
    let errno = SECCOMP_RET_ERRNO_EPERM;
    let mut p = vec![
        stmt(LD_W_ABS, OFF_ARCH),
        jump(JEQ_K, sys::AUDIT_ARCH_X86_64, 1, 0),
        stmt(RET_K, sys::SECCOMP_RET_KILL_PROCESS),
        stmt(LD_W_ABS, OFF_NR),
        jump(JGE_K, 0x4000_0000, 0, 1),
        stmt(RET_K, sys::SECCOMP_RET_KILL_PROCESS),
    ];
    for e in CORPUS.iter() {
        match e.class {
            Class::Emulate => {
                p.push(jump(JEQ_K, e.nr as u32, 0, 1));
                p.push(stmt(RET_K, sys::SECCOMP_RET_USER_NOTIF));
            }
            Class::Deny => {
                p.push(jump(JEQ_K, e.nr as u32, 0, 1));
                p.push(stmt(RET_K, errno));
            }
            Class::NullPathOnly => {
                // if nr == X { A = arg1.lo; if A != 0 deny; A = arg1.hi;
                //   if A != 0 deny; allow }. When nr != X the jump skips
                // the block with A still holding nr.
                p.push(jump(JEQ_K, e.nr as u32, 0, 6));
                p.push(stmt(LD_W_ABS, off_arg_lo(1)));
                p.push(jump(JEQ_K, 0, 0, 3));
                p.push(stmt(LD_W_ABS, off_arg_lo(1) + 4));
                p.push(jump(JEQ_K, 0, 0, 1));
                p.push(stmt(RET_K, sys::SECCOMP_RET_ALLOW));
                p.push(stmt(RET_K, errno));
            }
            Class::Unmediated => {}
        }
    }
    for nr in EXTRA_DENY {
        p.push(jump(JEQ_K, nr as u32, 0, 1));
        p.push(stmt(RET_K, errno));
    }
    p.push(stmt(RET_K, sys::SECCOMP_RET_ALLOW));
    p
}

const SECCOMP_RET_ERRNO_EPERM: u32 = sys::SECCOMP_RET_ERRNO | libc::EPERM as u32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_has_30_unique_syscalls() {
        let mut nrs: Vec<i64> = CORPUS.iter().map(|e| e.nr).collect();
        nrs.sort();
        nrs.dedup();
        assert_eq!(nrs.len(), 30);
    }

    #[test]
    fn program_fits_and_ends_with_allow() {
        let p = build();
        assert!(p.len() < 4096);
        let last = p.last().unwrap();
        assert_eq!(last.code, RET_K);
        assert_eq!(last.k, sys::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn null_path_block_skips_to_next_nr_test() {
        // When nr != utimensat, jf must land right after the 7-insn block,
        // which is the next `jeq nr` (A still holds nr there).
        let p = build();
        let i = p
            .iter()
            .position(|f| f.code == JEQ_K && f.k == libc::SYS_utimensat as u32)
            .unwrap();
        assert_eq!(p[i].jf, 6);
        assert_eq!(p[i + 1 + 6].code, JEQ_K);
    }

    #[test]
    fn no_emulated_syscall_is_also_denied() {
        for e in CORPUS.iter().filter(|e| e.class == Class::Emulate) {
            assert!(!EXTRA_DENY.contains(&e.nr), "{}", e.name);
        }
    }
}
