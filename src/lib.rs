//! ask-sandbox: a seccomp user-notification supervisor that decides per
//! syscall and opens files itself.
//!
//! # Design (why CONTINUE is never used for policy)
//!
//! `seccomp_unotify(2)` warns that answering with
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is unsafe when the decision depended
//! on a user pointer: a sibling thread can mutate the buffer between the
//! supervisor's `process_vm_readv` and the kernel's re-fetch. This crate
//! never does that for path-taking syscalls. For `open` / `openat` /
//! `openat2` / `creat` the supervisor:
//!
//! 1. copies the path **once** with `process_vm_readv`;
//! 2. resolves it beneath a pinned root with `openat2(RESOLVE_BENEATH)`;
//! 3. asks the policy (static rules, session grants, or an ask hook);
//! 4. injects the resulting fd with `SECCOMP_IOCTL_NOTIF_ADDFD` + `SEND`.
//!
//! The kernel never re-reads the target's pointer, so a concurrent mutate
//! cannot change what was opened.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod filter;
pub mod policy;
pub mod spawn;
pub mod supervisor;
pub mod sys;

pub use filter::{Class, Entry, CORPUS};
pub use policy::{Access, AskRequest, CommandDecider, Decision, DenyAll, Policy, Rule, TtyDecider};
pub use spawn::{install_in_self, spawn, Sandboxed};
pub use supervisor::{pin_roots, Handled, Root, Stats, Supervisor};
