//! Adversarial multithreaded TOCTOU harness.
//!
//! Parent process runs the supervisor (no filter). The child installs the
//! filter, then one of its threads flips a shared path buffer between an
//! allowed file and a secret file while another thread opens that buffer
//! N times and checks every fd it receives.
//!
//! * Secure mode (default): 0 escapes required.
//! * `--continue-control`: CONTINUE after a path-based allow decision; the
//!   harness must observe escapes > 0 (sensitivity check). Teammate
//!   `unotify-toctou-oracle` (#41) studies CONTINUE bypasses in depth;
//!   this binary only uses CONTINUE as a negative control.

use ask_sandbox::policy::{Access, Decision, Policy, Rule};
use ask_sandbox::spawn::spawn;
use ask_sandbox::supervisor::{pin_roots, Stats, Supervisor};
use ask_sandbox::sys;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Instant;

const ALLOWED_CONTENT: &[u8] = b"ALLOWED_PAYLOAD_v1\n";
const SECRET_CONTENT: &[u8] = b"SECRET_PAYLOAD_v1\n";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--worker") {
        return match worker(&args) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("worker error: {e}");
                ExitCode::from(2)
            }
        };
    }
    match parent(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("harness error: {e}");
            ExitCode::from(2)
        }
    }
}

fn parent(args: &[String]) -> io::Result<u8> {
    let mut n: u64 = 1000;
    let mut continue_control = false;
    let mut quiet = false;
    for a in args.iter().skip(1) {
        match a.as_str() {
            "--continue-control" => continue_control = true,
            "--quiet" => quiet = true,
            "--worker" => {}
            s if s.starts_with("-n=") => n = s[3..].parse().unwrap_or(1000),
            "-h" | "--help" => {
                eprintln!(
                    "Usage: ask-sandbox-harness [-n=N] [--continue-control] [--quiet]\n\
                     Default N=1000. Exit 0 iff escapes==0 in secure mode,\n\
                     or escapes>0 in --continue-control mode."
                );
                return Ok(0);
            }
            other => {
                eprintln!("unknown arg: {other}");
                return Ok(2);
            }
        }
    }

    let base = {
        let mut p = env::temp_dir();
        p.push(format!(
            "ask-sandbox-harness-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        fs::create_dir_all(&p)?;
        p
    };
    // Two sibling directories. Only `root` is in the policy. `outside` holds
    // the secret and must NEVER be granted — that is the escape target.
    let root = base.join("root");
    let outside = base.join("outside");
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&outside)?;
    let allowed = root.join("allowed.txt");
    let secret = outside.join("secret.txt");
    fs::write(&allowed, ALLOWED_CONTENT)?;
    fs::write(&secret, SECRET_CONTENT)?;
    let allowed_abs = fs::canonicalize(&allowed)?;
    let secret_abs = fs::canonicalize(&secret)?;

    // Path buffer and result live INSIDE the allow root so the worker can
    // mmap/write them without widening the policy to cover the secret.
    let buf_path = root.join("pathbuf");
    {
        let mut f = fs::File::create(&buf_path)?;
        let mut zeros = vec![0u8; sys::PATH_MAX];
        let a = allowed_abs.as_os_str().as_encoded_bytes();
        zeros[..a.len()].copy_from_slice(a);
        f.write_all(&zeros)?;
    }

    // The child execs a dynamically linked binary, so the loader must be
    // able to open shared libraries. Those opens are mediated too; grant
    // read on the usual loader paths. (A static binary would not need this.)
    let mut rules = vec![Rule {
        root: root.clone(),
        access: Access::Write,
    }];
    for p in ["/usr", "/lib", "/lib64", "/etc"] {
        if Path::new(p).is_dir() {
            rules.push(Rule {
                root: PathBuf::from(p),
                access: Access::Read,
            });
        }
    }
    let roots = pin_roots(&rules)?;
    let policy = Policy::new(
        rules,
        Box::new(|_: &ask_sandbox::policy::AskRequest| Decision::Deny),
    );
    let stats = Arc::new(Stats::default());

    let self_exe = env::current_exe()?;
    let worker_args = [
        "--worker".to_string(),
        format!("--n={n}"),
        format!("--buf={}", buf_path.display()),
        format!("--allowed={}", allowed_abs.display()),
        format!("--secret={}", secret_abs.display()),
    ];
    let worker_refs: Vec<&str> = worker_args.iter().map(|s| s.as_str()).collect();
    let mut sandboxed = spawn(self_exe.to_str().unwrap(), &worker_refs)?;
    let mut supervisor = Supervisor::new(sandboxed.listener, roots, policy, stats.clone())?;
    supervisor.set_continue_negative_control(continue_control);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_s = stop.clone();
    let sup = std::thread::spawn(move || {
        while !stop_s.load(Ordering::Relaxed) {
            let fd = supervisor.listener_fd();
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let pr = unsafe { libc::poll(&mut pfd, 1, 50) };
            if pr < 0 {
                break;
            }
            if pr == 0 {
                continue;
            }
            match sys::notif_recv(fd) {
                Ok(n) => {
                    let _ = supervisor.handle(&n);
                }
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::ENOENT) | Some(libc::EINTR) | Some(libc::ENOTCONN)
                    ) =>
                {
                    if e.raw_os_error() == Some(libc::ENOTCONN) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let status = sandboxed.child.wait()?;
    stop.store(true, Ordering::Relaxed);
    let _ = sup.join();

    // Worker prints: escapes=N opens_ok=N opens_err=N
    // We re-read via exit code convention: worker exits 0 on its local pass
    // criteria, but parent decides based on mode. Simpler: worker writes a
    // result file.
    let result_path = root.join("result");
    // Worker writes result next to buf. If missing, fail.
    // Actually worker writes to stdout which we didn't capture. Use a result file.
    let result = fs::read_to_string(&result_path).unwrap_or_default();
    let mut escapes = 0u64;
    let mut opens_ok = 0u64;
    let mut opens_err = 0u64;
    for part in result.split_whitespace() {
        if let Some(v) = part.strip_prefix("escapes=") {
            escapes = v.parse().unwrap_or(0);
        } else if let Some(v) = part.strip_prefix("opens_ok=") {
            opens_ok = v.parse().unwrap_or(0);
        } else if let Some(v) = part.strip_prefix("opens_err=") {
            opens_err = v.parse().unwrap_or(0);
        }
    }
    if !quiet {
        println!(
            "mode={} N={} opens_ok={} opens_err={} escapes={} handled={} injected={} denied={} child_status={status}",
            if continue_control {
                "continue-control"
            } else {
                "secure"
            },
            n,
            opens_ok,
            opens_err,
            escapes,
            Stats::get(&stats.handled),
            Stats::get(&stats.injected),
            Stats::get(&stats.denied),
        );
    }
    let _ = fs::remove_dir_all(&base);

    let pass = if continue_control {
        escapes > 0
    } else {
        escapes == 0 && Stats::get(&stats.handled) > 0
    };
    Ok(if pass { 0 } else { 1 })
}

fn worker(args: &[String]) -> io::Result<u8> {
    let mut n: u64 = 1000;
    let mut buf_path = PathBuf::new();
    let mut allowed = PathBuf::new();
    let mut secret = PathBuf::new();
    for a in args.iter().skip(1) {
        if let Some(v) = a.strip_prefix("-n=") {
            n = v.parse().unwrap_or(1000);
        } else if let Some(v) = a.strip_prefix("--buf=") {
            buf_path = PathBuf::from(v);
        } else if let Some(v) = a.strip_prefix("--allowed=") {
            allowed = PathBuf::from(v);
        } else if let Some(v) = a.strip_prefix("--secret=") {
            secret = PathBuf::from(v);
        }
    }
    if buf_path.as_os_str().is_empty() {
        return Err(io::Error::other("worker: missing --buf"));
    }
    let allowed_c = path_bytes(&allowed);
    let secret_c = path_bytes(&secret);

    let file = OpenOptions::new().read(true).write(true).open(&buf_path)?;
    let buf = unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            sys::PATH_MAX,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        );
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        p as *mut u8
    };
    write_path(buf, &allowed_c);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));
    let stop_m = stop.clone();
    let barrier_m = barrier.clone();
    let buf_addr = buf as usize;
    let mutator = std::thread::spawn(move || {
        let buf = buf_addr as *mut u8;
        barrier_m.wait();
        let mut flip = false;
        while !stop_m.load(Ordering::Relaxed) {
            if flip {
                write_path(buf, &allowed_c);
            } else {
                write_path(buf, &secret_c);
            }
            flip = !flip;
            std::hint::spin_loop();
        }
    });
    barrier.wait();

    let escapes = AtomicU64::new(0);
    let opens_ok = AtomicU64::new(0);
    let opens_err = AtomicU64::new(0);
    for _ in 0..n {
        let fd = unsafe { libc::open(buf.cast(), libc::O_RDONLY) };
        if fd < 0 {
            opens_err.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        opens_ok.fetch_add(1, Ordering::Relaxed);
        let mut got = [0u8; 64];
        let nread = unsafe { libc::read(fd, got.as_mut_ptr().cast(), got.len()) };
        unsafe {
            libc::close(fd);
        }
        if nread > 0 && got[..nread as usize].starts_with(SECRET_CONTENT) {
            escapes.fetch_add(1, Ordering::Relaxed);
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = mutator.join();

    let result = format!(
        "escapes={} opens_ok={} opens_err={}\n",
        escapes.load(Ordering::Relaxed),
        opens_ok.load(Ordering::Relaxed),
        opens_err.load(Ordering::Relaxed),
    );
    // Result file sits next to the pathbuf.
    let result_path = buf_path.parent().unwrap().join("result");
    fs::write(&result_path, &result)?;
    // Also print for humans when run directly.
    eprint!("{result}");
    Ok(0)
}

fn write_path(buf: *mut u8, path: &[u8]) {
    assert!(path.len() + 1 < sys::PATH_MAX);
    unsafe {
        std::ptr::copy_nonoverlapping(path.as_ptr(), buf, path.len());
        *buf.add(path.len()) = 0;
    }
}

fn path_bytes(p: &Path) -> Vec<u8> {
    p.as_os_str().as_encoded_bytes().to_vec()
}
