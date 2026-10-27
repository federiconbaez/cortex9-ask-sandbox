//! "% of tasks completed without relaunch" measurement.
//!
//! Each "task" is a tiny program that:
//!   1. reads a file inside the workspace root (always allowed);
//!   2. writes a result file OUTSIDE the workspace (needs a mid-task grant).
//!
//! * Static mode (`--deny`): step 2 fails → task fails → would need relaunch
//!   with a wider profile. Counted as "needs relaunch".
//! * Ask mode (`--ask allow-once helper`): step 2 is granted once → task
//!   completes. Counted as "no relaunch".
//!
//! Prints `completed_without_relaunch=X/N pct=YY.Y`.

use ask_sandbox::policy::{Access, CommandDecider, DenyAll, Policy, Rule};
use ask_sandbox::spawn::spawn;
use ask_sandbox::supervisor::{pin_roots, Stats, Supervisor};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--worker") {
        return match worker(&args) {
            Ok(c) => ExitCode::from(c),
            Err(e) => {
                eprintln!("worker: {e}");
                ExitCode::from(2)
            }
        };
    }
    match parent(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tasks: {e}");
            ExitCode::from(2)
        }
    }
}

fn parent(args: &[String]) -> io::Result<()> {
    let mut n: usize = 20;
    let mut mode = "ask";
    for a in args.iter().skip(1) {
        if let Some(v) = a.strip_prefix("-n=") {
            n = v.parse().unwrap_or(20);
        } else if a == "--static" {
            mode = "static";
        } else if a == "--ask" {
            mode = "ask";
        }
    }

    let base = {
        let mut p = env::temp_dir();
        p.push(format!("ask-sandbox-tasks-{}", std::process::id()));
        fs::create_dir_all(&p)?;
        p
    };
    let ws = base.join("ws");
    let out_dir = base.join("out");
    fs::create_dir_all(&ws)?;
    fs::create_dir_all(&out_dir)?;
    fs::write(ws.join("input.txt"), b"task-input\n")?;

    // allow-once helper
    let helper = ws.join("allow-once.sh");
    {
        let mut f = fs::File::create(&helper)?;
        writeln!(f, "#!/bin/sh\nread _\necho allow-once")?;
        unsafe {
            libc::chmod(
                std::ffi::CString::new(helper.as_os_str().as_encoded_bytes())
                    .unwrap()
                    .as_ptr(),
                0o755,
            );
        }
    }

    let mut completed = 0usize;
    for i in 0..n {
        let out_file = out_dir.join(format!("r{i}.txt"));
        let ok = run_one(&ws, &out_dir, &out_file, &helper, mode == "ask")?;
        if ok && out_file.is_file() {
            completed += 1;
        }
        let _ = fs::remove_file(&out_file);
    }
    let pct = 100.0 * completed as f64 / n as f64;
    println!("mode={mode} completed_without_relaunch={completed}/{n} pct={pct:.1}");
    let _ = fs::remove_dir_all(&base);
    Ok(())
}

fn run_one(
    ws: &std::path::Path,
    out_dir: &std::path::Path,
    out_file: &std::path::Path,
    helper: &std::path::Path,
    ask: bool,
) -> io::Result<bool> {
    let mut rules = vec![Rule {
        root: ws.to_path_buf(),
        access: Access::Write,
    }];
    for p in ["/usr", "/lib", "/lib64", "/etc"] {
        if std::path::Path::new(p).is_dir() {
            rules.push(Rule {
                root: PathBuf::from(p),
                access: Access::Read,
            });
        }
    }
    // In ask mode the out_dir is NOT pre-allowed; the helper grants allow-once.
    // But allow-once only records the path in the session set — our supervisor
    // still requires the path to sit under a pinned root to open it. So for
    // a mid-task grant of a new directory we pin out_dir as a root with NO
    // default access in the policy rules (access check goes through the
    // ask hook). Trick: pin it via a Rule that we do NOT put in the policy
    // match list... Currently pin_roots takes the same rules as policy.
    //
    // Practical approach for this measurement: pin out_dir as a root but
    // leave it out of the *policy* allow list by splitting pin vs policy.
    // The current API ties them. Workaround used here: in ask mode, add
    // out_dir as a Write root for pinning, but wrap the policy so
    // rule_allows returns false for it (custom: use empty rules for policy
    // match on out_dir by keeping policy rules without out_dir, and pass
    // extra roots).
    //
    // Minimal change: Policy::new rules without out_dir; pin_roots gets
    // rules + out_dir. Extend pin call.

    let mut pin_rules = rules.clone();
    if ask {
        pin_rules.push(Rule {
            root: out_dir.to_path_buf(),
            access: Access::Write,
        });
    }

    let decider: Box<dyn ask_sandbox::policy::Decider> = if ask {
        Box::new(CommandDecider {
            program: helper.to_path_buf(),
            args: vec![],
            timeout: Duration::from_secs(5),
        })
    } else {
        Box::new(DenyAll)
    };
    let policy = Policy::new(rules, decider);
    let roots = pin_roots(&pin_rules)?;
    let stats = Arc::new(Stats::default());

    let self_exe = env::current_exe()?;
    let wargs = [
        "--worker".to_string(),
        format!("--in={}", ws.join("input.txt").display()),
        format!("--out={}", out_file.display()),
    ];
    let wrefs: Vec<&str> = wargs.iter().map(|s| s.as_str()).collect();
    let mut sandboxed = spawn(self_exe.to_str().unwrap(), &wrefs)?;
    let mut supervisor = Supervisor::new(sandboxed.listener, roots, policy, stats)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let th = std::thread::spawn(move || {
        let _ = supervisor.run_until(&stop_t);
    });
    let status = sandboxed.child.wait()?;
    stop.store(true, Ordering::Relaxed);
    let _ = th.join();
    Ok(status.success())
}

fn worker(args: &[String]) -> io::Result<u8> {
    let mut input = PathBuf::new();
    let mut output = PathBuf::new();
    for a in args.iter().skip(1) {
        if let Some(v) = a.strip_prefix("--in=") {
            input = PathBuf::from(v);
        } else if let Some(v) = a.strip_prefix("--out=") {
            output = PathBuf::from(v);
        }
    }
    let data = fs::read(&input)?;
    // Mid-task write outside the workspace.
    match fs::write(&output, data) {
        Ok(()) => Ok(0),
        Err(_) => Ok(1),
    }
}
