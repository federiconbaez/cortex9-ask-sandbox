//! CLI: `ask-sandbox [--ask CMD] [--allow PATH:rw]... -- CMD [ARGS...]`
//!
//! Runs CMD under the ask-sandbox filter. Filesystem roots are the
//! `--allow` directories; anything else is denied, or forwarded to `--ask`.

use ask_sandbox::policy::{Access, CommandDecider, DenyAll, Policy, Rule, TtyDecider};
use ask_sandbox::spawn::spawn;
use ask_sandbox::supervisor::{pin_roots, Stats, Supervisor};
use ask_sandbox::CORPUS;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "Usage:\n  ask-sandbox [--allow PATH[:rw|:ro]]... [--ask CMD|--ask-tty|--deny] -- PROGRAM [ARGS...]\n  ask-sandbox --corpus\n  ask-sandbox --self-check"
    );
    std::process::exit(2);
}

fn parse_allow(s: &str) -> Rule {
    let (path, access) = if let Some((p, a)) = s.rsplit_once(':') {
        match a {
            "rw" | "w" | "write" => (p, Access::Write),
            "ro" | "r" | "read" => (p, Access::Read),
            _ => (s, Access::Read),
        }
    } else {
        (s, Access::Read)
    };
    Rule {
        root: PathBuf::from(path),
        access,
    }
}

fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    if args[0] == "--corpus" {
        for e in CORPUS.iter() {
            println!("{:<18} {:?}  {}", e.name, e.class, e.why);
        }
        return ExitCode::SUCCESS;
    }
    if args[0] == "--self-check" {
        return match self_check() {
            Ok(()) => {
                println!("self-check: ok");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("self-check: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let mut rules = Vec::new();
    let mut ask: AskMode = AskMode::Deny;
    let mut system_libs = true;
    let mut prog: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--allow" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                rules.push(parse_allow(&args[i]));
            }
            "--ask" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                ask = AskMode::Command(PathBuf::from(&args[i]), Vec::new());
            }
            "--ask-tty" => ask = AskMode::Tty,
            "--deny" => ask = AskMode::Deny,
            "--system-libs" => system_libs = true,
            "--no-system-libs" => system_libs = false,
            "--" => {
                prog = args.split_off(i + 1);
                break;
            }
            other if other.starts_with('-') => usage(),
            _ => {
                prog = args.split_off(i);
                break;
            }
        }
        i += 1;
    }
    if prog.is_empty() {
        usage();
    }
    if rules.is_empty() {
        eprintln!("ask-sandbox: at least one --allow is required");
        return ExitCode::FAILURE;
    }
    if system_libs {
        for p in ["/usr", "/lib", "/lib64", "/etc"] {
            if PathBuf::from(p).is_dir() {
                rules.push(Rule {
                    root: PathBuf::from(p),
                    access: Access::Read,
                });
            }
        }
    }

    let decider: Box<dyn ask_sandbox::policy::Decider> = match ask {
        AskMode::Deny => Box::new(DenyAll),
        AskMode::Tty => Box::new(TtyDecider),
        AskMode::Command(p, a) => Box::new(CommandDecider {
            program: p,
            args: a,
            timeout: Duration::from_secs(30),
        }),
    };
    let policy = Policy::new(rules.clone(), decider);
    let roots = match pin_roots(&rules) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ask-sandbox: pin roots: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stats = Arc::new(Stats::default());
    let argv: Vec<&str> = prog[1..].iter().map(|s| s.as_str()).collect();
    let mut sandboxed = match spawn(&prog[0], &argv) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ask-sandbox: spawn: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut supervisor = match Supervisor::new(sandboxed.listener, roots, policy, stats.clone()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ask-sandbox: supervisor: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let handle = std::thread::spawn(move || supervisor.run_until(&stop_t));
    let status = sandboxed.child.wait().expect("wait");
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    eprintln!(
        "ask-sandbox: handled={} injected={} denied={} escapes={}",
        Stats::get(&stats.handled),
        Stats::get(&stats.injected),
        Stats::get(&stats.denied),
        Stats::get(&stats.escapes),
    );
    if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(status.code().unwrap_or(1) as u8)
    }
}

enum AskMode {
    Deny,
    Tty,
    Command(PathBuf, Vec<String>),
}

fn self_check() -> std::io::Result<()> {
    ask_sandbox::sys::check_notif_sizes()?;
    let filter = ask_sandbox::filter::build();
    assert!(!filter.is_empty());
    // Prove that USER_NOTIF works without privileges.
    let listener = ask_sandbox::spawn::install_in_self()?;
    drop(listener);
    Ok(())
}
