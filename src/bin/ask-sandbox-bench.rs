//! Latency microbenchmark: mediated openat vs direct openat.
//!
//! Parent runs the supervisor; child installs the filter and times opens.
//! Prints p50/p99 in microseconds for both.

use ask_sandbox::policy::{Access, Decision, Policy, Rule};
use ask_sandbox::spawn::spawn;
use ask_sandbox::supervisor::{pin_roots, Stats, Supervisor};
use ask_sandbox::sys;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--worker") {
        return match worker(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("bench worker: {e}");
                ExitCode::from(2)
            }
        };
    }
    match parent() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bench: {e}");
            ExitCode::from(2)
        }
    }
}

fn parent() -> io::Result<()> {
    let tmp = {
        let mut p = env::temp_dir();
        p.push(format!("ask-sandbox-bench-{}", std::process::id()));
        fs::create_dir_all(&p)?;
        p
    };
    let root = tmp.join("root");
    fs::create_dir_all(&root)?;
    let file = root.join("f.txt");
    fs::write(&file, b"x")?;
    let file_abs = fs::canonicalize(&file)?;
    let out_path = root.join("out.txt");

    // Direct baseline runs in the parent (no filter).
    let path_c = {
        let mut b = file_abs.as_os_str().as_encoded_bytes().to_vec();
        b.push(0);
        b
    };
    let direct = time_opens(&path_c, 5000)?;
    print_stats("direct", &direct);

    let mut rules = vec![Rule {
        root: root.clone(),
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
    let roots = pin_roots(&rules)?;
    let policy = Policy::new(
        rules,
        Box::new(|_: &ask_sandbox::policy::AskRequest| Decision::Deny),
    );
    let stats = Arc::new(Stats::default());
    let self_exe = env::current_exe()?;
    let wargs = [
        "--worker".to_string(),
        format!("--file={}", file_abs.display()),
        format!("--out={}", out_path.display()),
    ];
    let wrefs: Vec<&str> = wargs.iter().map(|s| s.as_str()).collect();
    let mut sandboxed = spawn(self_exe.to_str().unwrap(), &wrefs)?;
    let mut supervisor = Supervisor::new(sandboxed.listener, roots, policy, stats)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_s = stop.clone();
    let th = std::thread::spawn(move || {
        while !stop_s.load(Ordering::Relaxed) {
            let fd = supervisor.listener_fd();
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pfd, 1, 50) } <= 0 {
                continue;
            }
            match sys::notif_recv(fd) {
                Ok(n) => {
                    let _ = supervisor.handle(&n);
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOTCONN) => break,
                Err(_) => break,
            }
        }
    });
    let _ = sandboxed.child.wait()?;
    stop.store(true, Ordering::Relaxed);
    let _ = th.join();

    let out = fs::read_to_string(&out_path)?;
    print!("{out}");
    // Parse p99 from worker output.
    let mut p99 = f64::NAN;
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("mediated:") {
            for part in rest.split_whitespace() {
                if let Some(v) = part.strip_prefix("p99_us=") {
                    p99 = v.parse().unwrap_or(f64::NAN);
                }
            }
        }
    }
    println!("acceptance_p99_us={p99:.2} target_us=50 met={}", p99 < 50.0);
    let _ = fs::remove_dir_all(&tmp);
    Ok(())
}

fn worker(args: &[String]) -> io::Result<()> {
    let mut file = PathBuf::new();
    let mut out = PathBuf::new();
    for a in args.iter().skip(1) {
        if let Some(v) = a.strip_prefix("--file=") {
            file = PathBuf::from(v);
        } else if let Some(v) = a.strip_prefix("--out=") {
            out = PathBuf::from(v);
        }
    }
    let path_c = {
        let mut b = file.as_os_str().as_encoded_bytes().to_vec();
        b.push(0);
        b
    };
    let _ = time_opens(&path_c, 200)?; // warmup
    let mediated = time_opens(&path_c, 5000)?;
    let mut s = String::new();
    use std::fmt::Write as _;
    let p50 = percentile_us(&mediated, 0.50);
    let p99 = percentile_us(&mediated, 0.99);
    let mean = mediated.iter().sum::<f64>() / mediated.len() as f64;
    let _ = writeln!(
        s,
        "mediated: n={} mean_us={mean:.2} p50_us={p50:.2} p99_us={p99:.2}",
        mediated.len()
    );
    fs::write(&out, &s)?;
    Ok(())
}

fn time_opens(path_c: &[u8], n: usize) -> io::Result<Vec<f64>> {
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        let fd = unsafe { libc::open(path_c.as_ptr().cast(), libc::O_RDONLY) };
        let dt = t0.elapsed();
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            libc::close(fd);
        }
        samples.push(dt.as_secs_f64() * 1e6);
    }
    Ok(samples)
}

fn percentile_us(samples: &[f64], p: f64) -> f64 {
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i]
}

fn print_stats(label: &str, samples: &[f64]) {
    let p50 = percentile_us(samples, 0.50);
    let p99 = percentile_us(samples, 0.99);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    println!(
        "{label}: n={} mean_us={mean:.2} p50_us={p50:.2} p99_us={p99:.2}",
        samples.len()
    );
}
