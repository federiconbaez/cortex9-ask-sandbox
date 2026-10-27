//! Declarative rules plus the hook that is consulted when no rule matches.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub struct Rule {
    /// Canonical path (file or directory). Matches itself and, component by
    /// component, everything below it.
    pub root: PathBuf,
    pub access: Access,
}

/// What the hook is asked. `path` is the path the kernel reports for the
/// object the supervisor resolved (or `parent/name` for a creation), never
/// the raw string the target passed.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AskRequest {
    pub syscall: &'static str,
    pub path: PathBuf,
    pub access: Access,
    pub pid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Grant this single operation only.
    AllowOnce,
    /// Grant this exact path and access for the rest of the session.
    AllowSession,
    Deny,
}

pub trait Decider: Send {
    fn decide(&mut self, req: &AskRequest) -> Decision;
}

/// Static sandbox behaviour: anything outside the rules is denied.
pub struct DenyAll;
impl Decider for DenyAll {
    fn decide(&mut self, _: &AskRequest) -> Decision {
        Decision::Deny
    }
}

impl<F: FnMut(&AskRequest) -> Decision + Send> Decider for F {
    fn decide(&mut self, req: &AskRequest) -> Decision {
        self(req)
    }
}

/// Runs an external program per request: the request is written as one JSON
/// line on its stdin and the first stdout line must be `allow-once`,
/// `allow-session` or `deny`. Anything else, a non-zero exit, or exceeding
/// the timeout is a deny. This is the hook an agent harness plugs into.
pub struct CommandDecider {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub timeout: Duration,
}

impl Decider for CommandDecider {
    fn decide(&mut self, req: &AskRequest) -> Decision {
        let Ok(mut child) = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
        else {
            return Decision::Deny;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let line = serde_json::to_string(req).unwrap_or_default();
            let _ = writeln!(stdin, "{line}");
        }
        let deadline = Instant::now() + self.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(st)) if st.success() => break,
                Ok(Some(_)) | Err(_) => return Decision::Deny,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Decision::Deny;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        let mut out = String::new();
        if let Some(stdout) = child.stdout.take() {
            let _ = stdout.take(256).read_to_string(&mut out);
        }
        parse_answer(out.lines().next().unwrap_or(""))
    }
}

/// Asks a human on the controlling terminal. The target is blocked in its
/// syscall while the question is open.
pub struct TtyDecider;
impl Decider for TtyDecider {
    fn decide(&mut self, req: &AskRequest) -> Decision {
        let Ok(tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        else {
            return Decision::Deny;
        };
        let mut w = &tty;
        let _ = write!(
            w,
            "ask-sandbox: pid {} wants {:?} {} via {} [o]nce/[s]ession/[D]eny? ",
            req.pid,
            req.access,
            req.path.display(),
            req.syscall
        );
        let mut line = String::new();
        let _ = BufReader::new(&tty).read_line(&mut line);
        match line.trim() {
            "o" | "once" => Decision::AllowOnce,
            "s" | "session" => Decision::AllowSession,
            _ => Decision::Deny,
        }
    }
}

pub fn parse_answer(s: &str) -> Decision {
    match s.trim() {
        "allow-once" => Decision::AllowOnce,
        "allow-session" => Decision::AllowSession,
        _ => Decision::Deny,
    }
}

pub struct Policy {
    rules: Vec<Rule>,
    session: HashSet<(PathBuf, Access)>,
    decider: Box<dyn Decider>,
}

/// Outcome of [`Policy::check`], with where the answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Rule,
    Session,
    AskedAllowed,
    AskedDenied,
}

impl Verdict {
    pub fn allowed(self) -> bool {
        !matches!(self, Verdict::AskedDenied)
    }
}

impl Policy {
    pub fn new(rules: Vec<Rule>, decider: Box<dyn Decider>) -> Self {
        Self {
            rules,
            session: HashSet::new(),
            decider,
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Pure rule match, without consulting the hook.
    pub fn rule_allows(&self, path: &Path, access: Access) -> bool {
        self.rules
            .iter()
            .any(|r| r.access >= access && path.starts_with(&r.root))
    }

    pub fn check(
        &mut self,
        syscall: &'static str,
        path: &Path,
        access: Access,
        pid: u32,
    ) -> Verdict {
        if self.rule_allows(path, access) {
            return Verdict::Rule;
        }
        if self.session.contains(&(path.to_path_buf(), access))
            || (access == Access::Read
                && self.session.contains(&(path.to_path_buf(), Access::Write)))
        {
            return Verdict::Session;
        }
        let req = AskRequest {
            syscall,
            path: path.to_path_buf(),
            access,
            pid,
        };
        match self.decider.decide(&req) {
            Decision::AllowOnce => Verdict::AskedAllowed,
            Decision::AllowSession => {
                self.session.insert((req.path, access));
                Verdict::AskedAllowed
            }
            Decision::Deny => Verdict::AskedDenied,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(d: Box<dyn Decider>) -> Policy {
        Policy::new(
            vec![
                Rule {
                    root: "/ws".into(),
                    access: Access::Write,
                },
                Rule {
                    root: "/usr".into(),
                    access: Access::Read,
                },
            ],
            d,
        )
    }

    #[test]
    fn component_prefix_not_string_prefix() {
        let p = pol(Box::new(DenyAll));
        assert!(p.rule_allows(Path::new("/ws/a"), Access::Write));
        assert!(p.rule_allows(Path::new("/ws"), Access::Read));
        assert!(!p.rule_allows(Path::new("/wsx/a"), Access::Read));
        assert!(!p.rule_allows(Path::new("/usr/bin/sh"), Access::Write));
        assert!(p.rule_allows(Path::new("/usr/bin/sh"), Access::Read));
    }

    #[test]
    fn allow_once_is_not_remembered_but_session_is() {
        let mut calls = 0;
        let mut p = pol(Box::new(move |r: &AskRequest| {
            calls += 1;
            if r.path.ends_with("once") {
                Decision::AllowOnce
            } else if calls < 100 {
                Decision::AllowSession
            } else {
                Decision::Deny
            }
        }));
        let once = Path::new("/out/once");
        assert_eq!(
            p.check("openat", once, Access::Write, 1),
            Verdict::AskedAllowed
        );
        assert_eq!(
            p.check("openat", once, Access::Write, 1),
            Verdict::AskedAllowed
        );
        let s = Path::new("/out/sess");
        assert_eq!(
            p.check("openat", s, Access::Write, 1),
            Verdict::AskedAllowed
        );
        assert_eq!(p.check("openat", s, Access::Read, 1), Verdict::Session);
        assert_eq!(p.check("openat", s, Access::Write, 1), Verdict::Session);
    }

    #[test]
    fn parse_answers() {
        assert_eq!(parse_answer("allow-once\n"), Decision::AllowOnce);
        assert_eq!(parse_answer("allow-session"), Decision::AllowSession);
        assert_eq!(parse_answer("yes"), Decision::Deny);
        assert_eq!(parse_answer(""), Decision::Deny);
    }

    #[test]
    fn command_decider_timeout_denies() {
        let mut d = CommandDecider {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "sleep 2; echo allow-once".into()],
            timeout: Duration::from_millis(50),
        };
        let req = AskRequest {
            syscall: "openat",
            path: "/x".into(),
            access: Access::Read,
            pid: 1,
        };
        assert_eq!(d.decide(&req), Decision::Deny);
        let mut ok = CommandDecider {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "cat >/dev/null; echo allow-once".into()],
            timeout: Duration::from_secs(5),
        };
        assert_eq!(ok.decide(&req), Decision::AllowOnce);
    }
}
