//! End-to-end checks that exercise the real seccomp user-notification
//! path. These MUST fail visibly if the kernel feature is missing.

use std::process::Command;

fn harness() -> &'static str {
    env!("CARGO_BIN_EXE_ask-sandbox-harness")
}

#[test]
fn self_check_installs_filter_unprivileged() {
    let out = Command::new(env!("CARGO_BIN_EXE_ask-sandbox"))
        .arg("--self-check")
        .output()
        .expect("run self-check");
    assert!(
        out.status.success(),
        "self-check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn corpus_lists_30_syscalls() {
    let out = Command::new(env!("CARGO_BIN_EXE_ask-sandbox"))
        .arg("--corpus")
        .output()
        .expect("run corpus");
    assert!(out.status.success());
    let n = String::from_utf8_lossy(&out.stdout).lines().count();
    assert_eq!(n, 30, "corpus must list exactly 30 syscalls");
}

#[test]
fn toctou_secure_zero_escapes() {
    let out = Command::new(harness())
        .args(["-n=200"])
        .output()
        .expect("run harness");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "secure harness failed: {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("escapes=0"),
        "expected escapes=0, got: {stdout}"
    );
}

#[test]
fn toctou_continue_control_detects_escapes() {
    let out = Command::new(harness())
        .args(["-n=200", "--continue-control"])
        .output()
        .expect("run continue-control");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "continue-control must observe escapes>0 (harness sensitivity): {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("mode=continue-control"),
        "unexpected output: {stdout}"
    );
}

#[test]
fn mediated_open_works_for_allowed_path() {
    let tmp = std::env::temp_dir().join(format!("ask-sandbox-it-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let f = tmp.join("hello.txt");
    std::fs::write(&f, b"hi\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ask-sandbox"))
        .args([
            "--allow",
            &format!("{}:rw", tmp.display()),
            "--",
            "/bin/cat",
            f.to_str().unwrap(),
        ])
        .output()
        .expect("run cat");
    assert!(
        out.status.success(),
        "cat under allow failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hi\n");
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn denied_outside_allow_without_ask() {
    let tmp = std::env::temp_dir().join(format!("ask-sandbox-deny-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let outside = std::env::temp_dir().join(format!("ask-sandbox-secret-{}", std::process::id()));
    std::fs::write(&outside, b"secret\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ask-sandbox"))
        .args([
            "--allow",
            &format!("{}:rw", tmp.display()),
            "--deny",
            "--",
            "/bin/cat",
            outside.to_str().unwrap(),
        ])
        .output()
        .expect("run denied cat");
    assert!(
        !out.status.success(),
        "cat of outside path must fail under --deny"
    );
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_file(&outside);
}
