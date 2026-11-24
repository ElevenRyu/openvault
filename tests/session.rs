//! Session unlock: one unlock, many uses, TTL, lock, `confirm` tags, MCP,
//! socket permissions and audit attribution.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PASS: &str = "correct horse battery staple";

struct Env {
    _tmp: TempDir,
    root: PathBuf,
    home: PathBuf,
    run: PathBuf,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let e = Env {
            home: root.join("v"),
            run: root.join("r"),
            root,
            _tmp: tmp,
        };
        e.with_pass()
            .args(["init", "--unlock", "passphrase", "--recovery-file"])
            .arg(e.root.join("rec"))
            .assert()
            .success();
        e
    }

    /// No key material in the environment and prompts disabled: values are
    /// only reachable through a session.
    fn bare(&self) -> Command {
        let mut c = Command::cargo_bin("openvault").unwrap();
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("HOME", &self.root)
            .env("OPENVAULT_HOME", &self.home)
            .env("OPENVAULT_RUNTIME_DIR", &self.run)
            .env("OPENVAULT_META_CACHE", "file")
            .env("OPENVAULT_TEST_SCRYPT_LOG_N", "10")
            .env("OPENVAULT_NO_PROMPT", "1")
            .current_dir(&self.root);
        c
    }

    fn with_pass(&self) -> Command {
        let mut c = self.bare();
        c.env("OPENVAULT_PASSPHRASE", PASS);
        c
    }

    fn add(&self, name: &str, value: &str, extra: &[&str]) {
        self.bare()
            .arg("add")
            .arg(name)
            .args(extra)
            .write_stdin(value.to_string())
            .assert()
            .success();
    }

    fn unlock(&self, ttl: &str) {
        self.with_pass()
            .args(["unlock", "--for", ttl])
            .assert()
            .success()
            .stderr(predicate::str::contains("unlocked for"));
    }

    fn socket(&self) -> PathBuf {
        let entries: Vec<PathBuf> = fs::read_dir(&self.run)
            .map(|rd| rd.map(|e| e.unwrap().path()).collect())
            .unwrap_or_default();
        entries
            .into_iter()
            .find(|p| p.extension().is_some_and(|x| x == "sock"))
            .expect("session socket")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.bare().arg("lock").output();
    }
}

fn run_ok(e: &Env, name: &str) -> assert_cmd::assert::Assert {
    e.bare()
        .args(["run", "--only", name, "--", "sh", "-c", "echo ${#V} $V"])
        .env("V", format!("secret://{name}"))
        .assert()
}

#[test]
fn no_session_means_no_values() {
    let e = Env::new();
    e.add("a/b", "value-0001", &[]);
    run_ok(&e, "a/b")
        .failure()
        .stderr(predicate::str::contains("fresh Touch ID"));
}

#[test]
fn one_unlock_serves_many_runs_until_lock() {
    let e = Env::new();
    e.add("a/b", "value-0001", &[]);
    e.unlock("10m");
    for _ in 0..3 {
        run_ok(&e, "a/b")
            .success()
            .stdout(predicate::str::contains("10 [REDACTED:a/b]"));
    }
    e.bare()
        .arg("lock")
        .assert()
        .success()
        .stderr(predicate::str::contains("locked"));
    run_ok(&e, "a/b").failure();
    assert!(
        fs::read_dir(&e.run).unwrap().next().is_none(),
        "socket left behind"
    );
}

#[test]
fn session_expires_after_ttl() {
    let e = Env::new();
    e.add("a/b", "value-0001", &[]);
    e.unlock("2s");
    run_ok(&e, "a/b").success();
    std::thread::sleep(Duration::from_millis(3500));
    run_ok(&e, "a/b").failure();
}

#[test]
fn confirm_tagged_secrets_need_fresh_auth_even_in_a_session() {
    let e = Env::new();
    e.add("prod/db", "prod-value-1", &["--tag", "confirm"]);
    e.add("dev/db", "dev-value-01", &[]);
    e.unlock("10m");
    run_ok(&e, "dev/db").success();
    run_ok(&e, "prod/db")
        .failure()
        .stderr(predicate::str::contains("fresh Touch ID"));

    // The agent enforces it too: a direct socket request is refused.
    let mut s = UnixStream::connect(e.socket()).unwrap();
    writeln!(s, r#"{{"op":"decrypt","names":["prod/db"]}}"#).unwrap();
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).unwrap();
    assert!(
        line.contains("\"ok\":false") && line.contains("confirm"),
        "{line}"
    );
    assert!(!line.contains("prod-value-1"));
}

#[test]
fn socket_is_private_and_requests_are_attributed() {
    let e = Env::new();
    e.add("a/b", "value-0001", &[]);
    e.unlock("10m");
    let sock = e.socket();
    let mode = |p: &PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&sock), 0o600);
    assert_eq!(mode(&e.run), 0o700);
    run_ok(&e, "a/b").success();
    let log = fs::read_to_string(e.home.join("audit.log")).unwrap();
    let line = log
        .lines()
        .find(|l| l.contains("\"op\":\"session-read\""))
        .expect("session read audited");
    assert!(line.contains("for pid "), "{line}");
    assert!(!log.contains("value-0001"));
    e.bare().args(["audit", "verify"]).assert().success();
}

#[test]
fn unlock_itself_requires_authentication() {
    let e = Env::new();
    e.bare().args(["unlock", "--for", "5m"]).assert().failure();
    assert!(!e.run.exists() || fs::read_dir(&e.run).unwrap().next().is_none());
}

#[test]
fn mcp_run_uses_the_session_transparently() {
    let e = Env::new();
    e.add("github/token", "ghp_sessionFAKE01", &[]);
    e.unlock("10m");
    let bin = assert_cmd::cargo::cargo_bin("openvault");
    let mut child = std::process::Command::new(bin)
        .arg("mcp")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", &e.root)
        .env("OPENVAULT_HOME", &e.home)
        .env("OPENVAULT_RUNTIME_DIR", &e.run)
        .env("OPENVAULT_META_CACHE", "file")
        .env("OPENVAULT_NO_PROMPT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run","arguments":{
        "command":["sh","-c","echo ${#GITHUB_TOKEN} $GITHUB_TOKEN"],"env":["GITHUB_TOKEN"],"cwd": e.root.to_str().unwrap()}}});
    writeln!(stdin, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    drop(stdin);
    child.wait().unwrap();
    assert!(line.contains("17 [REDACTED:github/token]"), "{line}");
    assert!(!line.contains("ghp_sessionFAKE01"));
}
