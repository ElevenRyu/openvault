//! End-to-end tests of the `openvault` binary. Each test gets a fresh vault in a
//! temp dir (passphrase mode, cheap scrypt, file metadata cache) and uses the
//! recovery key via OPENVAULT_IDENTITY for headless value access.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const VALUE: &str = "ghp_FAKE_value_0123456789";

struct Env {
    _tmp: TempDir,
    root: PathBuf,
    home: PathBuf,
    recovery: String,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = root.join("vault");
        let rec = root.join("recovery.txt");
        let mut c = Command::cargo_bin("openvault").unwrap();
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("HOME", &root)
            .env("OPENVAULT_HOME", &home)
            .env("OPENVAULT_META_CACHE", "file")
            .env("OPENVAULT_PASSPHRASE", "correct horse battery staple")
            .env("OPENVAULT_TEST_SCRYPT_LOG_N", "10")
            .args(["init", "--unlock", "passphrase", "--recovery-file"])
            .arg(&rec)
            .assert()
            .success();
        let recovery = fs::read_to_string(&rec).unwrap().trim().to_string();
        fs::remove_file(&rec).unwrap();
        Env {
            _tmp: tmp,
            root,
            home,
            recovery,
        }
    }

    /// Command with metadata access only (no value key in env).
    fn bare(&self) -> Command {
        let mut c = Command::cargo_bin("openvault").unwrap();
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("HOME", &self.root)
            .env("OPENVAULT_HOME", &self.home)
            .env("OPENVAULT_META_CACHE", "file")
            .env("OPENVAULT_NO_PROMPT", "1")
            .current_dir(&self.root);
        c
    }

    /// Command that can also unlock values (recovery key in env, like CI).
    fn cmd(&self) -> Command {
        let mut c = self.bare();
        c.env("OPENVAULT_IDENTITY", &self.recovery);
        c
    }

    fn add(&self, name: &str, value: &str, extra: &[&str]) {
        self.bare()
            .arg("add")
            .arg(name)
            .args(extra)
            .write_stdin(format!("{value}\n"))
            .assert()
            .success();
    }

    fn reveal(&self, name: &str) -> String {
        let out = self.cmd().args(["get", "--reveal", name]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn files(&self) -> Vec<PathBuf> {
        fn walk(p: &Path, out: &mut Vec<PathBuf>) {
            for e in fs::read_dir(p).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, out)
                } else {
                    out.push(p)
                }
            }
        }
        let mut v = vec![];
        walk(&self.home, &mut v);
        v
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

// ---------------------------------------------------------------- basics

#[test]
fn add_ls_run_roundtrip_and_exit_code() {
    let e = Env::new();
    e.add(
        "github/token",
        VALUE,
        &["--desc", "GitHub PAT", "--tag", "ci"],
    );
    e.bare()
        .arg("ls")
        .assert()
        .success()
        .stdout("github/token\n");
    e.cmd()
        .args(["run", "--only", "github/token", "--", "sh", "-c"])
        .arg("echo token=$GITHUB_TOKEN len=${#GITHUB_TOKEN}; exit 7")
        .assert()
        .code(7)
        .stdout(format!(
            "token=[REDACTED:github/token] len={}\n",
            VALUE.len()
        ));
    assert_eq!(e.reveal("github/token"), VALUE);
}

#[test]
fn ov_alias_binary_works() {
    Command::cargo_bin("ov")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("openvault"));
}

#[test]
fn add_refuses_overwrite_without_force_and_value_never_from_argv() {
    let e = Env::new();
    e.add("a/b", "first-value", &[]);
    e.bare()
        .args(["add", "a/b"])
        .write_stdin("x\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
    e.add("a/b", "second-value", &["--force"]);
    assert_eq!(e.reveal("a/b"), "second-value");
    // There is no flag that takes a value on the command line.
    e.bare()
        .args(["add", "a/c", "--value", "oops"])
        .assert()
        .failure();
}

// ---------------------------------------------------------------- agent safety

#[test]
fn get_refuses_non_tty_without_reveal() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    e.cmd()
        .args(["get", "a/b"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("openvault run"));
}

#[test]
fn reveal_requires_terminal_or_root_key() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    // A passphrase in the environment is not a human at a terminal.
    e.bare()
        .env("OPENVAULT_PASSPHRASE", "correct horse battery staple")
        .args(["get", "--reveal", "a/b"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("human at a terminal"));
}

#[test]
fn run_redacts_encodings_and_split_writes() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    let script = r#"
        printf '%s\n' "$A_B" | base64
        printf '%s' "$A_B" | od -An -tx1 | tr -d ' \n'; echo
        printf 'u:%s@h' "$A_B" | base64
        for c in $(printf '%s' "$A_B" | fold -w1); do printf '%s' "$c"; sleep 0.01; done; echo
        printf '%s' "$A_B" >&2
    "#;
    let out = e
        .cmd()
        .args(["run", "--only", "a/b", "--", "sh", "-c", script])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(VALUE) && !stderr.contains(VALUE));
    assert!(!stdout.contains("0123456789"), "{stdout}");
    assert_eq!(stdout.matches("[REDACTED:a/b]").count(), 4, "{stdout}");
    assert!(stderr.contains("[REDACTED:a/b]"));
}

#[test]
fn child_env_is_scrubbed_and_clean_env_is_minimal() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    e.cmd()
        .env("SOME_VAR", "visible")
        .args(["run", "--only", "a/b", "--", "sh", "-c"])
        .arg("echo id=${OPENVAULT_IDENTITY:-none} some=${SOME_VAR:-none}")
        .assert()
        .success()
        .stdout("id=none some=visible\n");
    e.cmd()
        .env("SOME_VAR", "visible")
        .args(["run", "--clean-env", "--only", "a/b", "--", "sh", "-c"])
        .arg("echo some=${SOME_VAR:-none} has=${A_B:+yes}")
        .assert()
        .success()
        .stdout("some=none has=yes\n");
}

#[test]
fn no_redact_requires_a_terminal() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    e.cmd()
        .args(["run", "--no-redact", "--only", "a/b", "--", "env"])
        .assert()
        .failure()
        .stdout("");
}

#[test]
fn child_runs_without_core_dumps() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    e.cmd()
        .args(["run", "--only", "a/b", "--", "sh", "-c", "ulimit -c"])
        .assert()
        .success()
        .stdout("0\n");
}

#[test]
fn secret_refs_in_env_are_resolved() {
    let e = Env::new();
    e.add("db/password", VALUE, &[]);
    e.cmd()
        .env("PGPASSWORD", "secret://db/password")
        .args(["run", "--", "sh", "-c", "echo ${#PGPASSWORD} $PGPASSWORD"])
        .assert()
        .success()
        .stdout(format!("{} [REDACTED:db/password]\n", VALUE.len()));
}

// ---------------------------------------------------------------- discovery

#[test]
fn search_and_env_never_show_values() {
    let e = Env::new();
    e.add(
        "github/token",
        VALUE,
        &["--desc", "GitHub PAT for CI", "--tag", "ci"],
    );
    e.add(
        "openai/key",
        "sk-fake-openai-0000",
        &["--env", "OPENAI_API_KEY", "--desc", "LLM key"],
    );
    let out = e
        .bare()
        .args(["search", "github", "--json"])
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("secret://github/token") && !s.contains(VALUE));
    e.bare()
        .args(["search", "llm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OPENAI_API_KEY"));
    e.bare().args(["env"]).assert().success().stdout(
        predicate::str::contains("GITHUB_TOKEN").and(predicate::str::contains("OPENAI_API_KEY")),
    );
    e.cmd()
        .args([
            "run",
            "--env",
            "OPENAI_API_KEY",
            "--",
            "sh",
            "-c",
            "echo ${#OPENAI_API_KEY}",
        ])
        .assert()
        .success()
        .stdout("19\n");
}

#[test]
fn add_meta_only_updates_metadata_and_keeps_value() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    e.bare()
        .args([
            "add",
            "a/b",
            "--meta-only",
            "--env",
            "CUSTOM",
            "--desc",
            "edited",
        ])
        .assert()
        .success();
    e.bare()
        .args(["search", "edited"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CUSTOM"));
    assert_eq!(e.reveal("a/b"), VALUE);
}

// ---------------------------------------------------------------- policy

#[test]
fn project_policy_maps_env_and_blocks_others() {
    let e = Env::new();
    e.add("github/token", VALUE, &[]);
    e.add("aws/key", "aws-fake-secret-1", &[]);
    let proj = e.root.join("proj");
    fs::create_dir(&proj).unwrap();
    fs::write(
        proj.join(".openvault.toml"),
        "[env]\nGH = \"secret://github/token\"\n",
    )
    .unwrap();
    e.cmd()
        .current_dir(&proj)
        .args(["run", "--", "sh", "-c", "echo ${#GH}"])
        .assert()
        .success()
        .stdout(format!("{}\n", VALUE.len()));
    e.cmd()
        .current_dir(&proj)
        .args(["run", "--only", "aws/key", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not allowed in this project"));
    e.cmd()
        .current_dir(&proj)
        .args(["get", "--reveal", "aws/key"])
        .assert()
        .failure();
    // Denials are audited.
    let log = fs::read_to_string(e.home.join("audit.log")).unwrap();
    assert!(log.contains("\"ok\":false") && log.contains("aws/key"));
    // `env` only shows what the project may use.
    e.bare()
        .current_dir(&proj)
        .arg("env")
        .assert()
        .success()
        .stdout(predicate::str::contains("GH").and(predicate::str::contains("aws").not()));
}

#[test]
fn world_writable_policy_file_is_refused() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    let proj = e.root.join("p");
    fs::create_dir(&proj).unwrap();
    let f = proj.join(".openvault.toml");
    fs::write(&f, "allow = [\"**\"]\n").unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o666)).unwrap();
    e.cmd()
        .current_dir(&proj)
        .args(["run", "--only", "a/b", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("writable by group/other"));
}

#[test]
fn scoped_secret_cannot_be_used_elsewhere() {
    let e = Env::new();
    let a = e.root.join("a");
    let b = e.root.join("b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    e.add("proj/db", VALUE, &["--scope", a.to_str().unwrap()]);
    e.cmd()
        .current_dir(&a)
        .args(["run", "--only", "proj/db", "--", "true"])
        .assert()
        .success();
    e.cmd()
        .current_dir(&b)
        .args(["run", "--only", "proj/db", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("scoped"));
}

#[test]
fn confirm_tag_rejects_non_interactive_unlock() {
    let e = Env::new();
    e.add("prod/db", VALUE, &["--tag", "confirm"]);
    // Root key in env is not enough for a `confirm` secret; a human must unlock.
    e.cmd()
        .env("OPENVAULT_PASSPHRASE", "correct horse battery staple")
        .args(["run", "--only", "prod/db", "--", "true"])
        .assert()
        .failure();
}

// ---------------------------------------------------------------- storage

#[test]
fn nothing_in_the_vault_reveals_names_or_values() {
    let e = Env::new();
    e.add(
        "github/token",
        VALUE,
        &["--desc", "very-identifiable-description"],
    );
    for f in e.files() {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let bytes = fs::read(&f).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(VALUE), "value leaked in {f:?}");
        if name == "audit.log" {
            continue; // local-only, gitignored; contains refs but never values
        }
        assert!(!text.contains("github"), "name leaked in {f:?}");
        assert!(
            !text.contains("very-identifiable"),
            "metadata leaked in {f:?}"
        );
        assert!(!f.to_string_lossy().contains("github"));
        let mode = fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{f:?} has mode {mode:o}");
    }
    let mode = fs::metadata(&e.home).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn loose_permissions_are_refused() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    fs::set_permissions(&e.home, fs::Permissions::from_mode(0o755)).unwrap();
    e.bare()
        .arg("ls")
        .assert()
        .failure()
        .stderr(predicate::str::contains("too open"));
}

#[test]
fn swapped_ciphertexts_are_detected() {
    let e = Env::new();
    e.add("a/one", "value-number-one", &[]);
    e.add("a/two", "value-number-two", &[]);
    let mut vfiles: Vec<PathBuf> = fs::read_dir(e.home.join("v"))
        .unwrap()
        .map(|d| d.unwrap().path())
        .collect();
    vfiles.sort();
    let a = fs::read(&vfiles[0]).unwrap();
    fs::write(&vfiles[1], a).unwrap();
    let both = e
        .cmd()
        .args(["run", "--only", "a/one,a/two", "--", "true"])
        .output()
        .unwrap();
    assert!(!both.status.success());
    assert!(String::from_utf8_lossy(&both.stderr).contains("swapped"));
}

#[test]
fn audit_log_is_hash_chained() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    e.cmd()
        .args(["run", "--only", "a/b", "--", "true"])
        .assert()
        .success();
    e.bare()
        .args(["audit", "verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 entries"));
    let log = e.home.join("audit.log");
    let text = fs::read_to_string(&log).unwrap();
    assert!(!text.contains(VALUE));
    assert!(text.contains("\"op\":\"run\""));
    fs::write(&log, text.replacen("\"op\":\"add\"", "\"op\":\"xxx\"", 1)).unwrap();
    e.bare().args(["audit", "verify"]).assert().failure();
}

#[test]
fn wrong_recovery_key_is_rejected() {
    let e = Env::new();
    e.add("a/b", VALUE, &[]);
    e.bare()
        .env(
            "OPENVAULT_IDENTITY",
            "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQSM5EKZ",
        )
        .args(["run", "--only", "a/b", "--", "true"])
        .assert()
        .failure();
}

// ---------------------------------------------------------------- import

fn import_names(e: &Env, args: &[&str]) -> String {
    let out = e.bare().arg("import").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn import_each_format_dry_run_then_real() {
    let cases: &[(&str, &[&str], &str)] = &[
        (
            "bitwarden.json",
            &[
                "github/password",
                "github/api-key",
                "github-2/password",
                "visa-card/number",
                "server-notes/notes",
            ],
            "bw-fake-github-pass",
        ),
        (
            "export.1pux",
            &[
                "github/password",
                "github/totp",
                "github/api-token",
                "home-wi-fi/password",
            ],
            "1pux-fake-github-pass",
        ),
        (
            "1password.csv",
            &["github/password", "github/username", "aws-console/totp"],
            "op-fake-github-pass",
        ),
        (
            "apple.csv",
            &["example.com-alice/password", "bank/totp", "bank/notes"],
            "apple-fake-pass-1",
        ),
        (
            "lastpass.csv",
            &["news-site/password", "home-wifi/notes"],
            "lp-fake-pass-1",
        ),
    ];
    for (file, expect, first_pw) in cases {
        let e = Env::new();
        let f = fixture(file);
        let dry = import_names(&e, &[f.to_str().unwrap(), "--dry-run"]);
        for n in *expect {
            assert!(dry.contains(n), "{file}: {n} missing from preview:\n{dry}");
        }
        assert!(!dry.contains(first_pw), "{file}: preview leaked a value");
        e.bare().arg("ls").assert().success().stdout("");
        import_names(&e, &[f.to_str().unwrap()]);
        let ls = String::from_utf8(e.bare().arg("ls").output().unwrap().stdout).unwrap();
        for n in *expect {
            assert!(
                ls.lines().any(|l| l == *n),
                "{file}: {n} not imported:\n{ls}"
            );
        }
        let pw = expect[0];
        assert_eq!(e.reveal(pw), *first_pw, "{file}");
    }
}

#[test]
fn onepassword_csv_skips_archived_and_lastpass_notes_drop_sn_url() {
    let e = Env::new();
    let out = import_names(
        &e,
        &[fixture("1password.csv").to_str().unwrap(), "--dry-run"],
    );
    assert!(!out.contains("old-thing"));
    let out = import_names(
        &e,
        &[fixture("lastpass.csv").to_str().unwrap(), "--dry-run"],
    );
    assert!(out.contains("home-wifi/notes"));
}

#[test]
fn dotenv_import_fills_env_names_for_discovery() {
    let e = Env::new();
    let out = import_names(
        &e,
        &[
            "--from-env-file",
            fixture("sample.env").to_str().unwrap(),
            "--prefix",
            "myapp",
        ],
    );
    assert!(out.contains("myapp/database_url"));
    e.bare().arg("env").assert().success().stdout(
        predicate::str::contains("DATABASE_URL").and(predicate::str::contains("OPENAI_API_KEY")),
    );
    e.cmd()
        .args([
            "run",
            "--env",
            "OPENAI_API_KEY,STRIPE_SECRET",
            "--",
            "sh",
            "-c",
            "echo $OPENAI_API_KEY ${#STRIPE_SECRET}",
        ])
        .assert()
        .success()
        .stdout("[REDACTED:myapp/openai_api_key] 23\n");
}

#[test]
fn import_conflicts_and_undo() {
    let e = Env::new();
    let f = fixture("apple.csv");
    let f = f.to_str().unwrap();
    e.add("bank/password", "my-own-bank-pass", &[]);
    // skip (default) leaves the existing secret alone
    let out = import_names(&e, &[f]);
    assert!(out.contains("skip"));
    assert_eq!(e.reveal("bank/password"), "my-own-bank-pass");
    e.bare()
        .args(["import", "--undo", "last"])
        .assert()
        .success();
    // rename
    let out = import_names(&e, &[f, "--on-conflict", "rename"]);
    assert!(out.contains("bank/password-2"));
    assert_eq!(e.reveal("bank/password-2"), "apple-fake-pass-2");
    e.bare()
        .args(["import", "--undo", "last"])
        .assert()
        .success();
    e.bare()
        .args(["ls", "bank"])
        .assert()
        .success()
        .stdout("bank/password\n");
    // overwrite, then undo restores the original value
    import_names(&e, &[f, "--on-conflict", "overwrite"]);
    assert_eq!(e.reveal("bank/password"), "apple-fake-pass-2");
    e.bare()
        .args(["import", "--undo", "last"])
        .assert()
        .success();
    assert_eq!(e.reveal("bank/password"), "my-own-bank-pass");
    e.bare()
        .args(["ls"])
        .assert()
        .success()
        .stdout("bank/password\n");
}

#[test]
fn import_rejects_encrypted_bitwarden_and_oversized_files() {
    let e = Env::new();
    e.bare()
        .args([
            "import",
            fixture("bitwarden-encrypted.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("encrypted Bitwarden export"));
    let big = e.root.join("big.csv");
    let f = fs::File::create(&big).unwrap();
    f.set_len(65 * 1024 * 1024).unwrap();
    e.bare()
        .args(["import", big.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("larger than"));
}

#[test]
fn import_shred_removes_plaintext_export() {
    let e = Env::new();
    let copy = e.root.join("export.csv");
    fs::copy(fixture("apple.csv"), &copy).unwrap();
    e.bare()
        .args(["import", copy.to_str().unwrap(), "--shred"])
        .assert()
        .success();
    assert!(!copy.exists());
}

// ---------------------------------------------------------------- MCP

#[test]
fn mcp_server_searches_and_runs_without_returning_values() {
    let e = Env::new();
    e.add("github/token", VALUE, &["--desc", "GitHub PAT"]);
    let bin = assert_cmd::cargo::cargo_bin("openvault");
    let mut child = std::process::Command::new(bin)
        .arg("mcp")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", &e.root)
        .env("OPENVAULT_HOME", &e.home)
        .env("OPENVAULT_META_CACHE", "file")
        .env("OPENVAULT_IDENTITY", &e.recovery)
        .current_dir(&e.root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut rpc = |id: u32, method: &str, params: serde_json::Value| -> serde_json::Value {
        let req = serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        writeln!(stdin, "{req}").unwrap();
        let line = lines.next().unwrap().unwrap();
        assert!(!line.contains(VALUE), "MCP leaked a value: {line}");
        serde_json::from_str(&line).unwrap()
    };
    let init = rpc(
        1,
        "initialize",
        serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "openvault");
    let tools = rpc(2, "tools/list", serde_json::json!({}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["search", "list_env", "run"]);
    let s = rpc(
        3,
        "tools/call",
        serde_json::json!({"name":"search","arguments":{"query":"github"}}),
    );
    assert!(s["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("secret://github/token"));
    let r = rpc(
        4,
        "tools/call",
        serde_json::json!({"name":"run","arguments":{
            "command":["sh","-c","echo $GITHUB_TOKEN; printf %s \"$GITHUB_TOKEN\" | base64"],
            "env":["GITHUB_TOKEN"],
            "cwd": e.root.to_str().unwrap()
        }}),
    );
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("[REDACTED:github/token]"), "{text}");
    assert_eq!(r["result"]["isError"], false);
    let bad = rpc(
        5,
        "tools/call",
        serde_json::json!({"name":"get","arguments":{"name":"github/token"}}),
    );
    assert_eq!(bad["result"]["isError"], true);
    drop(stdin);
    child.wait().unwrap();
}
