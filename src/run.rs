//! `openvault run`: resolve refs / env vars, enforce policy, unlock once,
//! inject values into the child's environment, and redact them from its output.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::audit;
use crate::discover;
use crate::names;
use crate::platform::{self, SecretBuf};
use crate::policy::{self, Project};
use crate::redact::Redactor;
use crate::unlock::{self, Auth};
use crate::vault::{Meta, MetaKeys, Vault};

/// Variables passed through by `--clean-env` (and to every MCP-launched child).
const CLEAN_ENV_KEEP: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR",
    "TZ",
];

#[derive(Default, Debug)]
pub struct Request {
    /// `ref` or `VAR=ref`
    pub only: Vec<String>,
    /// env var names
    pub env: Vec<String>,
    pub cwd: PathBuf,
    /// The environment the child would inherit (used for `secret://` resolution).
    pub inherited: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Injection {
    pub var: String,
    pub name: String,
}

fn push(out: &mut Vec<Injection>, var: String, name: String) -> Result<()> {
    names::validate_env_var(&var)?;
    names::validate(&name)?;
    if let Some(prev) = out.iter().find(|i| i.var == var) {
        if prev.name != name {
            bail!("{var} requested twice ({} and {name})", prev.name);
        }
        return Ok(());
    }
    out.push(Injection { var, name });
    Ok(())
}

/// Work out which secret goes into which variable.
pub fn plan(all: &[Meta], project: Option<&Project>, req: &Request) -> Result<Vec<Injection>> {
    let mut out: Vec<Injection> = Vec::new();
    let meta_env = |name: &str| {
        all.iter()
            .find(|m| m.name == name)
            .map(|m| m.env_var())
            .unwrap_or_else(|| names::env_var_for(name))
    };
    for item in &req.only {
        for part in item.split(',').filter(|s| !s.trim().is_empty()) {
            let part = part.trim();
            let (var, r) = match part.split_once('=') {
                Some((v, r)) => (v.to_string(), r),
                None => (String::new(), part),
            };
            let name = names::strip_ref(r).to_string();
            let var = if var.is_empty() { meta_env(&name) } else { var };
            push(&mut out, var, name)?;
        }
    }
    for item in &req.env {
        for var in item.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let name = discover::resolve_var(all, project, &req.cwd, var)?;
            push(&mut out, var.to_string(), name)?;
        }
    }
    if req.only.is_empty() && req.env.is_empty() {
        if let Some(p) = project {
            for (var, name) in &p.env {
                push(&mut out, var.clone(), name.clone())?;
            }
        }
    }
    for (k, v) in &req.inherited {
        if let Some(r) = v.strip_prefix(names::REF_SCHEME) {
            if !out.iter().any(|i| &i.var == k) {
                push(&mut out, k.clone(), r.to_string())?;
            }
        }
    }
    Ok(out)
}

/// Policy: project allowlist + per-secret directory scope.
pub fn check_access(meta: &Meta, project: Option<&Project>, cwd: &Path) -> Result<()> {
    if let Some(p) = project {
        if !p.allows(&meta.name) {
            bail!(
                "{} is not allowed in this project (see {}); add it to `allow` or [env]",
                meta.name,
                p.file.display()
            );
        }
    }
    if !meta.in_scope(cwd) {
        bail!(
            "{} is scoped to {} and cannot be used from {}",
            meta.name,
            meta.scope.join(", "),
            cwd.display()
        );
    }
    Ok(())
}

pub struct Prepared {
    pub values: Vec<(String, String, SecretBuf)>, // (var, name, value)
    pub auth: Auth,
}

/// Resolve, authorise, unlock and decrypt. Writes the audit record.
pub fn prepare(v: &Vault, mk: &MetaKeys, req: &Request, via: &str) -> Result<Prepared> {
    let project = policy::find(&req.cwd)?;
    // Only `--env VAR` lookups need every secret's metadata; otherwise decrypt
    // just the metadata of the refs involved (keeps `run --only` fast).
    let all = if req.env.is_empty() {
        let mut wanted: Vec<String> = req
            .only
            .iter()
            .flat_map(|o| o.split(','))
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| names::strip_ref(p.split_once('=').map(|x| x.1).unwrap_or(p)).to_string())
            .collect();
        wanted.extend(project.iter().flat_map(|p| p.env.values().cloned()));
        wanted.extend(
            req.inherited
                .iter()
                .filter_map(|(_, v)| v.strip_prefix(names::REF_SCHEME).map(String::from)),
        );
        wanted.sort();
        wanted.dedup();
        let mut metas = Vec::new();
        for n in wanted {
            if names::validate(&n).is_ok() {
                if let Some(m) = v.read_meta(mk, &n)? {
                    metas.push(m);
                }
            }
        }
        metas
    } else {
        v.all_meta(mk)?
    };
    let inj = plan(&all, project.as_ref(), req)?;
    let names: Vec<String> = inj.iter().map(|i| i.name.clone()).collect();
    let mut confirm = false;
    for i in &inj {
        let res = match all.iter().find(|m| m.name == i.name) {
            None => Err(anyhow::anyhow!("no secret named {}", i.name)),
            Some(m) => {
                confirm |= m.needs_confirm(
                    project
                        .as_ref()
                        .map(|p| p.confirm_tags.as_slice())
                        .unwrap_or(&[]),
                );
                check_access(m, project.as_ref(), &req.cwd)
            }
        };
        if let Err(e) = res {
            let _ = audit::record(&v.home, "run", &names, false, Some(e.to_string()), via);
            return Err(e);
        }
    }
    if inj.is_empty() {
        return Ok(Prepared {
            values: vec![],
            auth: Auth::Environment,
        });
    }
    let vk = unlock::value_key(v, confirm).inspect_err(|e| {
        let _ = audit::record(
            &v.home,
            "run",
            &names,
            false,
            Some(format!("unlock: {e}")),
            via,
        );
    })?;
    let mut values = Vec::new();
    for i in &inj {
        let val = v.read_value(mk, &vk.identity, &i.name)?;
        if val.as_bytes().contains(&0) {
            bail!(
                "{} contains a NUL byte and cannot be passed as an environment variable",
                i.name
            );
        }
        values.push((i.var.clone(), i.name.clone(), val));
    }
    audit::record(&v.home, "run", &names, true, None, via)?;
    Ok(Prepared {
        values,
        auth: vk.auth,
    })
}

pub fn build_command(
    argv: &[String],
    p: &Prepared,
    clean_env: bool,
    cwd: Option<&Path>,
) -> Result<Command> {
    let (prog, args) = argv.split_first().context("no command given")?;
    let mut cmd = Command::new(prog);
    cmd.args(args);
    if let Some(c) = cwd {
        cmd.current_dir(c);
    }
    if clean_env {
        cmd.env_clear();
        for k in CLEAN_ENV_KEEP {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
    } else {
        for (k, v) in std::env::vars_os() {
            let ks = k.to_string_lossy();
            let is_ref = v.as_bytes().starts_with(names::REF_SCHEME.as_bytes());
            if (ks.starts_with("OPENVAULT_") && ks != "OPENVAULT_HOME") || is_ref {
                cmd.env_remove(&k);
            }
        }
    }
    for (var, _, val) in &p.values {
        cmd.env(var, OsStr::from_bytes(val.as_bytes()));
    }
    Ok(cmd)
}

fn redactors(p: &Prepared) -> (Redactor, Redactor, Vec<String>) {
    let s: Vec<(String, &[u8])> = p
        .values
        .iter()
        .map(|(_, n, v)| (n.clone(), v.as_bytes()))
        .collect();
    let (a, skipped) = Redactor::new(&s);
    let (b, _) = Redactor::new(&s);
    (a, b, skipped)
}

pub fn exit_code(st: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(1))
}

fn pump<R: Read, W: Write>(mut src: R, mut dst: W, mut red: Redactor) {
    let mut buf = [0u8; 8192];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let out = red.push(&buf[..n]);
                if dst.write_all(&out).and_then(|_| dst.flush()).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = dst.write_all(&red.finish());
    let _ = dst.flush();
}

/// Run with stdout/stderr streamed through the redactor. Returns the exit code.
pub fn run_streaming(mut cmd: Command, p: &Prepared) -> Result<i32> {
    let (r_out, r_err, skipped) = redactors(p);
    for s in skipped {
        eprintln!("openvault: warning: {s} is shorter than 4 bytes and will not be redacted");
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("failed to start command")?;
    platform::ignore_terminal_signals();
    let out = child.stdout.take().expect("piped");
    let err = child.stderr.take().expect("piped");
    let t1 = std::thread::spawn(move || pump(out, std::io::stdout(), r_out));
    let t2 = std::thread::spawn(move || pump(err, std::io::stderr(), r_err));
    let st = child.wait()?;
    let _ = t1.join();
    let _ = t2.join();
    Ok(exit_code(st))
}

/// Replace this process with the command (no redaction).
pub fn exec(mut cmd: Command) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    Err(anyhow::anyhow!("failed to exec: {err}"))
}

pub struct Captured {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

const CAPTURE_LIMIT: usize = 256 * 1024;

fn collect<R: Read>(mut src: R, mut red: Redactor) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let o = red.push(&buf[..n]);
                if out.len() < CAPTURE_LIMIT {
                    out.extend_from_slice(&o);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    out.extend(red.finish());
    if out.len() > CAPTURE_LIMIT {
        out.truncate(CAPTURE_LIMIT);
        out.extend_from_slice(b"\n[openvault: output truncated]\n");
    }
    out
}

/// Run with captured, redacted output (for the MCP server).
pub fn run_captured(mut cmd: Command, p: &Prepared, timeout: Duration) -> Result<Captured> {
    let (r_out, r_err, _) = redactors(p);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("failed to start command")?;
    let out = child.stdout.take().expect("piped");
    let err = child.stderr.take().expect("piped");
    let t1 = std::thread::spawn(move || collect(out, r_out));
    let t2 = std::thread::spawn(move || collect(err, r_err));
    let start = Instant::now();
    let mut timed_out = false;
    let st = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            timed_out = true;
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = String::from_utf8_lossy(&t1.join().unwrap_or_default()).to_string();
    let stderr = String::from_utf8_lossy(&t2.join().unwrap_or_default()).to_string();
    Ok(Captured {
        code: exit_code(st),
        stdout,
        stderr,
        timed_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn m(name: &str, env: Option<&str>) -> Meta {
        Meta {
            name: name.into(),
            env: env.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn plans_only_env_project_and_refs() {
        let all = vec![
            m("github/token", None),
            m("openai/key", Some("OPENAI_API_KEY")),
        ];
        let req = Request {
            only: vec!["github/token,X=secret://openai/key".into()],
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let p = plan(&all, None, &req).unwrap();
        assert_eq!(
            p,
            vec![
                Injection {
                    var: "GITHUB_TOKEN".into(),
                    name: "github/token".into()
                },
                Injection {
                    var: "X".into(),
                    name: "openai/key".into()
                },
            ]
        );
        let req = Request {
            env: vec!["OPENAI_API_KEY".into()],
            inherited: vec![("DB".into(), "secret://github/token".into())],
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let p = plan(&all, None, &req).unwrap();
        assert_eq!(p[0].name, "openai/key");
        assert_eq!(p[1].var, "DB");

        let mut env = BTreeMap::new();
        env.insert("GH".to_string(), "github/token".to_string());
        let proj = Project {
            file: "/p/.openvault.toml".into(),
            root: "/p".into(),
            allow: vec!["github/token".into()],
            confirm_tags: vec![],
            env,
        };
        let req = Request {
            cwd: "/p".into(),
            ..Default::default()
        };
        assert_eq!(plan(&all, Some(&proj), &req).unwrap()[0].var, "GH");
        assert!(check_access(&all[1], Some(&proj), Path::new("/p")).is_err());
        assert!(check_access(&all[0], Some(&proj), Path::new("/p")).is_ok());
    }

    #[test]
    fn rejects_reserved_and_conflicting_vars() {
        let all = vec![m("a/b", None), m("c/d", None)];
        let req = Request {
            only: vec!["OPENVAULT_IDENTITY=a/b".into()],
            ..Default::default()
        };
        assert!(plan(&all, None, &req).is_err());
        let req = Request {
            only: vec!["X=a/b".into(), "X=c/d".into()],
            ..Default::default()
        };
        assert!(plan(&all, None, &req).is_err());
    }
}
