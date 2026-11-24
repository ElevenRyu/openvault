//! Command-line interface.

use std::collections::BTreeSet;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::audit;
use crate::discover;
use crate::import::{self, Conflict, Format};
use crate::mcp;
use crate::names;
use crate::platform::{self, SecretBuf};
use crate::policy;
use crate::run::{self, Request};
use crate::unlock::{self, Auth};
use crate::util;
use crate::vault::{self, Meta, Vault};

#[derive(Parser)]
#[command(
    name = "openvault",
    version,
    about = "Agent-safe secrets vault: age-encrypted, Touch ID gated, no daemon.",
    long_about = "openvault keeps secrets as age-encrypted files and hands them to programs \
                  (and AI agents) as environment variables without ever showing the values.\n\n\
                  Quick start:\n  openvault init\n  openvault add github/token --env GITHUB_TOKEN\n  \
                  openvault run --env GITHUB_TOKEN -- gh api user"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a vault and print the paper recovery key.
    Init {
        /// How the value key is unlocked: se (Secure Enclave + Touch ID) or passphrase.
        #[arg(long)]
        unlock: Option<String>,
        /// Secure Enclave access control (age-plugin-se): any-biometry, current-biometry,
        /// any-biometry-or-passcode, passcode, none, ...
        #[arg(long, default_value = "any-biometry")]
        se_access_control: String,
        /// Write the recovery key to this file (0600) instead of the terminal.
        #[arg(long)]
        recovery_file: Option<PathBuf>,
        /// Allow printing the recovery key to a non-terminal stdout.
        #[arg(long)]
        reveal: bool,
    },
    /// Add or update a secret. The value is read from stdin or a hidden prompt — never argv.
    Add {
        name: String,
        /// Human description (searchable; encrypted at rest).
        #[arg(long = "desc", visible_alias = "description")]
        description: Option<String>,
        /// Tag (repeatable). The tag `confirm` forces a fresh Touch ID on every use.
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Environment variable name this secret is injected as (default: from the name).
        #[arg(long)]
        env: Option<String>,
        /// Restrict use to this directory tree (repeatable).
        #[arg(long)]
        scope: Vec<PathBuf>,
        /// Overwrite an existing value.
        #[arg(long, short)]
        force: bool,
        /// Only update metadata; keep the stored value.
        #[arg(long)]
        meta_only: bool,
    },
    /// Show a secret to a human at a terminal (Touch ID). Refuses pipes unless --reveal.
    Get {
        name: String,
        /// Print even though stdout is not a terminal. Still needs a terminal on stdin and
        /// a fresh Touch ID / passphrase (or OPENVAULT_IDENTITY, which is root access anyway).
        #[arg(long)]
        reveal: bool,
    },
    /// List secret names (decrypts metadata only).
    Ls {
        prefix: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Fuzzy-search names, env vars, descriptions and tags. Never shows values.
    Search {
        #[arg(required = true)]
        query: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// List the env vars available to a project directory.
    Env {
        /// Project directory (default: current directory).
        #[arg(long = "for")]
        dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Delete secrets.
    Rm {
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// Run a command with secrets injected as env vars; values are redacted from its output.
    Run {
        /// Secret ref to inject: `github/token`, `secret://github/token` or `VAR=ref` (repeatable, comma-separated).
        #[arg(long)]
        only: Vec<String>,
        /// Env var names to inject, resolved via .openvault.toml and secret metadata (comma-separated).
        #[arg(long)]
        env: Vec<String>,
        /// Start the child with a minimal environment (PATH, HOME, ...) plus the injected secrets.
        #[arg(long)]
        clean_env: bool,
        /// Don't redact output (exec directly). Requires an interactive terminal.
        #[arg(long)]
        no_redact: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Import from 1Password (.1pux/CSV), Bitwarden JSON, Apple Passwords CSV, LastPass CSV or .env.
    Import {
        file: Option<PathBuf>,
        /// Format (default: detected): 1pux, 1password-csv, bitwarden, apple-csv, lastpass-csv, dotenv
        #[arg(long)]
        from: Option<String>,
        /// Shorthand for `--from dotenv FILE`; env var names are kept for discovery.
        #[arg(long)]
        from_env_file: Option<PathBuf>,
        /// Prefix for every imported name, e.g. `bw` -> bw/github/password.
        #[arg(long)]
        prefix: Option<String>,
        /// Extra tag for every imported secret (repeatable).
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Show what would happen; write nothing.
        #[arg(long)]
        dry_run: bool,
        /// When a name already exists: skip, overwrite or rename.
        #[arg(long, default_value = "skip")]
        on_conflict: String,
        /// Revert an import batch (`last` for the most recent).
        #[arg(long, conflicts_with_all = ["file", "from_env_file", "dry_run"])]
        undo: Option<String>,
        /// Overwrite and delete the plaintext export after a successful import.
        #[arg(long)]
        shred: bool,
    },
    /// Show the audit log, or `audit verify` to check its hash chain.
    Audit {
        action: Option<String>,
        #[arg(short, default_value_t = 20)]
        n: usize,
    },
    /// Serve the agent tools (search, list_env, run) over MCP stdio.
    Mcp,
}

pub fn main() -> i32 {
    platform::harden_process();
    let cli = Cli::parse();
    match dispatch(cli.cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("openvault: {e:#}");
            1
        }
    }
}

fn cwd() -> Result<PathBuf> {
    Ok(std::env::current_dir()?.canonicalize()?)
}

fn dispatch(cmd: Cmd) -> Result<i32> {
    match cmd {
        Cmd::Init {
            unlock,
            se_access_control,
            recovery_file,
            reveal,
        } => cmd_init(unlock, se_access_control, recovery_file, reveal),
        Cmd::Add {
            name,
            description,
            tags,
            env,
            scope,
            force,
            meta_only,
        } => cmd_add(&name, description, tags, env, scope, force, meta_only),
        Cmd::Get { name, reveal } => cmd_get(&name, reveal),
        Cmd::Ls { prefix, json } => cmd_ls(prefix, json),
        Cmd::Search { query, json, limit } => cmd_search(&query.join(" "), json, limit),
        Cmd::Env { dir, json } => cmd_env(dir, json),
        Cmd::Rm { names } => cmd_rm(&names),
        Cmd::Run {
            only,
            env,
            clean_env,
            no_redact,
            command,
        } => cmd_run(only, env, clean_env, no_redact, command),
        Cmd::Import {
            file,
            from,
            from_env_file,
            prefix,
            tags,
            dry_run,
            on_conflict,
            undo,
            shred,
        } => cmd_import(
            file,
            from,
            from_env_file,
            prefix,
            tags,
            dry_run,
            &on_conflict,
            undo,
            shred,
        ),
        Cmd::Audit { action, n } => cmd_audit(action.as_deref(), n),
        Cmd::Mcp => {
            mcp::serve()?;
            Ok(0)
        }
    }
}

fn cmd_init(
    unlock_m: Option<String>,
    se_ac: String,
    recovery_file: Option<PathBuf>,
    reveal: bool,
) -> Result<i32> {
    if recovery_file.is_none() && !reveal && !util::stdout_is_tty() {
        bail!("refusing to print the recovery key to a non-terminal; use --recovery-file PATH (or --reveal)");
    }
    let home = vault::home_dir()?;
    let res = unlock::init(
        &home,
        &unlock::InitOptions {
            unlock: unlock_m,
            se_access_control: se_ac,
        },
    )?;
    eprintln!(
        "openvault: vault created at {} (values unlock with: {}, metadata cache: {})",
        home.display(),
        if res.unlock == "se" {
            "Secure Enclave / Touch ID"
        } else {
            "passphrase"
        },
        res.meta_cache
    );
    match recovery_file {
        Some(p) => {
            util::write_atomic(
                &p,
                format!("{}\n", res.recovery_key.expose_secret()).as_bytes(),
            )?;
            eprintln!("openvault: recovery key written to {} — print it, store it offline, then delete the file.", p.display());
        }
        None => {
            println!(
                "\nRECOVERY KEY — write this down and keep it offline. It decrypts everything:\n"
            );
            println!("    {}\n", res.recovery_key.expose_secret());
            println!("To recover: OPENVAULT_IDENTITY=<key> openvault ...   (or plain `age -d -i` on keys/recovery.age)");
        }
    }
    Ok(0)
}

fn read_value(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut v = if io::stdin().is_terminal() {
        let s = rpassword::prompt_password(format!("Value for {name} (hidden): "))?;
        Zeroizing::new(s.into_bytes())
    } else {
        let mut buf = Zeroizing::new(Vec::new());
        io::stdin()
            .take(vault::MAX_VALUE_LEN as u64 + 2)
            .read_to_end(&mut buf)?;
        if buf.ends_with(b"\r\n") {
            let n = buf.len() - 2;
            buf.truncate(n);
        } else if buf.ends_with(b"\n") {
            let n = buf.len() - 1;
            buf.truncate(n);
        }
        buf
    };
    if v.is_empty() {
        bail!("empty value; nothing stored");
    }
    if v.len() > vault::MAX_VALUE_LEN {
        v.clear();
        bail!("value too large (max {} bytes)", vault::MAX_VALUE_LEN);
    }
    Ok(v)
}

fn cmd_add(
    name: &str,
    description: Option<String>,
    tags: Vec<String>,
    env: Option<String>,
    scope: Vec<PathBuf>,
    force: bool,
    meta_only: bool,
) -> Result<i32> {
    let name = names::strip_ref(name);
    names::validate(name)?;
    if let Some(e) = &env {
        names::validate_env_var(e)?;
    }
    let v = Vault::open()?;
    let mk = unlock::meta_keys(&v)?;
    let existing = v.read_meta(&mk, name)?;
    if meta_only && existing.is_none() {
        bail!("{name} does not exist");
    }
    if existing.is_some() && !force && !meta_only {
        bail!("{name} already exists; use --force to replace its value or --meta-only to edit metadata");
    }
    let now = util::now_utc();
    let mut meta = existing.unwrap_or_else(|| {
        let mut m = Meta::new(name);
        m.created = Some(now.clone());
        m
    });
    if description.is_some() {
        meta.description = description;
    }
    if !tags.is_empty() {
        meta.tags = tags.iter().map(|t| names::slug(t)).collect();
    }
    if env.is_some() {
        meta.env = env;
    }
    if !scope.is_empty() {
        meta.scope = scope
            .iter()
            .map(|s| s.canonicalize().map(|p| p.display().to_string()))
            .collect::<std::io::Result<_>>()
            .context("--scope must be an existing directory")?;
    }
    meta.updated = Some(now);
    if meta_only {
        v.put_meta(&mk, &meta)?;
        eprintln!("openvault: updated metadata for {name}");
    } else {
        let value = read_value(name)?;
        v.put(&mk, &meta, &value)?;
        eprintln!("openvault: stored {name} (env: {})", meta.env_var());
    }
    audit::record(
        &v.home,
        if meta_only { "meta" } else { "add" },
        &[name.to_string()],
        true,
        None,
        "cli",
    )?;
    Ok(0)
}

fn cmd_get(name: &str, reveal: bool) -> Result<i32> {
    let name = names::strip_ref(name).to_string();
    names::validate(&name)?;
    let v = Vault::open()?;
    let env_key = std::env::var_os(unlock::ENV_IDENTITY).is_some();
    let to_tty = util::stdout_is_tty();
    let refuse = |why: &str| -> Result<i32> {
        let _ = audit::record(
            &v.home,
            "get",
            std::slice::from_ref(&name),
            false,
            Some(why.to_string()),
            "cli",
        );
        bail!(
            "{why}. Secrets are never printed for programs or agents: use \
             `openvault run --only {name} -- <cmd>` to inject it instead"
        )
    };
    if !to_tty && !reveal {
        return refuse("refusing to print a secret to a non-terminal (pipe, file or agent)");
    }
    if reveal && !to_tty && !env_key && !util::stdin_is_tty() {
        return refuse("--reveal needs a human at a terminal (stdin is not a terminal)");
    }
    let mk = unlock::meta_keys(&v)?;
    let meta = v
        .read_meta(&mk, &name)?
        .with_context(|| format!("no secret named {name}"))?;
    let cwd = cwd()?;
    let project = policy::find(&cwd)?;
    if let Err(e) = run::check_access(&meta, project.as_ref(), &cwd) {
        return refuse(&e.to_string());
    }
    let confirm = meta.needs_confirm(
        project
            .as_ref()
            .map(|p| p.confirm_tags.as_slice())
            .unwrap_or(&[]),
    );
    let vk = unlock::value_key(&v, confirm)?;
    if vk.auth == Auth::Interactive && !util::stdin_is_tty() && !to_tty {
        return refuse("--reveal needs a human at a terminal");
    }
    let value: SecretBuf = v.read_value(&mk, &vk.identity, &name)?;
    audit::record(
        &v.home,
        "get",
        std::slice::from_ref(&name),
        true,
        Some(if reveal {
            "reveal".into()
        } else {
            "tty".into()
        }),
        "cli",
    )?;
    let mut out = io::stdout().lock();
    out.write_all(value.as_bytes())?;
    if to_tty {
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(0)
}

fn cmd_ls(prefix: Option<String>, json: bool) -> Result<i32> {
    let v = Vault::open()?;
    let mk = unlock::meta_keys(&v)?;
    let mut all = v.all_meta(&mk)?;
    if let Some(p) = prefix {
        let p = names::strip_ref(&p).trim_end_matches('/').to_string();
        all.retain(|m| m.name == p || m.name.starts_with(&format!("{p}/")));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&all)?);
    } else {
        for m in all {
            println!("{}", m.name);
        }
    }
    Ok(0)
}

fn cmd_search(query: &str, json: bool, limit: usize) -> Result<i32> {
    let v = Vault::open()?;
    let mk = unlock::meta_keys(&v)?;
    let hits = discover::search(&v.all_meta(&mk)?, query, limit);
    if json {
        println!("{}", serde_json::to_string_pretty(&hits)?);
        return Ok(0);
    }
    if hits.is_empty() {
        eprintln!("openvault: no matches for {query:?}");
        return Ok(1);
    }
    let rows: Vec<Vec<String>> = hits
        .iter()
        .map(|h| {
            vec![
                h.reference.clone(),
                h.env.clone(),
                h.tags.join(","),
                h.description.clone().unwrap_or_default(),
            ]
        })
        .collect();
    print!(
        "{}",
        util::table(&["REF", "ENV", "TAGS", "DESCRIPTION"], &rows)
    );
    Ok(0)
}

fn cmd_env(dir: Option<PathBuf>, json: bool) -> Result<i32> {
    let dir = match dir {
        Some(d) => d
            .canonicalize()
            .with_context(|| format!("no such directory {}", d.display()))?,
        None => cwd()?,
    };
    let v = Vault::open()?;
    let mk = unlock::meta_keys(&v)?;
    let project = policy::find(&dir)?;
    let entries = discover::env_for(&v.all_meta(&mk)?, project.as_ref(), &dir);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "dir": dir,
                "project_file": project.as_ref().map(|p| p.file.display().to_string()),
                "env": entries
            }))?
        );
        return Ok(0);
    }
    if let Some(p) = &project {
        eprintln!("openvault: policy {}", p.file.display());
    }
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            vec![
                e.var.clone(),
                e.reference.clone(),
                e.source.clone(),
                e.description.clone().unwrap_or_default(),
            ]
        })
        .collect();
    print!(
        "{}",
        util::table(&["VAR", "REF", "SOURCE", "DESCRIPTION"], &rows)
    );
    Ok(0)
}

fn cmd_rm(list: &[String]) -> Result<i32> {
    let v = Vault::open()?;
    let mk = unlock::meta_keys(&v)?;
    let mut code = 0;
    let mut removed = Vec::new();
    for n in list {
        let n = names::strip_ref(n);
        names::validate(n)?;
        if v.remove(&mk, n)? {
            eprintln!("openvault: removed {n}");
            removed.push(n.to_string());
        } else {
            eprintln!("openvault: no secret named {n}");
            code = 1;
        }
    }
    if !removed.is_empty() {
        audit::record(&v.home, "rm", &removed, true, None, "cli")?;
    }
    Ok(code)
}

fn cmd_run(
    only: Vec<String>,
    env: Vec<String>,
    clean_env: bool,
    no_redact: bool,
    command: Vec<String>,
) -> Result<i32> {
    if no_redact && !(util::stdin_is_tty() && util::stdout_is_tty()) {
        bail!("--no-redact requires an interactive terminal (stdin and stdout); agents always get redacted output");
    }
    let v = Vault::open()?;
    let mk = unlock::meta_keys(&v)?;
    let req = Request {
        only,
        env,
        cwd: cwd()?,
        inherited: std::env::vars().collect(),
    };
    let prepared = run::prepare(&v, &mk, &req, "cli")?;
    drop(mk);
    let cmd = run::build_command(&command, &prepared, clean_env, None)?;
    if no_redact {
        run::exec(cmd)
    } else {
        run::run_streaming(cmd, &prepared)
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_import(
    file: Option<PathBuf>,
    from: Option<String>,
    from_env_file: Option<PathBuf>,
    prefix: Option<String>,
    tags: Vec<String>,
    dry_run: bool,
    on_conflict: &str,
    undo: Option<String>,
    shred: bool,
) -> Result<i32> {
    let v = Vault::open()?;
    let mk = unlock::meta_keys(&v)?;
    if let Some(id) = undo {
        let id = if id == "last" {
            import::latest_batch(&v)?
        } else {
            id
        };
        let (n, kept) = import::undo(&v, &mk, &id)?;
        for k in &kept {
            eprintln!("openvault: kept {k}: changed since the import");
        }
        eprintln!("openvault: undid import {id}: {n} secret(s) reverted");
        audit::record(&v.home, "import-undo", &[id], true, None, "cli")?;
        return Ok(0);
    }
    let conflict = Conflict::parse(on_conflict)?;
    let (path, format) = match (file, from_env_file) {
        (Some(_), Some(_)) => bail!("give either FILE or --from-env-file, not both"),
        (None, Some(p)) => (p, Some(Format::Dotenv)),
        (Some(p), None) => (p, from.as_deref().map(Format::parse).transpose()?),
        (None, None) => {
            bail!("nothing to import: pass FILE (or --from-env-file FILE, or --undo ID)")
        }
    };
    let data = import::read_capped(&path)?;
    let format = match format {
        Some(f) => f,
        None => import::detect(&path, &data[..data.len().min(4096)])?,
    };
    let items = import::parse(format, &data)?;
    drop(data);
    let file_label = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut records = import::to_records(items, prefix.as_deref(), format, &file_label)?;
    for r in &mut records {
        for t in &tags {
            r.meta.tags.push(names::slug(t));
        }
    }
    let existing: BTreeSet<String> = v.all_meta(&mk)?.into_iter().map(|m| m.name).collect();
    let plan = import::plan(&records, &existing, conflict);
    print!("{}", import::render_plan(&records, &plan));
    if dry_run {
        let adds = plan
            .iter()
            .filter(|p| p.action != import::Action::Skip)
            .count();
        eprintln!(
            "openvault: dry run ({}): {adds} to write, {} skipped — nothing written",
            format.id(),
            plan.len() - adds
        );
        return Ok(0);
    }
    let res = import::apply(&v, &mk, &mut records, &plan, format)?;
    audit::record(
        &v.home,
        "import",
        std::slice::from_ref(&res.batch),
        true,
        Some(format!(
            "{} added, {} overwritten, {} skipped from {}",
            res.added,
            res.overwritten,
            res.skipped,
            format.id()
        )),
        "cli",
    )?;
    eprintln!(
        "openvault: imported batch {} ({}): {} added, {} overwritten, {} skipped\nopenvault: undo with: openvault import --undo {}",
        res.batch,
        format.id(),
        res.added,
        res.overwritten,
        res.skipped,
        res.batch
    );
    maybe_shred(&path, shred)?;
    Ok(0)
}

fn maybe_shred(path: &Path, shred: bool) -> Result<()> {
    let mut do_it = shred;
    if !shred && util::stdin_is_tty() && io::stderr().is_terminal() {
        eprint!(
            "openvault: {} contains plaintext secrets. Shred it now? [y/N] ",
            path.display()
        );
        let mut s = String::new();
        io::stdin().read_line(&mut s)?;
        do_it = s.trim().eq_ignore_ascii_case("y");
    }
    if do_it {
        import::shred(path)?;
        eprintln!("openvault: shredded {} (note: SSD/APFS copies may survive; empty the Trash and any backups)", path.display());
    } else {
        eprintln!(
            "openvault: WARNING: {} still holds plaintext secrets — delete it (`--shred` does this)",
            path.display()
        );
    }
    Ok(())
}

fn cmd_audit(action: Option<&str>, n: usize) -> Result<i32> {
    let home = vault::home_dir()?;
    Vault::open_at(&home)?;
    match action {
        Some("verify") => {
            let count = audit::verify(&home)?;
            println!("ok: {count} entries, hash chain intact");
        }
        None | Some("show") => {
            for l in audit::tail(&home, n)? {
                println!("{l}");
            }
        }
        Some(other) => bail!("unknown audit action {other:?} (use `verify`)"),
    }
    Ok(0)
}
