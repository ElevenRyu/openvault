//! `openvault mcp`: a stdio Model Context Protocol server for agents.
//!
//! Tools: `search`, `list_env`, `run`. No tool ever returns a secret value —
//! `run` returns the child's output with every injected value redacted.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::discover;
use crate::policy;
use crate::run::{self, Request};
use crate::unlock;
use crate::vault::{MetaKeys, Vault};

const SUPPORTED: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "openvault holds the user's secrets (API keys, tokens, passwords). \
Use `search` or `list_env` to find what exists, then `run` to execute a command with secrets \
injected as environment variables. You never see secret values: they are redacted from output. \
Never ask the user to paste a secret into the chat; if one is missing, ask them to run \
`openvault add <name>` themselves.";

struct State {
    vault: Option<Vault>,
    mk: Option<MetaKeys>,
}

impl State {
    fn ensure(&mut self) -> Result<(&Vault, &MetaKeys)> {
        if self.vault.is_none() {
            self.vault = Some(Vault::open()?);
        }
        let v = self.vault.as_ref().expect("set");
        if self.mk.is_none() {
            self.mk = Some(unlock::meta_keys(v)?);
        }
        Ok((v, self.mk.as_ref().expect("set")))
    }
}

pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut st = State {
        vault: None,
        mk: None,
    };
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle(&mut st, &req),
            Err(e) => Some(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("parse error: {e}")}}),
            ),
        };
        if let Some(r) = resp {
            writeln!(stdout, "{}", serde_json::to_string(&r)?)?;
            stdout.flush()?;
        }
    }
    Ok(())
}

fn tools() -> Value {
    json!([
        {
            "name": "search",
            "description": "Fuzzy-search the user's secrets by name, env var, description or tag. Returns refs and metadata only — never values.",
            "inputSchema": {"type":"object","properties":{
                "query":{"type":"string","description":"Words to match, e.g. 'github token' or 'OPENAI_API_KEY'"},
                "limit":{"type":"integer","minimum":1,"maximum":100}
            },"required":["query"]}
        },
        {
            "name": "list_env",
            "description": "List environment variables available to a project directory (from its .openvault.toml and scoped secrets). Never returns values.",
            "inputSchema": {"type":"object","properties":{
                "dir":{"type":"string","description":"Project directory (absolute). Defaults to the server's working directory."}
            }}
        },
        {
            "name": "run",
            "description": "Run a command with secrets injected as environment variables. Output is returned with every secret value (and its base64/hex/URL encodings) redacted. With no env/refs, the project's .openvault.toml [env] mappings are injected.",
            "inputSchema": {"type":"object","properties":{
                "command":{"type":"array","items":{"type":"string"},"minItems":1,"description":"argv, e.g. [\"gh\",\"api\",\"user\"]"},
                "env":{"type":"array","items":{"type":"string"},"description":"Env var names to inject, e.g. [\"GITHUB_TOKEN\"]"},
                "refs":{"type":"array","items":{"type":"string"},"description":"Secret refs, optionally VAR=ref, e.g. [\"secret://github/token\"]"},
                "cwd":{"type":"string","description":"Working directory (absolute); its .openvault.toml policy applies"},
                "timeout_secs":{"type":"integer","minimum":1,"maximum":3600}
            },"required":["command"]}
        }
    ])
}

fn handle(st: &mut State, req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // Notifications get no response.
    id.as_ref()?;
    let result: Result<Value, (i64, String)> = match method {
        "initialize" => {
            let asked = req
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(SUPPORTED[0]);
            let version = if SUPPORTED.contains(&asked) {
                asked
            } else {
                SUPPORTED[0]
            };
            Ok(json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "openvault", "version": env!("CARGO_PKG_VERSION")},
                "instructions": INSTRUCTIONS
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let name = req
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = req
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or(json!({}));
            match call(st, name, &args) {
                Ok(v) => Ok(
                    json!({"content":[{"type":"text","text": serde_json::to_string_pretty(&v).unwrap_or_default()}], "isError": false}),
                ),
                Err(e) => Ok(
                    json!({"content":[{"type":"text","text": format!("error: {e:#}")}], "isError": true}),
                ),
            }
        }
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    Some(match result {
        Ok(r) => json!({"jsonrpc":"2.0","id":id,"result":r}),
        Err((code, message)) => {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
        }
    })
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => vec![],
    }
}

fn dir_arg(args: &Value, key: &str) -> Result<PathBuf> {
    match args.get(key).and_then(Value::as_str) {
        Some(d) => {
            let p = PathBuf::from(d);
            if !p.is_absolute() {
                bail!("{key} must be an absolute path");
            }
            p.canonicalize()
                .with_context(|| format!("no such directory {d}"))
        }
        None => Ok(std::env::current_dir()?),
    }
}

fn call(st: &mut State, name: &str, args: &Value) -> Result<Value> {
    match name {
        "search" => {
            let q = args
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(20)
                .min(100) as usize;
            let (v, mk) = st.ensure()?;
            let all = v.all_meta(mk)?;
            Ok(json!(discover::search(&all, q, limit)))
        }
        "list_env" => {
            let dir = dir_arg(args, "dir")?;
            let (v, mk) = st.ensure()?;
            let all = v.all_meta(mk)?;
            let project = policy::find(&dir)?;
            Ok(json!({
                "dir": dir,
                "project_file": project.as_ref().map(|p| p.file.display().to_string()),
                "env": discover::env_for(&all, project.as_ref(), &dir)
            }))
        }
        "run" => {
            let argv = str_list(args.get("command"));
            if argv.is_empty() {
                bail!("command must be a non-empty array of strings");
            }
            let cwd = dir_arg(args, "cwd")?;
            let timeout = args
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(120)
                .clamp(1, 3600);
            let req = Request {
                only: str_list(args.get("refs")),
                env: str_list(args.get("env")),
                cwd: cwd.clone(),
                inherited: vec![],
            };
            let (v, mk) = st.ensure()?;
            let prepared = run::prepare(v, mk, &req, "mcp")?;
            let cmd = run::build_command(&argv, &prepared, true, Some(&cwd))?;
            let out = run::run_captured(cmd, &prepared, Duration::from_secs(timeout))?;
            Ok(json!({
                "exit_code": out.code,
                "timed_out": out.timed_out,
                "injected": prepared.values.iter().map(|(var, name, _)| json!({"var": var, "ref": format!("secret://{name}")})).collect::<Vec<_>>(),
                "stdout": out.stdout,
                "stderr": out.stderr
            }))
        }
        other => bail!("unknown tool {other}"),
    }
}
