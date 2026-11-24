//! Append-only, hash-chained audit log. Records who/what/where — never values.
//!
//! Each line is a JSON object whose `prev` field is the SHA-256 of the previous
//! line, so deleting or editing any entry breaks the chain from that point on
//! (`openvault audit verify`).

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::platform;
use crate::util;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Env vars that identify an agent / automation context (names only are logged,
/// plus the value of a few that are non-sensitive identifiers).
const AGENT_MARKERS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CODEX_SANDBOX",
    "CODEX_HOME",
    "CURSOR_AGENT",
    "CURSOR_TRACE_ID",
    "AIDER_MODEL",
    "GEMINI_CLI",
    "OPENVAULT_AGENT",
    "GITHUB_ACTIONS",
    "CI",
    "TERM_PROGRAM",
];

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub ts: String,
    pub op: String,
    pub refs: Vec<String>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub cwd: String,
    pub pid: u32,
    pub ppid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub uid: u32,
    pub via: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub agent: Vec<String>,
    pub prev: String,
}

pub fn record(
    home: &Path,
    op: &str,
    refs: &[String],
    ok: bool,
    detail: Option<String>,
    via: &str,
) -> Result<()> {
    let agent = AGENT_MARKERS
        .iter()
        .filter_map(|k| {
            std::env::var(k).ok().map(|v| {
                if *k == "TERM_PROGRAM" || *k == "OPENVAULT_AGENT" {
                    format!("{k}={}", v.chars().take(40).collect::<String>())
                } else {
                    k.to_string()
                }
            })
        })
        .collect();
    let path = home.join("audit.log");
    let mut f = {
        let mut o = OpenOptions::new();
        o.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(&path)?
    };
    f.lock()?;
    let prev = last_line_hash(&mut f)?;
    let e = Entry {
        ts: util::now_utc(),
        op: op.to_string(),
        refs: refs.to_vec(),
        ok,
        detail,
        cwd: std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        pid: std::process::id(),
        ppid: platform::ppid(),
        parent: platform::parent_process_name(),
        uid: platform::euid(),
        via: via.to_string(),
        agent,
        prev,
    };
    let mut line = serde_json::to_string(&e)?;
    line.push('\n');
    f.seek(SeekFrom::End(0))?;
    f.write_all(line.as_bytes())?;
    f.flush()?;
    let _ = f.unlock();
    Ok(())
}

fn last_line_hash(f: &mut fs::File) -> Result<String> {
    let len = f.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(GENESIS.to_string());
    }
    let mut window = 4096u64;
    loop {
        let start = len.saturating_sub(window);
        f.seek(SeekFrom::Start(start))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let body = buf.strip_suffix(b"\n").unwrap_or(&buf);
        if let Some(pos) = body.iter().rposition(|b| *b == b'\n') {
            return Ok(util::sha256_hex(&body[pos + 1..]));
        }
        if start == 0 {
            return Ok(util::sha256_hex(body));
        }
        window *= 2;
    }
}

/// Verify the chain. Returns the number of entries.
pub fn verify(home: &Path) -> Result<usize> {
    let path = home.join("audit.log");
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let mut prev = GENESIS.to_string();
    let mut n = 0;
    for (i, line) in text.lines().enumerate() {
        let v: Value = serde_json::from_str(line).map_err(|_| {
            anyhow::anyhow!("audit log line {} is not valid JSON (tampered?)", i + 1)
        })?;
        if v.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
            bail!(
                "audit log chain broken at line {} — an earlier entry was modified or removed",
                i + 1
            );
        }
        prev = util::sha256_hex(line.as_bytes());
        n += 1;
    }
    Ok(n)
}

pub fn tail(home: &Path, n: usize) -> Result<Vec<String>> {
    let text = fs::read_to_string(home.join("audit.log")).unwrap_or_default();
    let lines: Vec<String> = text.lines().map(String::from).collect();
    let start = lines.len().saturating_sub(n);
    Ok(lines[start..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_tampering() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..3 {
            record(d.path(), "get", &[format!("s/{i}")], true, None, "cli").unwrap();
        }
        assert_eq!(verify(d.path()).unwrap(), 3);
        let p = d.path().join("audit.log");
        let text = fs::read_to_string(&p).unwrap();
        // Edit the first entry.
        fs::write(&p, text.replacen("s/0", "s/X", 1)).unwrap();
        assert!(verify(d.path()).is_err());
        // Delete the first entry.
        let lines: Vec<&str> = text.lines().collect();
        fs::write(&p, lines[1..].join("\n") + "\n").unwrap();
        assert!(verify(d.path()).is_err());
    }
}
