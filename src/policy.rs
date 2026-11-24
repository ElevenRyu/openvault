//! Per-project policy: `.openvault.toml`, found by walking up from the cwd.
//!
//! ```toml
//! # Secrets this project may use (globs; `*` = one segment, `**` = any depth).
//! # Defaults to the refs listed in [env] when omitted.
//! allow = ["github/*"]
//! # Secrets with any of these tags need a fresh Touch ID / passphrase on every use.
//! confirm_tags = ["prod"]
//!
//! [env]
//! GITHUB_TOKEN = "secret://github/token"
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::names;

pub const FILE_NAME: &str = ".openvault.toml";

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
struct Raw {
    allow: Option<Vec<String>>,
    #[serde(default)]
    confirm_tags: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Project {
    pub file: PathBuf,
    pub root: PathBuf,
    pub allow: Vec<String>,
    pub confirm_tags: Vec<String>,
    /// env var -> secret name
    pub env: BTreeMap<String, String>,
}

impl Project {
    pub fn allows(&self, name: &str) -> bool {
        self.allow.iter().any(|p| glob_match(p, name))
    }
}

/// Find the nearest `.openvault.toml` at or above `start`.
pub fn find(start: &Path) -> Result<Option<Project>> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let f = d.join(FILE_NAME);
        if f.is_file() {
            return load(&f).map(Some);
        }
        dir = d.parent();
    }
    Ok(None)
}

pub fn load(file: &Path) -> Result<Project> {
    crate::platform::check_not_writable_by_others(file)?;
    let text = fs::read_to_string(file)?;
    let raw: Raw = toml::from_str(&text).with_context(|| format!("invalid {}", file.display()))?;
    let mut env = BTreeMap::new();
    for (var, r) in raw.env {
        names::validate_env_var(&var)?;
        let name = names::strip_ref(&r).to_string();
        names::validate(&name).with_context(|| format!("in {}", file.display()))?;
        env.insert(var, name);
    }
    let allow = match raw.allow {
        Some(a) => {
            for p in &a {
                if p.is_empty() {
                    bail!("empty allow pattern in {}", file.display());
                }
            }
            a.into_iter()
                .map(|p| names::strip_ref(&p).to_string())
                .collect()
        }
        None => env.values().cloned().collect(),
    };
    Ok(Project {
        root: file.parent().unwrap_or(Path::new("/")).to_path_buf(),
        file: file.to_path_buf(),
        allow,
        confirm_tags: raw.confirm_tags,
        env,
    })
}

/// Glob over `/`-separated names: `*` matches within one segment, `**` matches
/// any number of segments.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').collect();
    let n: Vec<&str> = name.split('/').collect();
    match_segs(&p, &n)
}

fn match_segs(p: &[&str], n: &[&str]) -> bool {
    match p.split_first() {
        None => n.is_empty(),
        Some((&"**", rest)) => (0..=n.len()).any(|i| match_segs(rest, &n[i..])),
        Some((seg, rest)) => match n.split_first() {
            Some((first, nrest)) => {
                match_seg(seg.as_bytes(), first.as_bytes()) && match_segs(rest, nrest)
            }
            None => false,
        },
    }
}

fn match_seg(p: &[u8], s: &[u8]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((b'*', rest)) => (0..=s.len()).any(|i| match_seg(rest, &s[i..])),
        Some((c, rest)) => s.first() == Some(c) && match_seg(rest, &s[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob_match("github/*", "github/token"));
        assert!(!glob_match("github/*", "github/a/b"));
        assert!(glob_match("github/**", "github/a/b"));
        assert!(glob_match("**", "x/y/z"));
        assert!(glob_match("aws/prod-*", "aws/prod-key"));
        assert!(!glob_match("aws/prod-*", "aws/dev-key"));
        assert!(glob_match("exact/name", "exact/name"));
        assert!(!glob_match("exact/name", "exact/name2"));
    }

    #[test]
    fn loads_and_defaults_allow_to_env() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join(FILE_NAME);
        fs::write(&f, "[env]\nGITHUB_TOKEN = \"secret://github/token\"\n").unwrap();
        let p = load(&f).unwrap();
        assert!(p.allows("github/token"));
        assert!(!p.allows("aws/key"));
        assert_eq!(p.env["GITHUB_TOKEN"], "github/token");
        let sub = d.path().join("a/b");
        fs::create_dir_all(&sub).unwrap();
        assert!(find(&sub).unwrap().is_some());
    }

    #[test]
    fn rejects_unknown_keys_and_bad_vars() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join(FILE_NAME);
        fs::write(&f, "alow = [\"x\"]\n").unwrap();
        assert!(load(&f).is_err());
        fs::write(&f, "[env]\nOPENVAULT_HOME = \"x\"\n").unwrap();
        assert!(load(&f).is_err());
    }
}
