//! Discovery without plaintext: search metadata and list the env vars a
//! project can use. Only the metadata key is needed — values stay sealed.

use std::path::Path;

use anyhow::{bail, Result};
use serde::Serialize;

use crate::policy::Project;
use crate::vault::Meta;

#[derive(Serialize, Debug, Clone)]
pub struct Hit {
    #[serde(rename = "ref")]
    pub reference: String,
    pub name: String,
    pub env: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub score: u32,
}

/// Case-insensitive fuzzy search. Every query word must match somewhere
/// (substring beats subsequence; name/env beat description/tags).
pub fn search(all: &[Meta], query: &str, limit: usize) -> Vec<Hit> {
    let words: Vec<String> = query.split_whitespace().map(|w| w.to_lowercase()).collect();
    let mut hits: Vec<Hit> = all
        .iter()
        .filter_map(|m| {
            let env = m.env_var();
            let fields: [(String, u32); 4] = [
                (m.name.to_lowercase(), 4),
                (env.to_lowercase(), 4),
                (m.tags.join(" ").to_lowercase(), 3),
                (m.description.clone().unwrap_or_default().to_lowercase(), 2),
            ];
            let mut total = 0;
            for w in &words {
                let best = fields
                    .iter()
                    .map(|(f, weight)| {
                        if f == w {
                            weight * 30
                        } else if f.contains(w.as_str()) {
                            weight * 10
                        } else if is_subsequence(w, f) {
                            weight * 2
                        } else {
                            0
                        }
                    })
                    .max()
                    .unwrap_or(0);
                if best == 0 {
                    return None;
                }
                total += best;
            }
            Some(Hit {
                reference: format!("secret://{}", m.name),
                name: m.name.clone(),
                env,
                description: m.description.clone(),
                tags: m.tags.clone(),
                score: total,
            })
        })
        .collect();
    hits.sort_by(|a, b| b.score.cmp(&a.score).then(a.name.cmp(&b.name)));
    hits.truncate(limit);
    hits
}

fn is_subsequence(needle: &str, hay: &str) -> bool {
    let mut it = hay.chars();
    needle.chars().all(|c| it.any(|h| h == c))
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct EnvEntry {
    pub var: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Env vars available in `dir`: project mappings first, then scoped secrets,
/// then (only when no project policy restricts it) every other secret.
pub fn env_for(all: &[Meta], project: Option<&Project>, dir: &Path) -> Vec<EnvEntry> {
    let mut out: Vec<EnvEntry> = Vec::new();
    let find = |n: &str| all.iter().find(|m| m.name == n);
    if let Some(p) = project {
        for (var, name) in &p.env {
            out.push(EnvEntry {
                var: var.clone(),
                reference: format!("secret://{name}"),
                source: if find(name).is_some() {
                    "project".into()
                } else {
                    "project (missing!)".into()
                },
                description: find(name).and_then(|m| m.description.clone()),
            });
        }
    }
    for m in all {
        if !m.in_scope(dir) {
            continue;
        }
        if let Some(p) = project {
            if !p.allows(&m.name) {
                continue;
            }
        }
        let var = m.env_var();
        if out
            .iter()
            .any(|e| e.var == var && e.source.starts_with("project"))
        {
            continue;
        }
        if out
            .iter()
            .any(|e| e.reference == format!("secret://{}", m.name))
        {
            continue;
        }
        out.push(EnvEntry {
            var,
            reference: format!("secret://{}", m.name),
            source: if m.scope.is_empty() {
                "vault".into()
            } else {
                "scope".into()
            },
            description: m.description.clone(),
        });
    }
    out.sort_by(|a, b| a.var.cmp(&b.var).then(a.reference.cmp(&b.reference)));
    out
}

/// Resolve an env var name to a secret name for `dir`.
pub fn resolve_var(
    all: &[Meta],
    project: Option<&Project>,
    dir: &Path,
    var: &str,
) -> Result<String> {
    if let Some(name) = project.and_then(|p| p.env.get(var)) {
        return Ok(name.clone());
    }
    let cands: Vec<EnvEntry> = env_for(all, project, dir)
        .into_iter()
        .filter(|e| e.var == var)
        .collect();
    let pick = |src: &str| -> Vec<&EnvEntry> { cands.iter().filter(|e| e.source == src).collect() };
    for tier in ["scope", "vault"] {
        let t = pick(tier);
        match t.len() {
            0 => continue,
            1 => return Ok(t[0].reference.trim_start_matches("secret://").to_string()),
            _ => {
                bail!(
                "{var} is ambiguous: {} — map it in .openvault.toml [env] or use --only VAR=ref",
                t.iter().map(|e| e.reference.as_str()).collect::<Vec<_>>().join(", ")
            )
            }
        }
    }
    if let Some(m) = all.iter().find(|m| m.env_var() == var) {
        match project {
            Some(p) if !p.allows(&m.name) => bail!(
                "{var} comes from {} but {} does not allow it here; add it to `allow` or [env]",
                m.name,
                p.file.display()
            ),
            _ => bail!(
                "{var} comes from {}, which is scoped to other directories",
                m.name
            ),
        }
    }
    bail!("no secret provides {var} (try `openvault search {var}`, or ask the user to `openvault add`)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, env: Option<&str>, desc: &str, tags: &[&str]) -> Meta {
        Meta {
            name: name.into(),
            env: env.map(String::from),
            description: Some(desc.into()),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn search_ranks_and_requires_all_words() {
        let all = vec![
            meta("github/token", None, "GitHub PAT for CI", &["ci"]),
            meta("openai/key", Some("OPENAI_API_KEY"), "OpenAI", &["llm"]),
            meta("aws/prod/key", None, "AWS production", &["prod"]),
        ];
        let h = search(&all, "github", 10);
        assert_eq!(h[0].name, "github/token");
        assert_eq!(h.len(), 1);
        assert_eq!(search(&all, "OPENAI_API_KEY", 10)[0].name, "openai/key");
        assert_eq!(search(&all, "llm", 10)[0].name, "openai/key");
        assert!(search(&all, "github prod", 10).is_empty());
        assert_eq!(search(&all, "ghtkn", 10)[0].name, "github/token"); // subsequence
    }

    #[test]
    fn resolves_vars_and_reports_ambiguity() {
        let all = vec![
            meta("a/token", Some("TOKEN"), "", &[]),
            meta("b/token", Some("TOKEN"), "", &[]),
            meta("github/token", None, "", &[]),
        ];
        let dir = Path::new("/tmp");
        assert_eq!(
            resolve_var(&all, None, dir, "GITHUB_TOKEN").unwrap(),
            "github/token"
        );
        assert!(resolve_var(&all, None, dir, "TOKEN").is_err());
        assert!(resolve_var(&all, None, dir, "NOPE").is_err());
    }

    #[test]
    fn scoped_secrets_only_visible_in_scope() {
        let mut m = meta("proj/db", None, "", &[]);
        m.scope = vec!["/work/proj".into()];
        let all = vec![m];
        assert_eq!(env_for(&all, None, Path::new("/work/proj/sub")).len(), 1);
        assert!(env_for(&all, None, Path::new("/elsewhere")).is_empty());
    }
}
