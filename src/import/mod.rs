//! Importers. Every input file is treated as hostile: size-capped, parsed
//! without panics (fuzzed), and never echoed back — previews show names only.

mod bitwarden;
mod csvfmt;
mod dotenv;
mod onepassword;

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::names;
use crate::util;
use crate::vault::{self, Meta, MetaKeys, Vault};

pub const MAX_FILE: u64 = 64 * 1024 * 1024;
pub const MAX_ITEMS: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    OnePux,
    OnePasswordCsv,
    Bitwarden,
    AppleCsv,
    LastPassCsv,
    Dotenv,
}

impl Format {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "1pux" => Format::OnePux,
            "1password-csv" | "1password" | "1p-csv" => Format::OnePasswordCsv,
            "bitwarden" | "bitwarden-json" | "bw" => Format::Bitwarden,
            "apple" | "apple-csv" | "apple-passwords" => Format::AppleCsv,
            "lastpass" | "lastpass-csv" => Format::LastPassCsv,
            "dotenv" | "env" | ".env" => Format::Dotenv,
            other => bail!(
                "unknown format {other:?}; use one of: 1pux, 1password-csv, bitwarden, apple-csv, lastpass-csv, dotenv"
            ),
        })
    }

    pub fn id(self) -> &'static str {
        match self {
            Format::OnePux => "1pux",
            Format::OnePasswordCsv => "1password-csv",
            Format::Bitwarden => "bitwarden",
            Format::AppleCsv => "apple-csv",
            Format::LastPassCsv => "lastpass-csv",
            Format::Dotenv => "dotenv",
        }
    }
}

/// A parsed entry from a source manager, before naming.
#[derive(Default)]
pub struct Item {
    pub title: String,
    pub fields: Vec<(String, Zeroizing<String>)>,
    pub url: Option<String>,
    pub tags: Vec<String>,
    /// dotenv: the exact name and env var, no slugging.
    pub fixed: Option<(String, String)>,
}

pub struct Record {
    pub name: String,
    pub value: Zeroizing<String>,
    pub source: String,
    pub meta: Meta,
}

pub fn detect(path: &Path, head: &[u8]) -> Result<Format> {
    let fname = path
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if fname.ends_with(".1pux") || head.starts_with(b"PK\x03\x04") {
        return Ok(Format::OnePux);
    }
    if fname.ends_with(".json") || head.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') {
        return Ok(Format::Bitwarden);
    }
    if fname == ".env" || fname.starts_with(".env.") || fname.ends_with(".env") {
        return Ok(Format::Dotenv);
    }
    if fname.ends_with(".csv") {
        return csvfmt::detect(head);
    }
    bail!(
        "cannot tell the format of {}; pass --from <format>",
        path.display()
    )
}

/// Read a file with a hard size cap.
pub fn read_capped(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let md = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if !md.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if md.len() > MAX_FILE {
        bail!(
            "{} is larger than {} MiB; refusing to import",
            path.display(),
            MAX_FILE >> 20
        );
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(md.len() as usize));
    fs::File::open(path)?
        .take(MAX_FILE + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_FILE {
        bail!("{} grew past the size limit while reading", path.display());
    }
    Ok(buf)
}

/// Parse raw bytes of a given format into items.
pub fn parse(format: Format, data: &[u8]) -> Result<Vec<Item>> {
    let items = match format {
        Format::OnePux => onepassword::parse_1pux(data)?,
        Format::OnePasswordCsv => csvfmt::parse_1password(data)?,
        Format::Bitwarden => bitwarden::parse(data)?,
        Format::AppleCsv => csvfmt::parse_apple(data)?,
        Format::LastPassCsv => csvfmt::parse_lastpass(data)?,
        Format::Dotenv => dotenv::parse(data)?,
    };
    if items.len() > MAX_ITEMS {
        bail!("too many items ({}; max {MAX_ITEMS})", items.len());
    }
    Ok(items)
}

/// Deterministic naming: `[prefix/]slug(title)/field`, with `-2`, `-3`… for
/// repeated titles (in input order) and repeated fields within an item.
pub fn to_records(
    items: Vec<Item>,
    prefix: Option<&str>,
    format: Format,
    source_file: &str,
) -> Result<Vec<Record>> {
    let prefix = match prefix {
        Some(p) => {
            let p = p.trim_matches('/');
            names::validate(p).context("invalid --prefix")?;
            Some(p.to_string())
        }
        None => None,
    };
    let join = |rest: &str| match &prefix {
        Some(p) => format!("{p}/{rest}"),
        None => rest.to_string(),
    };
    let mut used_items: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    let now = util::now_utc();
    for item in items {
        let mut fields = item.fields;
        fields.retain(|(_, v)| !v.is_empty() && v.len() <= vault::MAX_VALUE_LEN);
        if fields.is_empty() {
            continue;
        }
        if let Some((name, env)) = item.fixed {
            let name = join(&name);
            if names::validate(&name).is_err() {
                continue;
            }
            let (_, value) = fields.into_iter().next().expect("non-empty");
            let mut meta = Meta::new(&name);
            meta.env = Some(env.clone());
            meta.description = Some(format!("{env} from {source_file}"));
            meta.source = Some(format.id().to_string());
            meta.created = Some(now.clone());
            out.push(Record {
                name,
                value,
                source: env,
                meta,
            });
            continue;
        }
        let base = names::slug(&item.title);
        let mut item_slug = base.clone();
        let mut n = 2;
        while used_items.contains(&item_slug) {
            item_slug = format!("{base}-{n}");
            n += 1;
        }
        used_items.insert(item_slug.clone());
        let mut used_fields: BTreeSet<String> = BTreeSet::new();
        for (label, value) in fields {
            let fbase = names::slug(&label);
            let mut f = fbase.clone();
            let mut n = 2;
            while used_fields.contains(&f) {
                f = format!("{fbase}-{n}");
                n += 1;
            }
            used_fields.insert(f.clone());
            let name = join(&format!("{item_slug}/{f}"));
            if names::validate(&name).is_err() {
                continue;
            }
            let mut meta = Meta::new(&name);
            let title: String = item.title.chars().take(120).collect();
            meta.description = Some(match &item.url {
                Some(u) if !u.is_empty() => {
                    format!(
                        "{label} for {title} ({})",
                        u.chars().take(200).collect::<String>()
                    )
                }
                _ => format!("{label} for {title}"),
            });
            meta.tags = item
                .tags
                .iter()
                .map(|t| names::slug(t))
                .filter(|t| t != "item")
                .take(16)
                .collect();
            meta.source = Some(format.id().to_string());
            meta.created = Some(now.clone());
            out.push(Record {
                name,
                value,
                source: format!("{title} › {label}"),
                meta,
            });
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conflict {
    Skip,
    Overwrite,
    Rename,
}

impl Conflict {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "skip" => Conflict::Skip,
            "overwrite" => Conflict::Overwrite,
            "rename" => Conflict::Rename,
            _ => bail!("--on-conflict must be skip, overwrite or rename"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Add,
    Skip,
    Overwrite,
}

pub struct Planned {
    pub name: String,
    pub action: Action,
    pub idx: usize,
    pub note: Option<String>,
}

/// Decide what happens to every record given the names already in the vault.
pub fn plan(records: &[Record], existing: &BTreeSet<String>, conflict: Conflict) -> Vec<Planned> {
    let mut taken: BTreeSet<String> = existing.clone();
    let mut out = Vec::new();
    for (idx, r) in records.iter().enumerate() {
        if !existing.contains(&r.name) && !taken.contains(&r.name) {
            taken.insert(r.name.clone());
            out.push(Planned {
                name: r.name.clone(),
                action: Action::Add,
                idx,
                note: None,
            });
            continue;
        }
        match conflict {
            Conflict::Skip => out.push(Planned {
                name: r.name.clone(),
                action: Action::Skip,
                idx,
                note: Some("exists".into()),
            }),
            Conflict::Overwrite => out.push(Planned {
                name: r.name.clone(),
                action: Action::Overwrite,
                idx,
                note: None,
            }),
            Conflict::Rename => {
                let mut n = 2;
                let mut cand = format!("{}-{n}", r.name);
                while taken.contains(&cand) {
                    n += 1;
                    cand = format!("{}-{n}", r.name);
                }
                taken.insert(cand.clone());
                out.push(Planned {
                    name: cand,
                    action: Action::Add,
                    idx,
                    note: Some(format!("renamed from {}", r.name)),
                });
            }
        }
    }
    out
}

pub fn render_plan(records: &[Record], plan: &[Planned]) -> String {
    let rows: Vec<Vec<String>> = plan
        .iter()
        .map(|p| {
            let action = match p.action {
                Action::Add => "add",
                Action::Skip => "skip",
                Action::Overwrite => "overwrite",
            };
            let mut src = records[p.idx].source.clone();
            if let Some(n) = &p.note {
                src = format!("{src} ({n})");
            }
            vec![action.to_string(), p.name.clone(), src]
        })
        .collect();
    util::table(&["ACTION", "NAME", "SOURCE"], &rows)
}

#[derive(Serialize, Deserialize)]
struct UndoEntry {
    name: String,
    action: String,
    hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_meta: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct UndoRecord {
    id: String,
    created: String,
    format: String,
    entries: Vec<UndoEntry>,
}

pub struct Applied {
    pub batch: String,
    pub added: usize,
    pub overwritten: usize,
    pub skipped: usize,
}

pub fn apply(
    v: &Vault,
    mk: &MetaKeys,
    records: &mut [Record],
    plan: &[Planned],
    format: Format,
) -> Result<Applied> {
    let batch = format!("{}-{}", util::compact_utc(), util::random_hex(2));
    let mut entries = Vec::new();
    let (mut added, mut overwritten, mut skipped) = (0, 0, 0);
    for p in plan {
        if p.action == Action::Skip {
            skipped += 1;
            continue;
        }
        let rec = &mut records[p.idx];
        let mut meta = rec.meta.clone();
        meta.name = p.name.clone();
        meta.import_batch = Some(batch.clone());
        let (bv, bm) = if p.action == Action::Overwrite {
            let (bv, bm) = v.raw(mk, &p.name);
            (bv.map(|b| util::hex(&b)), bm.map(|b| util::hex(&b)))
        } else {
            (None, None)
        };
        v.put(mk, &meta, rec.value.as_bytes())?;
        entries.push(UndoEntry {
            name: p.name.clone(),
            action: if p.action == Action::Overwrite {
                "overwrite".into()
            } else {
                "add".into()
            },
            hash: v.value_ciphertext_hash(mk, &p.name).unwrap_or_default(),
            backup_value: bv,
            backup_meta: bm,
        });
        if p.action == Action::Overwrite {
            overwritten += 1;
        } else {
            added += 1;
        }
    }
    let rec = UndoRecord {
        id: batch.clone(),
        created: util::now_utc(),
        format: format.id().into(),
        entries,
    };
    let ct = v.seal_meta_blob(&serde_json::to_vec(&rec)?)?;
    util::write_atomic(&v.home.join("imports").join(format!("{batch}.age")), &ct)?;
    Ok(Applied {
        batch,
        added,
        overwritten,
        skipped,
    })
}

pub fn latest_batch(v: &Vault) -> Result<String> {
    let mut ids: Vec<String> = fs::read_dir(v.home.join("imports"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| {
                    e.file_name()
                        .to_str()?
                        .strip_suffix(".age")
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids.pop().context("no import batches to undo")
}

/// Undo an import batch. Entries changed since the import are left alone.
pub fn undo(v: &Vault, mk: &MetaKeys, batch: &str) -> Result<(usize, Vec<String>)> {
    if batch.contains('/') || batch.contains("..") || batch.is_empty() {
        bail!("invalid batch id");
    }
    let path = v.home.join("imports").join(format!("{batch}.age"));
    let ct = fs::read(&path).with_context(|| format!("no import batch {batch}"))?;
    let pt = v.open_meta_blob(mk, &ct)?;
    let rec: UndoRecord = serde_json::from_slice(&pt)?;
    if rec.id != batch {
        bail!("import record {batch} does not match its file name (tampered?)");
    }
    let mut reverted = 0;
    let mut kept = Vec::new();
    for e in rec.entries.iter().rev() {
        let cur = v.value_ciphertext_hash(mk, &e.name);
        if cur.as_deref() != Some(e.hash.as_str()) {
            kept.push(e.name.clone());
            continue;
        }
        match (e.action.as_str(), &e.backup_value, &e.backup_meta) {
            ("overwrite", Some(bv), Some(bm)) => {
                let bv = vault::decode_hex_pub(bv).context("corrupt backup")?;
                let bm = vault::decode_hex_pub(bm).context("corrupt backup")?;
                v.restore_raw(mk, &e.name, &bv, &bm)?;
            }
            _ => {
                v.remove(mk, &e.name)?;
            }
        }
        reverted += 1;
    }
    fs::remove_file(&path)?;
    Ok((reverted, kept))
}

/// Overwrite a file's bytes with random data, sync, then unlink. On SSDs and
/// copy-on-write file systems (APFS, btrfs) this cannot guarantee the old
/// blocks are gone — it is defence in depth, not a promise.
pub fn shred(path: &Path) -> Result<()> {
    use std::io::Write;
    let len = fs::metadata(path)?.len();
    let mut f = fs::OpenOptions::new().write(true).open(path)?;
    let mut remaining = len;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        getrandom::fill(&mut buf[..n]).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
        f.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str) -> Record {
        Record {
            name: name.into(),
            value: Zeroizing::new("v".into()),
            source: "s".into(),
            meta: Meta::new(name),
        }
    }

    #[test]
    fn conflict_strategies() {
        let existing: BTreeSet<String> = ["a/b".to_string(), "a/b-2".to_string()].into();
        let recs = vec![rec("a/b"), rec("c/d")];
        let p = plan(&recs, &existing, Conflict::Skip);
        assert_eq!(p[0].action, Action::Skip);
        assert_eq!(p[1].action, Action::Add);
        let p = plan(&recs, &existing, Conflict::Overwrite);
        assert_eq!(p[0].action, Action::Overwrite);
        let p = plan(&recs, &existing, Conflict::Rename);
        assert_eq!(p[0].name, "a/b-3");
        assert_eq!(p[0].action, Action::Add);
    }

    #[test]
    fn naming_is_deterministic_and_dedupes() {
        let mk = |t: &str| Item {
            title: t.into(),
            fields: vec![
                ("password".into(), Zeroizing::new("x".into())),
                ("Password".into(), Zeroizing::new("y".into())),
            ],
            ..Default::default()
        };
        let r = to_records(
            vec![mk("GitHub"), mk("GitHub")],
            Some("pm"),
            Format::AppleCsv,
            "f",
        )
        .unwrap();
        let n: Vec<&str> = r.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            n,
            vec![
                "pm/github/password",
                "pm/github/password-2",
                "pm/github-2/password",
                "pm/github-2/password-2"
            ]
        );
    }

    /// Cheap stable-toolchain fuzzing: random and mutated inputs must never
    /// panic any parser. (cargo-fuzz targets in fuzz/ go deeper.)
    #[test]
    fn parsers_never_panic_on_garbage() {
        let seeds: Vec<&[u8]> = vec![
            include_bytes!("../../tests/fixtures/bitwarden.json"),
            include_bytes!("../../tests/fixtures/1password.csv"),
            include_bytes!("../../tests/fixtures/apple.csv"),
            include_bytes!("../../tests/fixtures/lastpass.csv"),
            include_bytes!("../../tests/fixtures/sample.env"),
            include_bytes!("../../tests/fixtures/export.1pux"),
        ];
        let mut state: u64 = 0x9e3779b97f4a7c15;
        let mut rnd = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let formats = [
            Format::OnePux,
            Format::OnePasswordCsv,
            Format::Bitwarden,
            Format::AppleCsv,
            Format::LastPassCsv,
            Format::Dotenv,
        ];
        for _ in 0..400 {
            let seed = seeds[(rnd() % seeds.len() as u64) as usize];
            let mut data = seed.to_vec();
            let muts = rnd() % 16;
            for _ in 0..muts {
                if data.is_empty() {
                    break;
                }
                let i = (rnd() % data.len() as u64) as usize;
                match rnd() % 3 {
                    0 => data[i] = rnd() as u8,
                    1 => {
                        data.truncate(i);
                    }
                    _ => data.insert(i, b"\"{}[],\n=\\'"[(rnd() % 10) as usize]),
                }
            }
            for f in formats {
                let _ = parse(f, &data).map(|items| to_records(items, None, f, "fuzz"));
            }
        }
    }
}
