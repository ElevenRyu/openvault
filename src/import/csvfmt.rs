//! CSV exports: 1Password, Apple Passwords, LastPass.

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use super::{Format, Item};

pub fn detect(head: &[u8]) -> Result<Format> {
    let first = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let h = String::from_utf8_lossy(first).to_lowercase();
    let cols: Vec<String> = h
        .trim_start_matches('\u{feff}')
        .split(',')
        .map(|c| c.trim().trim_matches('"').to_string())
        .collect();
    let has = |c: &str| cols.iter().any(|x| x == c);
    if has("grouping") || has("extra") {
        return Ok(Format::LastPassCsv);
    }
    if has("archived")
        || has("archived status")
        || has("favorite")
        || has("favorite status")
        || has("one-time password")
    {
        return Ok(Format::OnePasswordCsv);
    }
    if has("title") && has("password") {
        return Ok(Format::AppleCsv);
    }
    bail!("unrecognised CSV header; pass --from 1password-csv|apple-csv|lastpass-csv")
}

struct Table {
    header: Vec<String>,
    rows: Vec<csv::StringRecord>,
}

impl Table {
    fn read(data: &[u8]) -> Result<Self> {
        let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
        let mut r = csv::ReaderBuilder::new().flexible(true).from_reader(data);
        let header = r
            .headers()
            .context("invalid CSV header")?
            .iter()
            .map(|h| h.trim().to_lowercase())
            .collect();
        let mut rows = Vec::new();
        for rec in r.records() {
            rows.push(rec.context("invalid CSV row")?);
            if rows.len() > super::MAX_ITEMS {
                bail!("too many rows");
            }
        }
        Ok(Table { header, rows })
    }

    fn col(&self, names: &[&str]) -> Option<usize> {
        names
            .iter()
            .find_map(|n| self.header.iter().position(|h| h == n))
    }
}

fn get(row: &csv::StringRecord, i: Option<usize>) -> String {
    i.and_then(|i| row.get(i)).unwrap_or_default().to_string()
}

type Columns = (Option<usize>, Option<usize>, Vec<(String, Option<usize>)>);

fn basic(
    t: &Table,
    title: &[&str],
    url: &[&str],
    user: &[&str],
    pass: &[&str],
    totp: &[&str],
    notes: &[&str],
) -> Columns {
    (
        t.col(title),
        t.col(url),
        vec![
            ("username".into(), t.col(user)),
            ("password".into(), t.col(pass)),
            ("totp".into(), t.col(totp)),
            ("notes".into(), t.col(notes)),
        ],
    )
}

fn rows_to_items(
    t: &Table,
    title: Option<usize>,
    url: Option<usize>,
    fields: &[(String, Option<usize>)],
    skip: impl Fn(&csv::StringRecord) -> bool,
) -> Vec<Item> {
    t.rows
        .iter()
        .filter(|r| !skip(r))
        .map(|r| {
            let u = get(r, url);
            let mut t = get(r, title);
            if t.is_empty() {
                t = u.clone();
            }
            Item {
                title: t,
                url: if u.is_empty() { None } else { Some(u) },
                fields: fields
                    .iter()
                    .map(|(l, i)| (l.clone(), Zeroizing::new(get(r, *i))))
                    .collect(),
                ..Default::default()
            }
        })
        .collect()
}

pub fn parse_apple(data: &[u8]) -> Result<Vec<Item>> {
    let t = Table::read(data)?;
    let (title, url, fields) = basic(
        &t,
        &["title"],
        &["url"],
        &["username"],
        &["password"],
        &["otpauth"],
        &["notes"],
    );
    if title.is_none() && url.is_none() {
        bail!("not an Apple Passwords CSV (no Title/URL columns)");
    }
    Ok(rows_to_items(&t, title, url, &fields, |_| false))
}

pub fn parse_1password(data: &[u8]) -> Result<Vec<Item>> {
    let t = Table::read(data)?;
    let (title, url, fields) = basic(
        &t,
        &["title"],
        &["url", "website"],
        &["username"],
        &["password"],
        &["otpauth", "one-time password"],
        &["notes"],
    );
    if title.is_none() {
        bail!("not a 1Password CSV (no Title column)");
    }
    let archived = t.col(&["archived", "archived status"]);
    let tags = t.col(&["tags"]);
    let mut items = rows_to_items(&t, title, url, &fields, |r| {
        matches!(
            get(r, archived).to_lowercase().as_str(),
            "true" | "archived" | "1"
        )
    });
    let live: Vec<&csv::StringRecord> = t
        .rows
        .iter()
        .filter(|r| {
            !matches!(
                get(r, archived).to_lowercase().as_str(),
                "true" | "archived" | "1"
            )
        })
        .collect();
    for (item, row) in items.iter_mut().zip(live) {
        item.tags = get(row, tags)
            .split([',', ';'])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    Ok(items)
}

pub fn parse_lastpass(data: &[u8]) -> Result<Vec<Item>> {
    let t = Table::read(data)?;
    let title = t.col(&["name"]);
    let url = t.col(&["url"]);
    if title.is_none() {
        bail!("not a LastPass CSV (no name column)");
    }
    let grouping = t.col(&["grouping"]);
    let fields = vec![
        ("username".to_string(), t.col(&["username"])),
        ("password".to_string(), t.col(&["password"])),
        ("totp".to_string(), t.col(&["totp"])),
        ("notes".to_string(), t.col(&["extra"])),
    ];
    let mut items = rows_to_items(&t, title, url, &fields, |_| false);
    for (item, row) in items.iter_mut().zip(&t.rows) {
        if item.url.as_deref() == Some("http://sn") {
            item.url = None;
        }
        let g = get(row, grouping);
        if !g.is_empty() {
            item.tags = vec![g];
        }
    }
    Ok(items)
}
