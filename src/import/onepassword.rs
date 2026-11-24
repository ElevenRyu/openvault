//! 1Password: `.1pux` (zip with `export.data` JSON). CSV lives in csvfmt.rs.

use std::io::{Cursor, Read};

use anyhow::{bail, Context, Result};
use serde_json::Value;
use zeroize::Zeroizing;

use super::Item;

/// Decompressed size cap for export.data (zip-bomb guard).
const MAX_EXPORT_DATA: u64 = 256 * 1024 * 1024;

pub fn parse_1pux(data: &[u8]) -> Result<Vec<Item>> {
    let mut zip =
        zip::ZipArchive::new(Cursor::new(data)).context("not a valid .1pux (zip) file")?;
    if zip.len() > 100_000 {
        bail!("too many entries in .1pux archive");
    }
    let mut f = zip
        .by_name("export.data")
        .context(".1pux archive has no export.data")?;
    let mut json = Zeroizing::new(Vec::new());
    (&mut f).take(MAX_EXPORT_DATA + 1).read_to_end(&mut json)?;
    if json.len() as u64 > MAX_EXPORT_DATA {
        bail!("export.data is larger than {} MiB", MAX_EXPORT_DATA >> 20);
    }
    parse_export_data(&json)
}

fn s(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or_default().to_string()
}

/// Pull a scalar out of a 1pux section field value like {"concealed":"x"}.
fn field_value(v: &Value) -> Option<String> {
    let obj = v.as_object()?;
    for (k, val) in obj {
        match (k.as_str(), val) {
            (_, Value::String(s)) => return Some(s.clone()),
            ("email", Value::Object(o)) => {
                return o
                    .get("email_address")
                    .and_then(Value::as_str)
                    .map(String::from)
            }
            (_, Value::Number(n)) => return Some(n.to_string()),
            _ => {}
        }
    }
    None
}

pub fn parse_export_data(json: &[u8]) -> Result<Vec<Item>> {
    let root: Value = serde_json::from_slice(json).context("export.data is not valid JSON")?;
    let accounts = root
        .get("accounts")
        .and_then(Value::as_array)
        .context("export.data has no accounts")?;
    let mut out = Vec::new();
    for acct in accounts {
        for vault in acct
            .get("vaults")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for it in vault
                .get("items")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let state = s(it.get("state"));
                if state == "archived" || state == "deleted" {
                    continue;
                }
                let overview = it.get("overview");
                let details = it.get("details");
                let mut item = Item {
                    title: s(overview.and_then(|o| o.get("title"))),
                    url: overview
                        .and_then(|o| o.get("url"))
                        .and_then(Value::as_str)
                        .map(String::from),
                    tags: overview
                        .and_then(|o| o.get("tags"))
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(String::from)
                                .collect()
                        })
                        .unwrap_or_default(),
                    ..Default::default()
                };
                let d = match details {
                    Some(d) => d,
                    None => continue,
                };
                for lf in d
                    .get("loginFields")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let value = s(lf.get("value"));
                    let label = match s(lf.get("designation")).as_str() {
                        "username" => "username".to_string(),
                        "password" => "password".to_string(),
                        _ if s(lf.get("fieldType")) == "P" => s(lf.get("name")),
                        _ => continue,
                    };
                    item.fields.push((label, Zeroizing::new(value)));
                }
                if let Some(p) = d.get("password").and_then(Value::as_str) {
                    item.fields
                        .push(("password".into(), Zeroizing::new(p.to_string())));
                }
                for sec in d
                    .get("sections")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    for f in sec
                        .get("fields")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let Some(val) = f.get("value").and_then(field_value) else {
                            continue;
                        };
                        let is_totp = f.get("value").and_then(|v| v.get("totp")).is_some();
                        let mut label = s(f.get("title"));
                        if is_totp {
                            label = "totp".into();
                        } else if label.is_empty() {
                            label = s(f.get("id"));
                        }
                        item.fields.push((label, Zeroizing::new(val)));
                    }
                }
                let notes = s(d.get("notesPlain"));
                if !notes.is_empty() {
                    item.fields.push(("notes".into(), Zeroizing::new(notes)));
                }
                out.push(item);
            }
        }
    }
    Ok(out)
}
