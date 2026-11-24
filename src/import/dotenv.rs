//! `.env` files: `KEY=value`, optional `export`, quotes and comments.
//! Each key becomes a secret named `lowercase(key)` with env var `KEY`, so
//! existing .env files are instantly discoverable by `openvault env`.

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use super::Item;

pub fn parse(data: &[u8]) -> Result<Vec<Item>> {
    let text = std::str::from_utf8(data).context(".env file is not UTF-8")?;
    let text = text.trim_start_matches('\u{feff}');
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").map(str::trim_start).unwrap_or(l);
        let Some((key, rest)) = l.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let valid = !key.is_empty()
            && !key.starts_with(|c: char| c.is_ascii_digit())
            && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !valid || key.starts_with("OPENVAULT_") {
            continue;
        }
        let rest = rest.trim_start();
        let value = if let Some(body) = rest.strip_prefix('"') {
            let mut buf = body.to_string();
            loop {
                if let Some(v) = parse_double(&buf) {
                    break v;
                }
                match lines.next() {
                    Some(next) => {
                        buf.push('\n');
                        buf.push_str(next);
                    }
                    None => break unescape(&buf),
                }
            }
        } else if let Some(body) = rest.strip_prefix('\'') {
            match body.find('\'') {
                Some(end) => body.get(..end).unwrap_or_default().to_string(),
                None => body.to_string(),
            }
        } else {
            let v = match rest.find(" #") {
                Some(i) => rest.get(..i).unwrap_or_default(),
                None => rest,
            };
            v.trim().to_string()
        };
        out.push(Item {
            title: key.to_string(),
            fields: vec![("value".into(), Zeroizing::new(value))],
            fixed: Some((key.to_lowercase(), key.to_string())),
            ..Default::default()
        });
    }
    Ok(out)
}

/// If `s` contains an unescaped closing quote, return the unescaped body.
fn parse_double(s: &str) -> Option<String> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(unescape(s.get(..i)?));
        }
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_forms() {
        let src = b"# comment\nexport A=1\nB = \"two\\nlines\" \nC='lit $x'\nD=plain # trailing\nE=\"multi\nline\"\n1BAD=x\nnot a line\nOPENVAULT_IDENTITY=nope\n";
        let items = parse(src).unwrap();
        let kv: Vec<(String, String)> = items
            .iter()
            .map(|i| (i.title.clone(), i.fields[0].1.to_string()))
            .collect();
        assert_eq!(
            kv,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two\nlines".into()),
                ("C".into(), "lit $x".into()),
                ("D".into(), "plain".into()),
                ("E".into(), "multi\nline".into()),
            ]
        );
        assert_eq!(items[0].fixed, Some(("a".into(), "A".into())));
    }
}
