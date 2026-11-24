//! Bitwarden unencrypted JSON export.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use zeroize::Zeroizing;

use super::Item;

fn s(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or_default().to_string()
}

pub fn parse(data: &[u8]) -> Result<Vec<Item>> {
    let root: Value = serde_json::from_slice(data).context("not valid Bitwarden JSON")?;
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        bail!("this is an encrypted Bitwarden export; export as unencrypted JSON (then shred it with --shred)");
    }
    let items = root
        .get("items")
        .and_then(Value::as_array)
        .context("Bitwarden export has no items")?;
    let mut out = Vec::new();
    for it in items {
        let mut item = Item {
            title: s(it.get("name")),
            ..Default::default()
        };
        let push = |item: &mut Item, label: &str, v: Option<&Value>| {
            let val = s(v);
            if !val.is_empty() {
                item.fields.push((label.to_string(), Zeroizing::new(val)));
            }
        };
        if let Some(l) = it.get("login") {
            push(&mut item, "username", l.get("username"));
            push(&mut item, "password", l.get("password"));
            push(&mut item, "totp", l.get("totp"));
            item.url = l
                .get("uris")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|u| u.get("uri"))
                .and_then(Value::as_str)
                .map(String::from);
        }
        if let Some(c) = it.get("card") {
            push(&mut item, "cardholder", c.get("cardholderName"));
            push(&mut item, "number", c.get("number"));
            push(&mut item, "cvv", c.get("code"));
            let (m, y) = (s(c.get("expMonth")), s(c.get("expYear")));
            if !m.is_empty() || !y.is_empty() {
                item.fields
                    .push(("expiry".into(), Zeroizing::new(format!("{m}/{y}"))));
            }
        }
        if let Some(k) = it.get("sshKey") {
            push(&mut item, "private-key", k.get("privateKey"));
            push(&mut item, "public-key", k.get("publicKey"));
        }
        for f in it
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let label = s(f.get("name"));
            push(
                &mut item,
                if label.is_empty() { "field" } else { &label },
                f.get("value"),
            );
        }
        push(&mut item, "notes", it.get("notes"));
        out.push(item);
    }
    Ok(out)
}
