//! Secret names (refs), slugs and environment-variable naming.

use anyhow::{bail, Result};

pub const REF_SCHEME: &str = "secret://";
const MAX_NAME_LEN: usize = 200;
const MAX_DEPTH: usize = 8;

/// Strip an optional `secret://` scheme from a ref.
pub fn strip_ref(s: &str) -> &str {
    s.strip_prefix(REF_SCHEME).unwrap_or(s)
}

/// Validate a secret name: lowercase `a-z0-9._-` segments separated by `/`.
/// Lowercase-only avoids collisions on case-insensitive file systems and keeps
/// names deterministic across imports.
pub fn validate(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        bail!("invalid secret name {name:?}: must be 1-{MAX_NAME_LEN} characters");
    }
    let segs: Vec<&str> = name.split('/').collect();
    if segs.len() > MAX_DEPTH {
        bail!("invalid secret name {name:?}: at most {MAX_DEPTH} path segments");
    }
    for seg in segs {
        let ok_chars = seg
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
        if seg.is_empty() || seg.starts_with('.') || !ok_chars {
            bail!(
                "invalid secret name {name:?}: use lowercase letters, digits, '.', '_' and '-' in '/'-separated segments (e.g. github/token)"
            );
        }
    }
    Ok(())
}

/// Turn arbitrary text (an item title) into a name segment, deterministically.
pub fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars() {
        let c = c.to_ascii_lowercase();
        let keep = c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || ((c == '.' || c == '_') && !out.is_empty());
        if keep {
            out.push(c);
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    let out = out.trim_end_matches(['-', '.', '_']).to_string();
    let out: String = out.chars().take(64).collect();
    if out.is_empty() {
        "item".to_string()
    } else {
        out
    }
}

/// The default environment variable for a name: `github/token` -> `GITHUB_TOKEN`.
pub fn env_var_for(name: &str) -> String {
    let mut out = String::new();
    let mut us = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
            us = false;
        } else if !us && !out.is_empty() {
            out.push('_');
            us = true;
        }
    }
    let out = out.trim_end_matches('_').to_string();
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{out}")
    } else {
        out
    }
}

/// Validate an environment variable name.
pub fn validate_env_var(var: &str) -> Result<()> {
    let ok = !var.is_empty()
        && !var.starts_with(|c: char| c.is_ascii_digit())
        && var.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !ok {
        bail!("invalid environment variable name {var:?}");
    }
    if var.starts_with("OPENVAULT_") {
        bail!("refusing to inject into reserved variable {var}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names() {
        for ok in ["github/token", "a", "aws/prod/key-1", "x.y_z"] {
            validate(ok).unwrap();
        }
        for bad in [
            "", "/a", "a/", "a//b", "../x", "a/../b", ".hidden", "Up", "a b", "a\\b",
        ] {
            assert!(validate(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn slugs_are_deterministic() {
        assert_eq!(slug("GitHub"), "github");
        assert_eq!(slug("My Bank (Chase)"), "my-bank-chase");
        assert_eq!(slug("  ...  "), "item");
        assert_eq!(slug("Ünïcode"), "n-code");
        assert_eq!(slug("api_key.v2"), "api_key.v2");
    }

    #[test]
    fn env_vars() {
        assert_eq!(env_var_for("github/token"), "GITHUB_TOKEN");
        assert_eq!(env_var_for("aws/prod-key.v2"), "AWS_PROD_KEY_V2");
        assert_eq!(env_var_for("1password/x"), "_1PASSWORD_X");
        assert!(validate_env_var("OPENVAULT_HOME").is_err());
        assert!(validate_env_var("GOOD_1").is_ok());
        assert!(validate_env_var("1BAD").is_err());
    }
}
