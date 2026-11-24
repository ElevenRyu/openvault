//! Creating a vault and unlocking its keys.
//!
//! Two keys, two privilege levels:
//! - the **metadata key** (names, env vars, descriptions) is cached where it can be
//!   used without a prompt (macOS login Keychain, or a 0600 local file on Linux),
//!   so agents can *discover* secrets quickly;
//! - the **value key** is only ever reachable through the Secure Enclave (Touch ID)
//!   or the scrypt passphrase — or `OPENVAULT_IDENTITY` for headless CI, which is
//!   equivalent to holding the root key.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::Command;

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::util;
use crate::vault::{self, Config, MetaKeys, Vault};

pub const ENV_IDENTITY: &str = "OPENVAULT_IDENTITY";
pub const ENV_PASSPHRASE: &str = "OPENVAULT_PASSPHRASE";
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "openvault.meta";
const MIN_PASSPHRASE: usize = 12;

/// How the value key was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// A human just authenticated (Touch ID or a typed passphrase).
    Interactive,
    /// Key material came from the environment (CI). Holder already has root access.
    Environment,
    /// Served by a live session agent (unlocked earlier by a human, within its TTL).
    Session,
}

pub struct ValueKey {
    pub identity: x25519::Identity,
    pub auth: Auth,
}

/// age plugin UI: prompts go to the controlling terminal, never stdout.
#[derive(Clone)]
struct Ui;

impl age::Callbacks for Ui {
    fn display_message(&self, message: &str) {
        eprintln!("openvault: {message}");
    }
    fn confirm(&self, message: &str, yes: &str, no: Option<&str>) -> Option<bool> {
        eprint!("{message} [{yes}/{}] ", no.unwrap_or("no"));
        let mut s = String::new();
        io::stdin().lock().read_line(&mut s).ok()?;
        Some(s.trim().eq_ignore_ascii_case(yes) || s.trim().eq_ignore_ascii_case("y"))
    }
    fn request_public_string(&self, description: &str) -> Option<String> {
        eprint!("{description} ");
        let mut s = String::new();
        io::stdin().lock().read_line(&mut s).ok()?;
        Some(s.trim().to_string())
    }
    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        rpassword::prompt_password(format!("{description} "))
            .ok()
            .map(SecretString::from)
    }
}

pub struct InitOptions {
    pub unlock: Option<String>,
    pub se_access_control: String,
}

pub struct InitResult {
    pub recovery_key: SecretString,
    pub unlock: String,
    pub meta_cache: String,
}

pub fn se_available() -> bool {
    cfg!(target_os = "macos") && which("age-plugin-se")
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

/// Create a new vault at `home`.
pub fn init(home: &Path, opts: &InitOptions) -> Result<InitResult> {
    if home.join("vault.json").exists() {
        bail!("a vault already exists at {}", home.display());
    }
    let method = match opts.unlock.as_deref() {
        Some(m @ ("se" | "passphrase")) => m.to_string(),
        Some(other) => bail!("unknown unlock method {other:?} (use se or passphrase)"),
        None if se_available() => "se".to_string(),
        None => "passphrase".to_string(),
    };
    if method == "se" && !se_available() {
        bail!(
            "Secure Enclave unlock needs macOS and `age-plugin-se` on PATH (brew install age-plugin-se)"
        );
    }

    util::create_private_dir(home)?;
    crate::platform::check_private(home, "vault directory")?;
    let keys = home.join("keys");
    util::create_private_dir(&keys)?;
    util::create_private_dir(&home.join("v"))?;
    util::create_private_dir(&home.join("m"))?;

    let value = x25519::Identity::generate();
    let meta = MetaKeys::generate();
    let recovery = x25519::Identity::generate();
    let value_secret = value.to_string();

    // Paper recovery key unlocks everything.
    let bundle = vault::recovery_bundle(&value, &meta);
    util::write_atomic(
        &keys.join("recovery.age"),
        &age::encrypt(&recovery.to_public(), bundle.as_bytes())?,
    )?;
    // Value key unlocks the metadata key (so one Touch ID covers both).
    util::write_atomic(
        &keys.join("meta.age"),
        &age::encrypt(&value.to_public(), meta.serialize().as_bytes())?,
    )?;

    match method.as_str() {
        "se" => init_se(&keys, value_secret.expose_secret(), &opts.se_access_control)?,
        _ => init_passphrase(&keys, value_secret.expose_secret())?,
    }

    let cfg = Config {
        version: 1,
        id: util::random_hex(16),
        value_recipient: value.to_public().to_string(),
        meta_recipient: meta.recipient().to_string(),
        unlock: method.clone(),
        created: util::now_utc(),
        session_ttl: Some("15m".into()),
    };
    let meta_cache = store_meta_cache(home, &cfg, &meta)?;
    util::write_atomic(
        &home.join(".gitignore"),
        b"# local-only state; everything else is ciphertext and safe to sync\naudit.log\nkeys/meta.key\n",
    )?;
    util::write_atomic(&home.join("vault.json"), &serde_json::to_vec_pretty(&cfg)?)?;

    Ok(InitResult {
        recovery_key: recovery.to_string(),
        unlock: method,
        meta_cache,
    })
}

fn init_se(keys: &Path, value_secret: &str, access_control: &str) -> Result<()> {
    let id_path = keys.join("se.identity");
    eprintln!("openvault: creating a Secure Enclave key (access control: {access_control})");
    let st = Command::new("age-plugin-se")
        .arg("keygen")
        .arg(format!("--access-control={access_control}"))
        .arg("-o")
        .arg(&id_path)
        .stdout(std::process::Stdio::null())
        .status()
        .context("failed to run age-plugin-se")?;
    if !st.success() {
        bail!("age-plugin-se keygen failed");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&id_path, fs::Permissions::from_mode(0o600))?;
    }
    let text = fs::read_to_string(&id_path)?;
    let rcpt = text
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .context("age-plugin-se did not report a public key")?
        .trim()
        .to_string();
    let rcpt: age::plugin::Recipient = rcpt
        .parse()
        .map_err(|e| anyhow::anyhow!("bad Secure Enclave recipient: {e}"))?;
    let plugin =
        age::plugin::RecipientPluginV1::new(rcpt.plugin(), std::slice::from_ref(&rcpt), &[], Ui)
            .map_err(|e| anyhow::anyhow!("cannot load age-plugin-se: {e:?}"))?;
    let ct = age::encrypt(&plugin, value_secret.as_bytes())?;
    util::write_atomic(&keys.join("se.age"), &ct)?;
    Ok(())
}

fn read_new_passphrase() -> Result<SecretString> {
    if let Ok(p) = std::env::var(ENV_PASSPHRASE) {
        return Ok(SecretString::from(p));
    }
    let a = Zeroizing::new(rpassword::prompt_password("New vault passphrase: ")?);
    let b = Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ")?);
    if *a != *b {
        bail!("passphrases do not match");
    }
    Ok(SecretString::from(a.to_string()))
}

fn init_passphrase(keys: &Path, value_secret: &str) -> Result<()> {
    eprintln!(
        "openvault: WARNING: passphrase mode. Anyone who copies your vault files can try to\n\
         brute-force the passphrase offline; scrypt slows them down but cannot stop a weak\n\
         passphrase. Use 5+ random words. On a Mac, prefer Secure Enclave (brew install age-plugin-se)."
    );
    let pass = read_new_passphrase()?;
    if pass.expose_secret().chars().count() < MIN_PASSPHRASE {
        bail!("passphrase too short: use at least {MIN_PASSPHRASE} characters (5+ random words is better)");
    }
    let mut r = age::scrypt::Recipient::new(pass);
    // Test-only knob so the suite does not spend seconds per scrypt; never lower than 10.
    if let Some(n) = std::env::var("OPENVAULT_TEST_SCRYPT_LOG_N")
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
    {
        r.set_work_factor(n.max(10));
    }
    let ct = age::encrypt(&r, value_secret.as_bytes())?;
    util::write_atomic(&keys.join("passphrase.age"), &ct)?;
    Ok(())
}

fn meta_cache_mode() -> String {
    std::env::var("OPENVAULT_META_CACHE").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "keychain".into()
        } else {
            "file".into()
        }
    })
}

fn store_meta_cache(home: &Path, cfg: &Config, meta: &MetaKeys) -> Result<String> {
    let mode = meta_cache_mode();
    match mode.as_str() {
        "none" => {}
        "file" => util::write_atomic(&home.join("keys/meta.key"), meta.serialize().as_bytes())?,
        "keychain" => keychain_set(&cfg.id, &meta.serialize())?,
        other => bail!("unknown OPENVAULT_META_CACHE {other:?} (keychain|file|none)"),
    }
    Ok(mode)
}

#[cfg(target_os = "macos")]
fn keychain_set(id: &str, data: &str) -> Result<()> {
    security_framework::passwords::set_generic_password(KEYCHAIN_SERVICE, id, data.as_bytes())
        .context("could not store the metadata key in the login Keychain")
}

#[cfg(not(target_os = "macos"))]
fn keychain_set(_id: &str, _data: &str) -> Result<()> {
    bail!("the keychain metadata cache is only available on macOS")
}

#[cfg(target_os = "macos")]
fn keychain_get(id: &str) -> Option<Zeroizing<String>> {
    security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, id)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .map(Zeroizing::new)
}

#[cfg(not(target_os = "macos"))]
fn keychain_get(_id: &str) -> Option<Zeroizing<String>> {
    None
}

/// Parse `OPENVAULT_IDENTITY`: either the recovery key or the value key itself.
fn env_keys(v: &Vault) -> Result<Option<(x25519::Identity, Option<MetaKeys>)>> {
    let Ok(raw) = std::env::var(ENV_IDENTITY) else {
        return Ok(None);
    };
    let raw = Zeroizing::new(raw);
    let id: x25519::Identity = raw.trim().parse().map_err(|_| {
        anyhow::anyhow!("{ENV_IDENTITY} is not an age identity (AGE-SECRET-KEY-1…)")
    })?;
    if id.to_public().to_string() == v.cfg.value_recipient {
        return Ok(Some((id, None)));
    }
    let ct = fs::read(v.keys_dir().join("recovery.age"))?;
    let pt = Zeroizing::new(
        age::decrypt(&id, &ct)
            .map_err(|_| anyhow::anyhow!("{ENV_IDENTITY} does not unlock this vault"))?,
    );
    let (value, meta) = vault::parse_recovery_bundle(std::str::from_utf8(&pt)?)?;
    Ok(Some((value, Some(meta))))
}

pub fn meta_from_value(v: &Vault, vk: &x25519::Identity) -> Result<MetaKeys> {
    let ct = fs::read(v.keys_dir().join("meta.age"))?;
    let pt = Zeroizing::new(age::decrypt(vk, &ct)?);
    MetaKeys::parse(std::str::from_utf8(&pt)?)
}

/// Unlock the metadata key (no prompt when a cache exists).
pub fn meta_keys(v: &Vault) -> Result<MetaKeys> {
    if let Some((vk, meta)) = env_keys(v)? {
        return match meta {
            Some(m) => Ok(m),
            None => meta_from_value(v, &vk),
        };
    }
    if let Some(s) = keychain_get(&v.cfg.id) {
        return MetaKeys::parse(&s);
    }
    let file = v.keys_dir().join("meta.key");
    if file.exists() {
        crate::platform::check_private(&file, "metadata key")?;
        return MetaKeys::parse(&Zeroizing::new(fs::read_to_string(&file)?));
    }
    let vk = value_key(v, false)?;
    meta_from_value(v, &vk.identity)
}

/// Unlock the value key. With `require_interactive`, environment-provided keys
/// are not accepted: a human must authenticate right now.
pub fn value_key(v: &Vault, require_interactive: bool) -> Result<ValueKey> {
    if !require_interactive {
        if let Some((identity, _)) = env_keys(v)? {
            return Ok(ValueKey {
                identity,
                auth: Auth::Environment,
            });
        }
    }
    match v.cfg.unlock.as_str() {
        "se" => unlock_se(v),
        "passphrase" => unlock_passphrase(v, require_interactive),
        other => bail!("unknown unlock method {other:?} in vault.json"),
    }
}

fn no_prompt_guard() -> Result<()> {
    if std::env::var_os("OPENVAULT_NO_PROMPT").is_some() {
        bail!("a fresh Touch ID / passphrase unlock is required, but OPENVAULT_NO_PROMPT is set");
    }
    Ok(())
}

fn unlock_se(v: &Vault) -> Result<ValueKey> {
    no_prompt_guard()?;
    let id_text = Zeroizing::new(fs::read_to_string(v.keys_dir().join("se.identity"))?);
    let line = id_text
        .lines()
        .find(|l| l.starts_with("AGE-PLUGIN-SE-"))
        .context("keys/se.identity has no Secure Enclave identity")?;
    let ident: age::plugin::Identity = line
        .parse()
        .map_err(|e| anyhow::anyhow!("bad Secure Enclave identity: {e}"))?;
    let plugin =
        age::plugin::IdentityPluginV1::new(ident.plugin(), std::slice::from_ref(&ident), Ui)
            .map_err(|_| {
                anyhow::anyhow!(
                "Secure Enclave unlock needs `age-plugin-se` on PATH (brew install age-plugin-se), \
                 or set {ENV_IDENTITY} to your recovery key"
            )
            })?;
    let ct = fs::read(v.keys_dir().join("se.age"))?;
    let pt = Zeroizing::new(
        age::decrypt(&plugin, &ct).context("Secure Enclave unlock failed or was cancelled")?,
    );
    let identity = std::str::from_utf8(&pt)?
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("corrupt value key"))?;
    Ok(ValueKey {
        identity,
        auth: Auth::Interactive,
    })
}

fn unlock_passphrase(v: &Vault, require_interactive: bool) -> Result<ValueKey> {
    let (pass, auth) = match std::env::var(ENV_PASSPHRASE) {
        Ok(p) if !require_interactive => (SecretString::from(p), Auth::Environment),
        _ => {
            no_prompt_guard()?;
            let _ = io::stderr().flush();
            let p = rpassword::prompt_password("openvault passphrase: ")
                .context("a passphrase is required (no terminal available?)")?;
            (SecretString::from(p), Auth::Interactive)
        }
    };
    let ct = fs::read(v.keys_dir().join("passphrase.age"))?;
    let pt = Zeroizing::new(
        age::decrypt(&age::scrypt::Identity::new(pass), &ct)
            .map_err(|_| anyhow::anyhow!("wrong passphrase"))?,
    );
    let identity = std::str::from_utf8(&pt)?
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("corrupt value key"))?;
    Ok(ValueKey { identity, auth })
}
