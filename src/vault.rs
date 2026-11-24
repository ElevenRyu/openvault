//! On-disk vault layout and (de)serialisation of encrypted secrets and metadata.
//!
//! ```text
//! $OPENVAULT_HOME (default ~/.openvault, mode 0700)
//!   vault.json        public config: version, vault id, the two age recipients, unlock method
//!   keys/recovery.age value+metadata keys, encrypted to the paper recovery key
//!   keys/se.identity  Secure Enclave key handle (age-plugin-se; useless off this Mac)
//!   keys/se.age       value key, encrypted to the Secure Enclave key
//!   keys/passphrase.age value key, encrypted with an scrypt passphrase (fallback)
//!   keys/meta.age     metadata key, encrypted to the value key
//!   v/<id>.age        one secret value per file, encrypted to the value key
//!   m/<id>.age        its metadata (name, env var, description, tags, scope), encrypted to the metadata key
//!   imports/<batch>.age undo records, encrypted to the metadata key
//!   audit.log         hash-chained read log (local only, never values)
//! ```
//!
//! `<id>` is HMAC-SHA256(name_key, name), so file names reveal nothing about
//! secret names; plaintext is padded to 256-byte buckets so sizes leak little.

use std::fs;
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519;
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::names;
use crate::platform::{self, SecretBuf};
use crate::util;

const VALUE_MAGIC: &str = "openvault-value-v1";
const META_KEY_MAGIC: &str = "openvault-meta-key-v1";
const RECOVERY_MAGIC: &str = "openvault-recovery-v1";
const PAD: usize = 256;
pub const MAX_VALUE_LEN: usize = 1 << 20;

pub fn home_dir() -> Result<PathBuf> {
    if let Some(h) = std::env::var_os("OPENVAULT_HOME") {
        return Ok(PathBuf::from(h));
    }
    let home = std::env::var_os("HOME").context("$HOME is not set; set OPENVAULT_HOME")?;
    Ok(PathBuf::from(home).join(".openvault"))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub version: u32,
    pub id: String,
    pub value_recipient: String,
    pub meta_recipient: String,
    /// "se" (Secure Enclave via age-plugin-se) or "passphrase".
    pub unlock: String,
    pub created: String,
    /// How long one Touch ID unlocks values for, e.g. "15m" ("0" disables sessions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ttl: Option<String>,
}

/// Searchable metadata. Encrypted at rest with the metadata key; never holds a value.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Meta {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Directories this secret may be used from (empty = anywhere).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_batch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
}

impl Meta {
    pub fn new(name: &str) -> Self {
        Meta {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// The env var this secret is injected as by default.
    pub fn env_var(&self) -> String {
        self.env
            .clone()
            .unwrap_or_else(|| names::env_var_for(&self.name))
    }

    /// Is `dir` inside one of this secret's scope directories (or unscoped)?
    pub fn in_scope(&self, dir: &Path) -> bool {
        self.scope.is_empty() || self.scope.iter().any(|s| dir.starts_with(s))
    }

    pub fn needs_confirm(&self, extra_tags: &[String]) -> bool {
        self.tags
            .iter()
            .any(|t| t == "confirm" || extra_tags.contains(t))
    }
}

/// Keys that unlock metadata (names, env vars, descriptions) but not values.
pub struct MetaKeys {
    identity: x25519::Identity,
    name_key: Zeroizing<Vec<u8>>,
}

impl MetaKeys {
    pub fn generate() -> Self {
        let mut k = vec![0u8; 32];
        getrandom::fill(&mut k).expect("OS RNG failed");
        MetaKeys {
            identity: x25519::Identity::generate(),
            name_key: Zeroizing::new(k),
        }
    }

    pub fn recipient(&self) -> x25519::Recipient {
        self.identity.to_public()
    }

    /// Opaque, stable file id for a name.
    pub fn file_id(&self, name: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.name_key).expect("hmac key");
        mac.update(b"openvault-name-v1\0");
        mac.update(name.as_bytes());
        util::hex(&mac.finalize().into_bytes()[..16])
    }

    pub fn serialize(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{META_KEY_MAGIC}\n{}\n{}\n",
            self.identity.to_string().expose_secret(),
            util::hex(&self.name_key)
        ))
    }

    pub fn parse(s: &str) -> Result<Self> {
        let mut lines = s.lines();
        if lines.next() != Some(META_KEY_MAGIC) {
            bail!("not an openvault metadata key");
        }
        Self::from_lines(&mut lines)
    }

    fn from_lines<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Result<Self> {
        let identity: x25519::Identity = lines
            .next()
            .context("truncated key")?
            .parse()
            .map_err(|e| anyhow::anyhow!("bad metadata identity: {e}"))?;
        let nk = lines.next().context("truncated key")?;
        let name_key = Zeroizing::new(decode_hex(nk).context("bad name key")?);
        if name_key.len() != 32 {
            bail!("bad name key length");
        }
        Ok(MetaKeys { identity, name_key })
    }
}

/// Everything the paper recovery key unlocks.
pub fn recovery_bundle(value: &x25519::Identity, meta: &MetaKeys) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{RECOVERY_MAGIC}\n{}\n{}\n{}\n",
        value.to_string().expose_secret(),
        meta.identity.to_string().expose_secret(),
        util::hex(&meta.name_key)
    ))
}

pub fn parse_recovery_bundle(s: &str) -> Result<(x25519::Identity, MetaKeys)> {
    let mut lines = s.lines();
    if lines.next() != Some(RECOVERY_MAGIC) {
        bail!("not an openvault recovery bundle");
    }
    let value: x25519::Identity = lines
        .next()
        .context("truncated bundle")?
        .parse()
        .map_err(|e| anyhow::anyhow!("bad value identity: {e}"))?;
    let meta = MetaKeys::from_lines(&mut lines)?;
    Ok((value, meta))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn decode_hex_pub(s: &str) -> Option<Vec<u8>> {
    decode_hex(s)
}

fn pad(buf: &mut Vec<u8>) {
    let target = buf.len().div_ceil(PAD).max(1) * PAD;
    buf.resize(target, 0);
}

pub struct Vault {
    pub home: PathBuf,
    pub cfg: Config,
    value_rcpt: x25519::Recipient,
    meta_rcpt: x25519::Recipient,
}

impl Vault {
    pub fn open() -> Result<Self> {
        Self::open_at(&home_dir()?)
    }

    pub fn open_at(home: &Path) -> Result<Self> {
        let cfg_path = home.join("vault.json");
        if !cfg_path.exists() {
            bail!(
                "no vault at {} — run `openvault init` first (or set OPENVAULT_HOME)",
                home.display()
            );
        }
        platform::check_private(home, "vault directory")?;
        platform::check_private(&home.join("keys"), "key directory")?;
        let cfg: Config = serde_json::from_slice(&fs::read(&cfg_path)?)
            .with_context(|| format!("corrupt {}", cfg_path.display()))?;
        if cfg.version != 1 {
            bail!("unsupported vault version {}", cfg.version);
        }
        let value_rcpt = cfg
            .value_recipient
            .parse()
            .map_err(|e| anyhow::anyhow!("bad value recipient in vault.json: {e}"))?;
        let meta_rcpt = cfg
            .meta_recipient
            .parse()
            .map_err(|e| anyhow::anyhow!("bad metadata recipient in vault.json: {e}"))?;
        Ok(Vault {
            home: home.to_path_buf(),
            cfg,
            value_rcpt,
            meta_rcpt,
        })
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.home.join("keys")
    }

    pub fn value_recipient(&self) -> &x25519::Recipient {
        &self.value_rcpt
    }

    fn value_path(&self, id: &str) -> PathBuf {
        self.home.join("v").join(format!("{id}.age"))
    }

    fn meta_path(&self, id: &str) -> PathBuf {
        self.home.join("m").join(format!("{id}.age"))
    }

    pub fn exists(&self, mk: &MetaKeys, name: &str) -> bool {
        self.value_path(&mk.file_id(name)).exists()
    }

    pub fn encrypt_value(&self, name: &str, value: &[u8]) -> Result<Vec<u8>> {
        if value.len() > MAX_VALUE_LEN {
            bail!("secret value too large (max {MAX_VALUE_LEN} bytes)");
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(value.len() + 64));
        buf.extend_from_slice(format!("{VALUE_MAGIC}\n{name}\n{}\n", value.len()).as_bytes());
        buf.extend_from_slice(value);
        pad(&mut buf);
        Ok(age::encrypt(&self.value_rcpt, &buf)?)
    }

    fn encrypt_meta(&self, meta: &Meta) -> Result<Vec<u8>> {
        let mut buf = Zeroizing::new(serde_json::to_vec(meta)?);
        buf.push(b'\n');
        let target = buf.len().div_ceil(PAD) * PAD;
        buf.resize(target, b' ');
        Ok(age::encrypt(&self.meta_rcpt, &buf)?)
    }

    /// Store a value and its metadata.
    pub fn put(&self, mk: &MetaKeys, meta: &Meta, value: &[u8]) -> Result<()> {
        names::validate(&meta.name)?;
        let id = mk.file_id(&meta.name);
        let ct = self.encrypt_value(&meta.name, value)?;
        util::write_atomic(&self.value_path(&id), &ct)?;
        self.put_meta(mk, meta)
    }

    pub fn put_meta(&self, mk: &MetaKeys, meta: &Meta) -> Result<()> {
        names::validate(&meta.name)?;
        let id = mk.file_id(&meta.name);
        util::write_atomic(&self.meta_path(&id), &self.encrypt_meta(meta)?)?;
        Ok(())
    }

    fn decrypt_meta_file(&self, mk: &MetaKeys, path: &Path) -> Result<Meta> {
        let ct = fs::read(path)?;
        let pt = Zeroizing::new(age::decrypt(&mk.identity, &ct)?);
        let meta: Meta = serde_json::from_slice(&pt)
            .with_context(|| format!("corrupt metadata {}", path.display()))?;
        Ok(meta)
    }

    pub fn read_meta(&self, mk: &MetaKeys, name: &str) -> Result<Option<Meta>> {
        let id = mk.file_id(name);
        let path = self.meta_path(&id);
        if !path.exists() {
            return Ok(None);
        }
        let meta = self.decrypt_meta_file(mk, &path)?;
        if meta.name != name {
            bail!("metadata for {name} is bound to a different name — vault tampered?");
        }
        Ok(Some(meta))
    }

    /// Metadata for every secret, sorted by name. Files whose content does not
    /// match their HMAC id (swapped/renamed by someone) are reported and skipped.
    pub fn all_meta(&self, mk: &MetaKeys) -> Result<Vec<Meta>> {
        let dir = self.home.join("m");
        let mut out = Vec::new();
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        let mut files = Vec::new();
        for ent in rd {
            let ent = ent?;
            let fname = ent.file_name().to_string_lossy().to_string();
            if fname.starts_with('.') || !fname.ends_with(".age") {
                continue;
            }
            files.push((fname, ent.path()));
        }
        // X25519 per file dominates; spread it over a few threads.
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 8);
        let chunk = files.len().div_ceil(threads).max(16);
        let results: Vec<(String, Result<Meta>)> = std::thread::scope(|sc| {
            let handles: Vec<_> = files
                .chunks(chunk)
                .map(|part| {
                    sc.spawn(move || {
                        part.iter()
                            .map(|(f, p)| (f.clone(), self.decrypt_meta_file(mk, p)))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap_or_default())
                .collect()
        });
        for (fname, res) in results {
            let id = fname.trim_end_matches(".age");
            match res {
                Ok(m) if mk.file_id(&m.name) == id => out.push(m),
                Ok(m) => eprintln!(
                    "openvault: warning: metadata file {fname} claims name {:?} but does not match it; ignoring (tampered?)",
                    m.name
                ),
                Err(e) => eprintln!("openvault: warning: unreadable metadata {fname}: {e}"),
            }
        }
        out.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Decrypt a value. The plaintext is bound to its name, so a value file
    /// moved or swapped under another name is rejected.
    pub fn read_value(
        &self,
        mk: &MetaKeys,
        vk: &x25519::Identity,
        name: &str,
    ) -> Result<SecretBuf> {
        let path = self.value_path(&mk.file_id(name));
        let ct = fs::read(&path).with_context(|| format!("no secret named {name}"))?;
        let mut pt = age::decrypt(vk, &ct).with_context(|| format!("cannot decrypt {name}"))?;
        let res = parse_value(&pt, name);
        let out = res.map(|v| SecretBuf::new(v.to_vec()));
        pt.zeroize();
        out
    }

    pub fn remove(&self, mk: &MetaKeys, name: &str) -> Result<bool> {
        let id = mk.file_id(name);
        let v = self.value_path(&id);
        let m = self.meta_path(&id);
        let existed = v.exists() || m.exists();
        for p in [v, m] {
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(existed)
    }

    /// Raw ciphertexts (value, meta) for undo backups.
    pub fn raw(&self, mk: &MetaKeys, name: &str) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let id = mk.file_id(name);
        (
            fs::read(self.value_path(&id)).ok(),
            fs::read(self.meta_path(&id)).ok(),
        )
    }

    pub fn restore_raw(&self, mk: &MetaKeys, name: &str, value: &[u8], meta: &[u8]) -> Result<()> {
        let id = mk.file_id(name);
        util::write_atomic(&self.value_path(&id), value)?;
        util::write_atomic(&self.meta_path(&id), meta)?;
        Ok(())
    }

    pub fn value_ciphertext_hash(&self, mk: &MetaKeys, name: &str) -> Option<String> {
        fs::read(self.value_path(&mk.file_id(name)))
            .ok()
            .map(|b| util::sha256_hex(&b))
    }

    /// Encrypt arbitrary small records (import undo logs) to the metadata key.
    pub fn seal_meta_blob(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(age::encrypt(&self.meta_rcpt, data)?)
    }

    pub fn open_meta_blob(&self, mk: &MetaKeys, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(age::decrypt(&mk.identity, ct)?))
    }
}

fn parse_value<'a>(pt: &'a [u8], name: &str) -> Result<&'a [u8]> {
    let bad = || anyhow::anyhow!("corrupt secret payload for {name}");
    let mut parts = pt.splitn(4, |b| *b == b'\n');
    let magic = parts.next().ok_or_else(bad)?;
    let bound = parts.next().ok_or_else(bad)?;
    let len = parts.next().ok_or_else(bad)?;
    let rest = parts.next().ok_or_else(bad)?;
    if magic != VALUE_MAGIC.as_bytes() {
        return Err(bad());
    }
    if bound != name.as_bytes() {
        bail!(
            "secret file for {name} is bound to {:?} — it was swapped or renamed (vault tampered?)",
            String::from_utf8_lossy(bound)
        );
    }
    let len: usize = std::str::from_utf8(len)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(bad)?;
    rest.get(..len).ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_payload_binds_name() {
        let vk = x25519::Identity::generate();
        let mut buf = format!("{VALUE_MAGIC}\ngithub/token\n5\n").into_bytes();
        buf.extend_from_slice(b"abcde");
        pad(&mut buf);
        assert_eq!(buf.len(), PAD);
        let ct = age::encrypt(&vk.to_public(), &buf).unwrap();
        let pt = age::decrypt(&vk, &ct).unwrap();
        assert_eq!(parse_value(&pt, "github/token").unwrap(), b"abcde");
        assert!(parse_value(&pt, "aws/key").is_err());
    }

    #[test]
    fn meta_keys_roundtrip_and_ids_are_opaque() {
        let mk = MetaKeys::generate();
        let s = mk.serialize();
        let mk2 = MetaKeys::parse(&s).unwrap();
        assert_eq!(mk.file_id("github/token"), mk2.file_id("github/token"));
        assert_ne!(mk.file_id("github/token"), mk.file_id("github/tokem"));
        assert_eq!(mk.file_id("a").len(), 32);
        assert!(!mk.file_id("github/token").contains("github"));
        let other = MetaKeys::generate();
        assert_ne!(mk.file_id("github/token"), other.file_id("github/token"));
    }

    #[test]
    fn recovery_bundle_roundtrip() {
        let v = x25519::Identity::generate();
        let m = MetaKeys::generate();
        let b = recovery_bundle(&v, &m);
        let (v2, m2) = parse_recovery_bundle(&b).unwrap();
        assert_eq!(v.to_public().to_string(), v2.to_public().to_string());
        assert_eq!(m.file_id("x"), m2.file_id("x"));
    }
}
