//! Session unlock: one Touch ID unlocks values for a limited time.
//!
//! After a successful unlock, a short-lived per-user **session agent**
//! (`openvault __agent`) holds the value key in `mlock`ed memory and decrypts
//! on request over a Unix socket. The key never leaves that process — clients
//! receive only the values they ask for — and it never touches disk.
//!
//! * socket `0600` inside a `0700` per-user runtime dir; every connection's peer
//!   uid is checked with `getpeereid` / `SO_PEERCRED` (kernel-provided);
//! * the agent is hardened like every openvault process (no core dumps,
//!   `PT_DENY_ATTACH` / non-dumpable) and zeroizes the key on expiry;
//! * it exits after the TTL (default 15 min), on `openvault lock`, when the
//!   machine sleeps, and (macOS) when the screen locks;
//! * secrets tagged `confirm` are refused by the agent: they always need a
//!   fresh Touch ID;
//! * every request is written to the audit log with the requesting pid and
//!   process name.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use age::secrecy::ExposeSecret;
use age::x25519;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::audit;
use crate::names;
use crate::platform::{self, SecretBuf};
use crate::unlock::{self, Auth, ValueKey};
use crate::util;
use crate::vault::{self, MetaKeys, Vault};

pub const DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_REQUEST: u64 = 64 * 1024;
const MAX_NAMES: usize = 256;

/// Parse `90`, `90s`, `15m`, `2h`. `0` disables sessions.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        _ => (s, 1),
    };
    let n: u64 = num
        .parse()
        .with_context(|| format!("invalid duration {s:?} (use e.g. 90s, 15m, 1h)"))?;
    let secs = n.checked_mul(mult).context("duration too large")?;
    if secs > 24 * 3600 {
        bail!("session TTL is capped at 24h");
    }
    Ok(Duration::from_secs(secs))
}

/// TTL for automatically started sessions: `OPENVAULT_SESSION_TTL`, then
/// `session_ttl` in vault.json, then 15 minutes.
pub fn configured_ttl(v: &Vault) -> Result<Duration> {
    if let Ok(s) = std::env::var("OPENVAULT_SESSION_TTL") {
        return parse_duration(&s);
    }
    match &v.cfg.session_ttl {
        Some(s) => parse_duration(s),
        None => Ok(DEFAULT_TTL),
    }
}

pub fn runtime_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("OPENVAULT_RUNTIME_DIR") {
        return PathBuf::from(d);
    }
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(d).join("openvault");
    }
    PathBuf::from(format!("/tmp/openvault-{}", platform::euid()))
}

pub fn socket_path(v: &Vault) -> PathBuf {
    let id: String = v.cfg.id.chars().take(16).collect();
    runtime_dir().join(format!("{id}.sock"))
}

/// Reject peers that are not the same user. Pure so it can be unit-tested.
pub fn authorize_peer(peer_uid: u32, my_uid: u32) -> Result<()> {
    if peer_uid != my_uid {
        bail!("peer uid {peer_uid} is not the session owner (uid {my_uid})");
    }
    Ok(())
}

// ------------------------------------------------------------------ client

pub struct Client {
    path: PathBuf,
}

impl Client {
    /// Connect to a live session for this vault, if any.
    pub fn connect(v: &Vault) -> Option<Client> {
        let path = socket_path(v);
        if !path.exists() {
            return None;
        }
        if platform::check_private(path.parent()?, "session directory").is_err() {
            return None;
        }
        let c = Client { path };
        match c.request(&json!({"op": "status"})) {
            Ok(r) if r["ok"] == true => Some(c),
            _ => None,
        }
    }

    fn request(&self, req: &Value) -> Result<Value> {
        let mut s = UnixStream::connect(&self.path)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut line = serde_json::to_vec(req)?;
        line.push(b'\n');
        s.write_all(&line)?;
        let mut resp = Zeroizing::new(String::new());
        BufReader::new(s.take(16 * 1024 * 1024)).read_line(&mut resp)?;
        let v: Value = serde_json::from_str(&resp).context("bad session response")?;
        Ok(v)
    }

    pub fn expires_in(&self) -> Result<u64> {
        let r = self.request(&json!({"op": "status"}))?;
        Ok(r["expires_in"].as_u64().unwrap_or(0))
    }

    pub fn lock(&self) -> Result<()> {
        let _ = self.request(&json!({"op": "lock"}));
        Ok(())
    }

    pub fn decrypt(&self, names: &[String]) -> Result<Vec<SecretBuf>> {
        let r = self.request(&json!({"op": "decrypt", "names": names}))?;
        if r["ok"] != true {
            bail!(
                "{}",
                r["error"].as_str().unwrap_or("session refused the request")
            );
        }
        let vals = r["values"].as_array().context("bad session response")?;
        if vals.len() != names.len() {
            bail!("bad session response");
        }
        vals.iter()
            .map(|h| {
                let h = Zeroizing::new(h.as_str().unwrap_or_default().to_string());
                vault::decode_hex_pub(&h)
                    .map(SecretBuf::new)
                    .context("bad session response")
            })
            .collect()
    }
}

/// Stop the session for this vault. Returns whether one was running.
pub fn lock(v: &Vault) -> Result<bool> {
    match Client::connect(v) {
        Some(c) => {
            c.lock()?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Start a session agent holding `vk` for `ttl`.
pub fn start(v: &Vault, vk: &x25519::Identity, ttl: Duration) -> Result<()> {
    if ttl.is_zero() {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    // The agent gets a minimal environment: nothing secret, and no agent markers
    // from whoever started it (its audit entries describe the *requester*).
    cmd.env_clear();
    for k in ["PATH", "HOME", "OPENVAULT_RUNTIME_DIR", "XDG_RUNTIME_DIR"] {
        if let Some(val) = std::env::var_os(k) {
            cmd.env(k, val);
        }
    }
    let mut child = cmd
        .arg("__agent")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .context("could not start the session agent")?;
    {
        let mut stdin = child.stdin.take().context("agent stdin")?;
        let msg = Zeroizing::new(format!(
            "{}\n{}\n{}\n",
            ttl.as_secs(),
            v.home.display(),
            vk.to_string().expose_secret()
        ));
        stdin.write_all(msg.as_bytes())?;
    }
    let mut ready = String::new();
    BufReader::new(child.stdout.take().context("agent stdout")?).read_line(&mut ready)?;
    if ready.trim() != "ready" {
        let _ = child.wait();
        bail!("the session agent failed to start");
    }
    Ok(())
}

// ------------------------------------------------------------------ values

/// Where plaintext values come from for this command.
pub enum Values {
    Key(ValueKey),
    Session(Client),
}

impl Values {
    pub fn auth(&self) -> Auth {
        match self {
            Values::Key(k) => k.auth,
            Values::Session(_) => Auth::Session,
        }
    }

    pub fn read_many(&self, v: &Vault, mk: &MetaKeys, names: &[String]) -> Result<Vec<SecretBuf>> {
        match self {
            Values::Key(k) => names
                .iter()
                .map(|n| v.read_value(mk, &k.identity, n))
                .collect(),
            Values::Session(c) => c.decrypt(names),
        }
    }
}

/// Get access to values: the root key from the environment, else a live
/// session, else a fresh Touch ID / passphrase unlock (which then starts a
/// session). With `require_fresh` (secrets tagged `confirm`), only a fresh
/// human unlock is accepted.
pub fn values(v: &Vault, require_fresh: bool) -> Result<Values> {
    if !require_fresh {
        if std::env::var_os(unlock::ENV_IDENTITY).is_some() {
            return Ok(Values::Key(unlock::value_key(v, false)?));
        }
        if let Some(c) = Client::connect(v) {
            return Ok(Values::Session(c));
        }
    }
    let vk = unlock::value_key(v, require_fresh)?;
    if vk.auth == Auth::Interactive && Client::connect(v).is_none() {
        let ttl = configured_ttl(v)?;
        if let Err(e) = start(v, &vk.identity, ttl) {
            eprintln!("openvault: warning: could not start a session ({e}); you will be asked again next time");
        } else if !ttl.is_zero() {
            eprintln!(
                "openvault: unlocked for {} (openvault lock to end early)",
                human(ttl)
            );
        }
    }
    Ok(Values::Key(vk))
}

pub fn human(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 && s.is_multiple_of(3600) {
        format!("{}h", s / 3600)
    } else if s >= 60 && s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

// ------------------------------------------------------------------ agent

struct Shared {
    key: Mutex<Option<SecretBuf>>,
    socket: PathBuf,
}

impl Shared {
    fn shutdown(&self, why: &str) -> ! {
        let _ = std::fs::remove_file(&self.socket);
        if let Ok(mut k) = self.key.lock() {
            k.take(); // SecretBuf zeroizes + munlocks on drop
        }
        let _ = why;
        std::process::exit(0)
    }
}

/// Body of the hidden `openvault __agent` subcommand.
pub fn serve_agent() -> Result<()> {
    platform::ignore_hangup();
    platform::ignore_terminal_signals();
    let mut input = Zeroizing::new(String::new());
    std::io::stdin().take(4096).read_to_string(&mut input)?;
    let mut lines = input.lines();
    let ttl: u64 = lines.next().context("ttl")?.parse()?;
    let home = PathBuf::from(lines.next().context("home")?);
    let key = SecretBuf::new(lines.next().context("key")?.trim().as_bytes().to_vec());
    drop(input);

    let v = Vault::open_at(&home)?;
    let identity = parse_identity(&key)?;
    let mk = unlock::meta_from_value(&v, &identity)?;
    drop(identity);

    let dir = runtime_dir();
    util::create_private_dir(&dir)?;
    platform::check_private(&dir, "session directory")?;
    let sock = socket_path(&v);
    if sock.exists() {
        if UnixStream::connect(&sock).is_ok() {
            bail!("a session is already running");
        }
        std::fs::remove_file(&sock)?;
    }
    let listener = UnixListener::bind(&sock)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    }
    let shared = Arc::new(Shared {
        key: Mutex::new(Some(key)),
        socket: sock.clone(),
    });
    let deadline = Instant::now() + Duration::from_secs(ttl);
    {
        let mut out = std::io::stdout().lock();
        out.write_all(b"ready\n")?;
        out.flush()?;
    }
    let w = Arc::clone(&shared);
    std::thread::spawn(move || watchdog(w, deadline));

    let me = platform::euid();
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let creds = platform::peer_credentials(stream.as_raw_fd());
        let (uid, pid) = match creds {
            Ok(c) => c,
            Err(_) => continue,
        };
        if authorize_peer(uid, me).is_err() {
            let _ = audit::record(
                &v.home,
                "session",
                &[],
                false,
                Some(format!("rejected connection from uid {uid}")),
                "session",
            );
            continue;
        }
        if let Some(lock_now) = handle(&v, &mk, &shared, stream, pid, deadline) {
            if lock_now {
                shared.shutdown("lock");
            }
        }
    }
    Ok(())
}

fn parse_identity(key: &SecretBuf) -> Result<x25519::Identity> {
    std::str::from_utf8(key.as_bytes())?
        .parse()
        .map_err(|_| anyhow::anyhow!("corrupt session key"))
}

/// Handle one request. Returns Some(true) when the session should end.
fn handle(
    v: &Vault,
    mk: &MetaKeys,
    shared: &Shared,
    stream: UnixStream,
    pid: Option<u32>,
    deadline: Instant,
) -> Option<bool> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new((&stream).take(MAX_REQUEST));
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let req: Value = serde_json::from_str(&line).ok()?;
    let who = match pid {
        Some(p) => format!(
            "pid {p} ({})",
            platform::process_name(p).unwrap_or_else(|| "?".into())
        ),
        None => "pid ?".into(),
    };
    let (resp, lock_now) = match req["op"].as_str() {
        Some("status") => (
            json!({"ok": true, "expires_in": deadline.saturating_duration_since(Instant::now()).as_secs()}),
            false,
        ),
        Some("lock") => {
            let _ = audit::record(
                &v.home,
                "lock",
                &[],
                true,
                Some(format!("by {who}")),
                "session",
            );
            (json!({"ok": true}), true)
        }
        Some("decrypt") => {
            let names: Vec<String> = req["names"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            match decrypt(v, mk, shared, &names) {
                Ok(vals) => {
                    let _ = audit::record(
                        &v.home,
                        "session-read",
                        &names,
                        true,
                        Some(format!("for {who}")),
                        "session",
                    );
                    (json!({"ok": true, "values": *vals}), false)
                }
                Err(e) => {
                    let _ = audit::record(
                        &v.home,
                        "session-read",
                        &names,
                        false,
                        Some(format!("for {who}: {e}")),
                        "session",
                    );
                    (json!({"ok": false, "error": e.to_string()}), false)
                }
            }
        }
        _ => (json!({"ok": false, "error": "unknown op"}), false),
    };
    let mut out = Zeroizing::new(serde_json::to_vec(&resp).unwrap_or_default());
    out.push(b'\n');
    let _ = (&stream).write_all(&out);
    Some(lock_now)
}

fn decrypt(
    v: &Vault,
    mk: &MetaKeys,
    shared: &Shared,
    names: &[String],
) -> Result<Zeroizing<Vec<String>>> {
    if names.is_empty() || names.len() > MAX_NAMES {
        bail!("bad request");
    }
    let guard = shared
        .key
        .lock()
        .map_err(|_| anyhow::anyhow!("session poisoned"))?;
    let key = guard.as_ref().context("session locked")?;
    let identity = parse_identity(key)?;
    let mut out = Zeroizing::new(Vec::with_capacity(names.len()));
    for n in names {
        names::validate(n)?;
        let meta = v
            .read_meta(mk, n)?
            .with_context(|| format!("no secret named {n}"))?;
        // Enforced here, not just in the client: a direct socket caller cannot
        // skip the fresh-Touch-ID rule for `confirm` secrets.
        if meta.tags.iter().any(|t| t == "confirm") {
            bail!("{n} is tagged `confirm` and needs a fresh Touch ID; sessions cannot release it");
        }
        let val = v.read_value(mk, &identity, n)?;
        out.push(util::hex(val.as_bytes()));
    }
    Ok(out)
}

/// End the session on TTL expiry, system sleep, or (macOS) screen lock.
fn watchdog(shared: Arc<Shared>, deadline: Instant) {
    let mut last_mono = Instant::now();
    let mut last_wall = SystemTime::now();
    let mut tick = 0u64;
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let now = Instant::now();
        if now >= deadline {
            shared.shutdown("ttl");
        }
        // The monotonic clock stops while the machine sleeps; the wall clock does not.
        let wall = SystemTime::now();
        let wall_dt = wall.duration_since(last_wall).unwrap_or_default();
        let mono_dt = now.duration_since(last_mono);
        if wall_dt > mono_dt + Duration::from_secs(10) {
            shared.shutdown("sleep");
        }
        last_mono = now;
        last_wall = wall;
        tick += 1;
        if tick.is_multiple_of(6) && screen_locked() {
            shared.shutdown("screen-lock");
        }
        if !shared.socket.exists() {
            shared.shutdown("socket removed");
        }
    }
}

#[cfg(target_os = "macos")]
fn screen_locked() -> bool {
    let Ok(out) = Command::new("/usr/sbin/ioreg")
        .args(["-n", "Root", "-d1", "-a"])
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let flag = |key: &str| {
        text.find(&format!("<key>{key}</key>"))
            .map(|i| {
                text[i..]
                    .lines()
                    .nth(1)
                    .unwrap_or_default()
                    .contains("<true/>")
            })
            .unwrap_or(false)
    };
    flag("IOConsoleLocked") || flag("CGSSessionScreenIsLocked")
}

#[cfg(not(target_os = "macos"))]
fn screen_locked() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert!(parse_duration("25h").is_err());
        assert!(parse_duration("abc").is_err());
        assert_eq!(human(Duration::from_secs(900)), "15m");
    }

    #[test]
    fn peer_uid_must_match() {
        assert!(authorize_peer(501, 501).is_ok());
        assert!(authorize_peer(0, 501).is_err());
        assert!(authorize_peer(502, 501).is_err());
    }

    #[test]
    fn peer_credentials_of_a_socketpair_are_ours() {
        let (a, _b) = UnixStream::pair().unwrap();
        let (uid, pid) = platform::peer_credentials(a.as_raw_fd()).unwrap();
        assert_eq!(uid, platform::euid());
        assert_eq!(pid, Some(std::process::id()));
    }
}
