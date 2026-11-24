//! The one audited module allowed to use `unsafe`: thin wrappers over libc for
//! process hardening, memory locking and a few process-identity lookups.
//!
//! Everything here is best-effort hardening: failures are ignored (or reported
//! as `false`) because the security of stored secrets never depends on them.
#![allow(unsafe_code)]

use std::fs;
use std::io;
use std::path::Path;

use zeroize::Zeroize;

/// Harden the current process before it touches plaintext:
/// - no core dumps (`RLIMIT_CORE = 0`), so a crash cannot spill secrets to disk;
/// - macOS: `PT_DENY_ATTACH`, so debuggers / other processes cannot attach;
/// - Linux: `PR_SET_DUMPABLE = 0`, which also blocks same-user `ptrace` attach
///   and hides `/proc/<pid>/mem`.
pub fn harden_process() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit with a valid, fully initialised struct.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
    #[cfg(target_os = "macos")]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        // SAFETY: PT_DENY_ATTACH takes no address/data arguments.
        unsafe {
            libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) has no pointer arguments.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

/// Is the current process marked non-dumpable (core limit zero)? Used by tests.
pub fn core_dumps_disabled() -> bool {
    let mut lim = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: getrlimit writes into a valid struct we own.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
    rc == 0 && lim.rlim_cur == 0
}

/// A heap buffer for plaintext secret material: `mlock`ed so it is never
/// swapped to disk (best effort), and zeroed before it is freed.
pub struct SecretBuf {
    data: Vec<u8>,
    locked: bool,
}

impl SecretBuf {
    pub fn new(mut data: Vec<u8>) -> Self {
        data.shrink_to_fit();
        let locked = !data.is_empty()
            // SAFETY: the pointer/len pair describes memory owned by `data`, which
            // is not reallocated for the lifetime of this SecretBuf.
            && unsafe { libc::mlock(data.as_ptr() as *const libc::c_void, data.len()) } == 0;
        SecretBuf { data, locked }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.data.zeroize();
        if self.locked {
            // SAFETY: same region that was successfully mlock'ed in `new`. The Vec's
            // capacity is still allocated (zeroize clears but does not free).
            unsafe {
                libc::munlock(
                    self.data.as_ptr() as *const libc::c_void,
                    self.data.capacity(),
                );
            }
        }
    }
}

impl std::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBuf({} bytes, redacted)", self.data.len())
    }
}

pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub fn ppid() -> u32 {
    // SAFETY: getppid has no preconditions and cannot fail.
    unsafe { libc::getppid() as u32 }
}

/// Best-effort name of the parent process (for the audit log's "who").
pub fn parent_process_name() -> Option<String> {
    process_name(ppid())
}

/// Name of any process by pid (best effort; used to attribute session requests).
pub fn process_name(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: buffer pointer and size describe `buf`, which outlives the call.
        let n = unsafe {
            libc::proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as u32,
            )
        };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        let path = String::from_utf8_lossy(&buf).to_string();
        Some(
            Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or(path),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Credentials of the process on the other end of a Unix socket: (uid, pid).
/// Uses `getpeereid` + `LOCAL_PEERPID` on macOS and `SO_PEERCRED` on Linux;
/// the kernel fills these in, so the peer cannot lie about them.
pub fn peer_credentials(fd: std::os::fd::RawFd) -> io::Result<(u32, Option<u32>)> {
    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: fd is a connected Unix socket owned by the caller; out-params are valid.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        const SOL_LOCAL: libc::c_int = 0;
        const LOCAL_PEERPID: libc::c_int = 2;
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: valid fd and out-params sized for pid_t.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        Ok((uid, (rc == 0).then_some(pid as u32)))
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: valid fd and out-params sized for ucred.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((cred.uid, Some(cred.pid as u32)))
    }
}

/// Ignore SIGHUP (the session agent must outlive the terminal that started it).
pub fn ignore_hangup() {
    // SAFETY: installing SIG_IGN for a standard signal.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
}

/// Ignore SIGINT/SIGQUIT in this process (the child still receives them from the
/// terminal), so a Ctrl-C reaches the child and we keep relaying its output.
pub fn ignore_terminal_signals() {
    // SAFETY: installing SIG_IGN for standard signals.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
}

/// Refuse to operate on a path that other users could read or tamper with.
/// `max_mode` are the permission bits that are tolerated (e.g. 0o700).
pub fn check_private(path: &Path, what: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if md.file_type().is_symlink() {
        anyhow::bail!("refusing to use {what} {}: it is a symlink", path.display());
    }
    if md.uid() != euid() {
        anyhow::bail!(
            "refusing to use {what} {}: owned by uid {}, not you (uid {})",
            path.display(),
            md.uid(),
            euid()
        );
    }
    if md.mode() & 0o077 != 0 {
        anyhow::bail!(
            "refusing to use {what} {}: permissions {:o} are too open (group/other access). Fix with: chmod -R go-rwx {}",
            path.display(),
            md.mode() & 0o777,
            path.display()
        );
    }
    Ok(())
}

/// Refuse a project policy file that someone else could rewrite to widen access.
pub fn check_not_writable_by_others(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = fs::metadata(path)?;
    if md.mode() & 0o022 != 0 {
        anyhow::bail!(
            "refusing to trust {}: it is writable by group/other (mode {:o}). Fix with: chmod go-w {}",
            path.display(),
            md.mode() & 0o777,
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_buf_roundtrip_and_debug_is_redacted() {
        let b = SecretBuf::new(b"hunter2".to_vec());
        assert_eq!(b.as_bytes(), b"hunter2");
        assert!(!format!("{b:?}").contains("hunter2"));
    }

    #[test]
    fn rejects_world_readable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_private(d.path(), "vault").is_err());
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_private(d.path(), "vault").is_ok());
    }
}
