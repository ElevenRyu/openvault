# openvault threat model

openvault stores secrets so that **programs and AI agents can use them without
ever seeing them**, and so that a copy of the vault (disk image, backup, git
remote) is worthless without a human-held key. This document lists what we
defend against, how, and — just as important — what we do not.

## Assets

| Asset | Where it lives |
|---|---|
| Secret values | `v/<id>.age`, encrypted to the **value key** |
| Secret metadata (name, env var, description, tags, scope) | `m/<id>.age`, encrypted to the **metadata key** |
| Value key (X25519) | wrapped by the Secure Enclave (`keys/se.age`) or an scrypt passphrase (`keys/passphrase.age`), and by the recovery key |
| Metadata key (X25519 + 256-bit HMAC name key) | wrapped by the value key (`keys/meta.age`) and the recovery key; cached in the macOS login Keychain (or a 0600 local file on Linux) |
| Recovery key (X25519) | on paper, offline. Never stored by openvault |

All encryption is [age](https://age-encryption.org) (X25519 + ChaCha20-Poly1305,
scrypt for passphrases) via the audited `age` crate. openvault contains no
hand-written cryptography.

## Attackers and mitigations

### 1. A malicious or compromised agent / prompt injection

The agent runs commands as you, in your shell, and may have been told by a
web page or a README to exfiltrate your keys.

| Attack | Mitigation | Test |
|---|---|---|
| `openvault get x` and read stdout | `get` refuses non-terminals; `--reveal` additionally requires a terminal on stdin **and** a fresh Touch ID / typed passphrase (or `OPENVAULT_IDENTITY`, i.e. the root key itself) | `get_refuses_non_tty_without_reveal`, `reveal_requires_terminal_or_root_key` |
| MCP tool that returns a value | No such tool exists. `search`/`list_env` return metadata; `run` returns redacted output | `mcp_server_searches_and_runs_without_returning_values` |
| `run -- sh -c 'echo $TOKEN'` | Streaming redaction of stdout/stderr: raw value, base64 (std/url, padded or not, at all three byte alignments so it is caught inside larger blobs), hex (lower/upper), percent-encoding; matches split across reads are caught | `run_redacts_encodings_and_split_writes`, `redact::*`, `fuzz/redact` |
| `run --no-redact` | Requires stdin **and** stdout to be a terminal | `no_redact_requires_a_terminal` |
| Child reads unrelated secrets from env | Only requested vars are injected; `OPENVAULT_*` (incl. `OPENVAULT_IDENTITY`) and unresolved `secret://` refs are stripped; MCP children (and `--clean-env`) get a minimal env (PATH, HOME, LANG, …) | `child_env_is_scrubbed_and_clean_env_is_minimal` |
| Using secrets outside the project | `.openvault.toml` allowlist enforced for `run`/`get`/MCP; per-secret `--scope` directories | `project_policy_maps_env_and_blocks_others`, `scoped_secret_cannot_be_used_elsewhere` |
| Widening policy by editing `.openvault.toml` | Refused if writable by group/other. **An agent that can write your files can edit it** — see limits | `world_writable_policy_file_is_refused` |
| Silent use of high-value secrets | Tag `confirm` (or a project's `confirm_tags`) forces a fresh Touch ID / passphrase even when `OPENVAULT_IDENTITY` is set | `confirm_tag_rejects_non_interactive_unlock` |
| Covering tracks | Hash-chained audit log of every read/denial with pid, parent process, uid, cwd and agent markers (`CLAUDECODE`, `CODEX_*`, `CURSOR_*`, …); `openvault audit verify` | `audit_log_is_hash_chained`, `audit::chain_detects_tampering` |
| Attaching a debugger to read plaintext from memory | `PT_DENY_ATTACH` (macOS) / `PR_SET_DUMPABLE=0` (Linux), no core dumps (`RLIMIT_CORE=0`, inherited by children), plaintext in `mlock`ed buffers that are zeroed on drop | `child_runs_without_core_dumps`, `platform::*` |

**Limits (be honest):** redaction is a seatbelt, not a sandbox. A child process
*has* the plaintext; a hostile command can encrypt, compress, reverse or
slowly leak it through the network. In Secure Enclave mode every `run`/`get`
needs your fingerprint, so you see each use — that is the real boundary.
An agent with write access to your home directory can also replace the
`openvault` binary or edit shell rc files; no CLI can defend against that.

### 2. Another local user

Vault directories are `0700`, files `0600`, written atomically. openvault
**refuses to run** if the vault or key directory is group/other-accessible,
not owned by you, or a symlink (`loose_permissions_are_refused`). The audit log
is `0600` and opened `O_APPEND`.

### 3. Stolen disk, laptop, or backup

* Values need the value key, which is sealed by the **Secure Enclave** (a
  non-exportable P-256 key created with `any-biometry` access control by
  `age-plugin-se`; it cannot be extracted from the chip or used on another
  Mac) or by an **scrypt** passphrase (memory-hard; we enforce ≥ 12
  characters and warn loudly that passphrase mode is offline-attackable).
* Names and metadata are encrypted too. The metadata key is cached in the
  macOS **login Keychain** (encrypted with your login password); on Linux it is
  cached in `keys/meta.key` (0600, git-ignored) — a stolen Linux disk without
  full-disk encryption reveals *names*, never values. Set
  `OPENVAULT_META_CACHE=none` at `init` to require an unlock for metadata too.
* No plaintext ever touches disk: values go from stdin straight into an
  encrypted file; temp files hold only ciphertext; core dumps are disabled.

### 4. Compromised git remote / sync folder

Everything outside `audit.log` and `keys/meta.key` (both git-ignored) is
safe to sync. A remote attacker sees:

* the **number** of secrets and their sizes rounded up to 256 bytes;
* file ids that are `HMAC-SHA256(name_key, name)` — no names, no grouping;
* public recipients in `vault.json`.

Integrity: an attacker with push access can delete or roll back files, and
can swap ciphertexts between ids. Swaps are detected — every value is bound
to its name inside the encryption, and metadata ids are re-derived and
checked on read (`swapped_ciphertexts_are_detected`). Rollback to an older
*valid* ciphertext of the same secret is **not** detected; review vault
history like any other code.

### 5. A malicious import file

Exports come from elsewhere and are parsed by code that holds your keys:

* hard caps: 64 MiB input, 256 MiB decompressed `export.data` (zip bombs),
  100 000 items, 1 MiB per value; zip entries are never extracted to disk;
* all parsers are written without indexing panics and are fuzzed
  (`fuzz/fuzz_targets/import.rs` in CI, plus a stable-toolchain mutation test
  `parsers_never_panic_on_garbage`);
* values are never echoed — `--dry-run` previews show names and sources only;
* names are slugged to `[a-z0-9._-]` so no path traversal is possible;
* `--shred` overwrites and deletes the plaintext export after a successful
  import (and openvault offers to on a terminal). On SSDs and copy-on-write
  file systems this is best effort.

### 6. Supply chain

* Small, mainstream dependency set; `Cargo.lock` committed; `--locked` builds.
* `cargo deny` (licenses, advisories, sources: crates.io only) and
  `cargo audit` run in CI. Ignored advisories are listed with justification
  in `deny.toml`.
* `#![deny(unsafe_code)]` crate-wide; the only exception is
  `src/platform.rs` (libc calls for hardening), enforced by a CI grep.
* Release builds are checked for reproducibility in CI (two builds from
  different paths must be byte-identical). Linux builds are static (musl).
* Secure Enclave support uses the external `age-plugin-se` binary from your
  `PATH`; its integrity is your package manager's responsibility.

## Session unlock (one Touch ID per 15 minutes)

**Choice: a short-lived per-user agent process, not a Keychain item.**
After a fresh Touch ID (or `openvault unlock --for 15m`), `openvault __agent`
holds the value key in `mlock`ed memory and serves decryptions over a Unix
socket until the TTL ends, `openvault lock` is run, the machine sleeps, or (macOS)
the screen locks. It then deletes the socket and zeroizes the key.

Why not a Keychain item with `kSecAttrAccessible…ThisDeviceOnly` + an
`LAContext` reuse window? The `LAContext` reuse duration lives inside one
process, so a CLI that exits after every command cannot share it. Making it
work would mean caching the key in the Keychain itself, which puts key material
on disk (encrypted by the login keychain). It would also need Objective-C/Swift
bindings and code signing for the data-protection keychain. The agent keeps
the "no key material on disk, ever" property and needs no entitlements.

| Control | Detail |
|---|---|
| Key never leaves the agent | clients send *names*; the agent decrypts and returns only those values |
| Socket | `0600` in a `0700` per-user dir (`$XDG_RUNTIME_DIR/openvault` or `/tmp/openvault-<uid>`, refused if not ours) |
| Peer check | kernel-provided peer uid (`getpeereid` / `SO_PEERCRED`) must equal ours; rejections are audited |
| Process hardening | no core dumps, `PT_DENY_ATTACH` / non-dumpable, minimal environment, own process group |
| Expiry | TTL (default 15 min, `session_ttl` in `vault.json`, `OPENVAULT_SESSION_TTL`, `unlock --for`, max 24 h), `lock`, sleep (wall vs monotonic clock), macOS screen lock (`IOConsoleLocked`) |
| `confirm` secrets | the **agent** refuses them, so a direct socket client cannot bypass the fresh-Touch-ID rule |
| Attribution | every session read is audited with the requesting pid and process name |

**New risk:** while a session is open, any process running as you can ask the
agent for values. That includes an agent, or a script it writes, talking to the
socket directly and skipping the CLI's project policy. Mitigations: the session
is short and visible (`openvault unlock` prints its length), `confirm` secrets are
never released, the agent keeps the secret *bound* to its name (no swaps), and every
request lands in the hash-chained audit log with the requesting process. For
the strictest setup set `session_ttl = "0"`: every use then needs Touch ID.
Tests: `tests/session.rs` (TTL expiry, lock, confirm refusal incl. direct
socket, socket permissions, audit attribution, MCP) and `session::tests`
(peer-uid rejection, kernel peer credentials).

## Out of scope

* Root / kernel compromise, malware running as you with write access to your
  home directory or binaries, hardware attacks on the Secure Enclave.
* Keyloggers capturing a typed passphrase (use Secure Enclave mode).
* Values once handed to a child process — that program is trusted with them.
* Truncation of the tail of the audit log (the chain proves the prefix is
  intact; anchor `openvault audit verify` output elsewhere if you need more).
* Memory that `std` or `age` allocate internally (we zero and lock our own
  buffers; the copies inside `std::process::Command`'s environment cannot be).
