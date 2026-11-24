# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/ElevenRyu/openvault/security/advisories/new).
Do not open a public issue. We aim to acknowledge within 72 hours and to ship
a fix or mitigation within 14 days for high-severity issues.

Useful details: openvault version (`openvault --version`), OS, unlock mode
(Secure Enclave or passphrase), and a minimal reproduction.

## Supported versions

Only the latest release receives security fixes while openvault is pre-1.0.

## Design and threat model

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for attackers, mitigations,
the tests that prove each property, and the explicit non-goals.

## Security checklist

| Property | How it is enforced | Test |
|---|---|---|
| No plaintext on disk | values go stdin → age ciphertext; atomic 0600 writes; core dumps off | `nothing_in_the_vault_reveals_names_or_values`, `child_runs_without_core_dumps` |
| Names and metadata encrypted at rest | separate metadata key; HMAC file ids; 256-byte padding | `nothing_in_the_vault_reveals_names_or_values` |
| Strict permissions | 0700 dirs / 0600 files; refuse loose perms, foreign owner, symlinks | `loose_permissions_are_refused`, `platform::rejects_world_readable_dir` |
| No tool returns a value | `get` needs a terminal; `--reveal` needs a terminal + fresh auth; MCP has no value tool | `get_refuses_non_tty_without_reveal`, `reveal_requires_terminal_or_root_key`, `mcp_server_*` |
| Output redaction | raw, base64 (all alignments), hex, URL-encoded; across chunk boundaries | `run_redacts_encodings_and_split_writes`, `redact::*`, fuzz target `redact` |
| Minimal child env | only requested vars; `OPENVAULT_*` stripped; `--clean-env`; MCP always clean | `child_env_is_scrubbed_and_clean_env_is_minimal` |
| Project allowlist | `.openvault.toml` `allow` / `[env]`; refuse world-writable policy | `project_policy_maps_env_and_blocks_others`, `world_writable_policy_file_is_refused` |
| Per-secret confirmation | tag `confirm` / `confirm_tags` ⇒ fresh Touch ID | `confirm_tag_rejects_non_interactive_unlock` |
| Tamper-evident audit | SHA-256 hash chain; who/what/where, never values | `audit_log_is_hash_chained` |
| Tamper-evident storage | values bound to names inside the ciphertext | `swapped_ciphertexts_are_detected` |
| Memory hygiene | `zeroize`, `mlock`, `RLIMIT_CORE=0`, `PT_DENY_ATTACH` / `PR_SET_DUMPABLE` | `platform::*`, `child_runs_without_core_dumps` |
| Hostile imports | size caps, zip-bomb cap, no panics, fuzzed, `--shred` | `import_rejects_*`, `parsers_never_panic_on_garbage`, `import_shred_removes_plaintext_export` |
| Session unlock without key on disk | in-memory agent, 0600 socket in 0700 dir, peer-uid check, TTL/lock/sleep/screen-lock expiry, `confirm` refused by the agent, requests audited with pid | `tests/session.rs`, `session::tests` |
| Supply chain | `cargo deny`, `cargo audit`, unsafe confined, reproducible build, static musl binary | CI jobs `supply-chain`, `reproducible`, `static-linux` |

## Verifying a build

```sh
git clone https://github.com/ElevenRyu/openvault && cd openvault
RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME/.cargo=/cargo" \
  cargo build --release --locked
sha256sum target/release/openvault   # compare with the release checksum
```

CI builds the same commit twice from different directories and requires
byte-identical output.
