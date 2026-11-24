# openvault

**Secrets your AI agents can use but never see.** Age-encrypted, Touch ID gated,
one static binary, no daemon, ~6 ms per read.

```sh
brew install age-plugin-se          # macOS: Secure Enclave + Touch ID (optional; passphrase otherwise)
cargo install --locked --git https://github.com/ElevenRyu/openvault   # installs `openvault` and `ov`
openvault init                      # write down the recovery key it prints
openvault add github/token --env GITHUB_TOKEN --desc "GitHub PAT"     # hidden prompt
openvault run --env GITHUB_TOKEN -- gh api user                       # injected + redacted
```

## Why openvault

1Password's `op`, Bitwarden's `bw` and `pass` were built for humans copying
passwords. Agents changed the problem: a coding agent runs commands as you, reads
everything they print, and can be prompt-injected. openvault is built for that.

| | openvault | `op` | `bw` | `pass` |
|---|---|---|---|---|
| Agent can **use** a secret without **seeing** it | ✅ `run` injects + redacts output (raw/base64/hex/URL) | partial: `op run` masks exact values | ❌ | ❌ |
| Refuses to print secrets to pipes/agents | ✅ | ❌ | ❌ | ❌ |
| Discovery without decryption (search, env vars per project) | ✅ `search`, `env`, MCP | partial | ❌ | ❌ |
| MCP server for agents | ✅ built in | ❌ | ❌ | ❌ |
| Hardware-bound root key | ✅ Secure Enclave + Touch ID | Touch ID unlocks the app | ❌ | GPG smartcard |
| Secret names hidden in the store | ✅ HMAC file ids | n/a (cloud) | n/a (cloud) | ❌ paths are names |
| Tamper-evident audit log | ✅ hash-chained, local | server-side (business plans) | server-side (paid plans) | ❌ |
| Daemon / account / network | none | desktop app + account | Node.js + account | gpg-agent |
| Standard, no lock-in format | ✅ plain [age](https://age-encryption.org) files | ❌ | ❌ | ✅ GPG |
| Import from the others | ✅ 1Password, Bitwarden, Apple, LastPass, .env | — | — | — |

### Benchmarks

Measured with [`bench/bench.sh`](bench/bench.sh) (hyperfine, 200+ runs, warm,
vault of 100 secrets, Apple M1 Max, macOS, release build, value key from
`OPENVAULT_IDENTITY` — Touch ID is human time and is excluded):

| Command | Mean |
|---|---:|
| `openvault --version` (cold start) | 5.3 ms |
| `openvault get --reveal github/token` | **5.7 ms** |
| `openvault run --only github/token -- true` (spawn + inject + redact) | 9.4 ms |
| `openvault ls` (decrypts 100 metadata files) | 7.9 ms |
| `openvault search token` | 7.9 ms |

About 3.5 ms of every invocation on macOS is the OS loading `Security.framework`
(for the Keychain); `/usr/bin/true` takes 1.2 ms on the same machine.

`op`, `bw` and `pass` were **not installed on the benchmark machine**, so we have
not measured them and do not quote numbers for them. `bench/bench.sh` benchmarks
`pass` automatically when `pass` and `gpg` are installed, and `op`/`bw` when you
export `OV_BENCH_OP_REF` / `OV_BENCH_BW_ID` — please send results. Structurally:
`bw` starts a Node.js runtime per call, `op` talks to the 1Password app over IPC,
and `pass` spawns `gpg`; openvault is one small native process (1.8 MB binary,
static on Linux).

## How it works

```
~/.openvault/            (OPENVAULT_HOME)          safe to commit/sync except audit.log & keys/meta.key
  vault.json             public recipients, unlock mode
  keys/se.age            value key, sealed by the Secure Enclave (Touch ID)
  keys/passphrase.age    …or by an scrypt passphrase (Linux/CI)
  keys/recovery.age      everything, sealed to your paper recovery key
  keys/meta.age          metadata key, sealed by the value key
  v/9f2c…e1.age          a secret value     (file id = HMAC(name); padded to 256 B)
  m/9f2c…e1.age          its metadata: name, env var, description, tags, scope
  audit.log              hash-chained log of every use (never values)
```

* **Two keys, two privileges.** The *metadata key* (cached in the macOS login
  Keychain) lets you and your agents search and list without a prompt. The
  *value key* only comes out of the Secure Enclave after Touch ID (or a typed
  passphrase), once per command.
* **No lock-in.** Every file is plain age. With the recovery key,
  `age -d -i recovery.txt keys/recovery.age` gives you all keys back.
* **No crypto written here.** X25519, ChaCha20-Poly1305 and scrypt come from the
  [`age`](https://crates.io/crates/age) crate; the Secure Enclave via
  [`age-plugin-se`](https://github.com/remko/age-plugin-se).

## Commands

| Command | What it does |
|---|---|
| `openvault init [--unlock se\|passphrase] [--se-access-control …]` | Create the vault; prints the paper recovery key. Defaults to Secure Enclave when `age-plugin-se` is installed, with `any-biometry` (Touch ID required; use `any-biometry-or-passcode` on Macs without Touch ID). |
| `openvault add NAME [--env VAR] [--desc D] [--tag T] [--scope DIR] [--force\|--meta-only]` | Store a value from stdin or a hidden prompt (never argv). |
| `openvault get NAME [--reveal]` | Show a value to a human at a terminal. |
| `openvault ls [PREFIX] [--json]` | List names. |
| `openvault search QUERY [--json]` | Fuzzy search names, env vars, descriptions, tags. |
| `openvault env [--for DIR] [--json]` | Env vars a project can use. |
| `openvault run [--env VARS] [--only REFS] [--clean-env] -- CMD…` | Run with secrets injected; output redacted. |
| `openvault rm NAME…` | Delete. |
| `openvault import FILE [--dry-run] [--on-conflict skip\|overwrite\|rename] [--prefix P] [--shred]` | Import; `--undo ID\|last` reverts. |
| `openvault audit [verify]` | Show / verify the audit log. |
| `openvault mcp` | MCP stdio server for agents. |

`ov` is a short alias for `openvault`.

## Using it with agents

**Projects** declare what they need in a committed `.openvault.toml` (refs, never values):

```toml
allow = ["github/*", "openai/key"]   # optional; defaults to the [env] refs
confirm_tags = ["prod"]              # these always need a fresh Touch ID

[env]
GITHUB_TOKEN = "secret://github/token"
OPENAI_API_KEY = "secret://openai/key"
```

Then `openvault run -- npm test` just works, `openvault env` shows the agent what
is available, and anything not listed is refused (and the denial is audited).

**Agent instructions:** copy [`skills/openvault/SKILL.md`](skills/openvault/SKILL.md)
into your agent's skills (e.g. `~/.claude/skills/openvault/`). It tells agents to
discover with `search`/`env`, inject with `run`, never ask you to paste a secret,
and never use `--reveal`.

**MCP:** add the server to your agent, e.g. for Claude Code:

```sh
claude mcp add openvault -- openvault mcp
```

Tools: `search`, `list_env`, `run` (argv + env names/refs, cwd, timeout). No tool
returns a value; `run` returns redacted stdout/stderr and the exit code, and its
child gets a minimal environment.

**What an agent sees:**

```console
$ openvault get github/token | cat
openvault: refusing to print a secret to a non-terminal (pipe, file or agent). Secrets are never printed for programs or agents: use `openvault run --only github/token -- <cmd>` to inject it instead
$ openvault run --env GITHUB_TOKEN -- sh -c 'echo $GITHUB_TOKEN; echo -n $GITHUB_TOKEN | base64'
[REDACTED:github/token]
[REDACTED:github/token]
```

## Importing

Every import shows a preview, never prints values, is undoable, and names things
deterministically (`slug(title)/field`, `-2` for duplicates):

```sh
openvault import export.1pux --dry-run          # preview table: ACTION NAME SOURCE
openvault import export.1pux --prefix 1p        # writes; prints a batch id
openvault import --undo last                    # or --undo 20261124-101500-ab12
```

| Source | How to export | Format flag (auto-detected) |
|---|---|---|
| 1Password | File → Export → `.1pux` (or CSV) | `1pux`, `1password-csv` |
| Bitwarden | Tools → Export vault → `.json` (**unencrypted**) | `bitwarden` |
| Apple Passwords | File → Export All Passwords → CSV | `apple-csv` |
| LastPass | Advanced options → Export → CSV | `lastpass-csv` |
| `.env` | — | `--from-env-file .env` (keeps `KEY` as the env var) |

Conflicts with existing names: `--on-conflict skip` (default), `overwrite`
(undo restores the old value), or `rename` (`name-2`). Imported exports are
plaintext — `--shred` overwrites and deletes the file afterwards.

## Threat model (summary)

Full version: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Security checklist and
reporting: [SECURITY.md](SECURITY.md).

* **Malicious/prompt-injected agent:** cannot print values (`get` refuses
  non-terminals; `--reveal` needs a terminal + Touch ID), output of `run` is
  redacted in several encodings, child env is minimal, per-project allowlist and
  scopes are enforced, every use is in a tamper-evident audit log, and in Secure
  Enclave mode every use costs a fingerprint. Redaction is a seatbelt, not a
  sandbox: a command you let run *has* the secret.
* **Other local users:** 0700/0600, and openvault refuses to run on loose permissions.
* **Stolen disk / backup / git remote:** sees ciphertext only — not even names.
  Values need the Secure Enclave (non-exportable) or an scrypt passphrase.
* **Malicious import file:** size and zip-bomb caps, fuzzed panic-free parsers.
* **Supply chain:** cargo-deny + cargo-audit, `unsafe` confined to one module,
  reproducible and static release builds.

## Building

```sh
cargo build --release      # target/release/openvault and target/release/ov
cargo test                 # unit + end-to-end tests
bench/bench.sh             # needs hyperfine
```

License: MIT OR Apache-2.0.
