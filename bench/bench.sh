#!/usr/bin/env bash
# Benchmark openvault with hyperfine.
#
#   cargo build --release && bench/bench.sh            # uses target/release/openvault
#   OV=/path/to/openvault bench/bench.sh --export-markdown bench/results.md
#
# The value key comes from OPENVAULT_IDENTITY (the headless/CI path): Touch ID
# and passphrase prompts are human time, not program time, so they are excluded.
set -euo pipefail

OV="${OV:-$(cd "$(dirname "$0")/.." && pwd)/target/release/openvault}"
command -v hyperfine >/dev/null || { echo "hyperfine not found (brew install hyperfine / cargo install hyperfine)"; exit 1; }
[ -x "$OV" ] || { echo "build first: cargo build --release"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export OPENVAULT_HOME="$TMP/vault" OPENVAULT_META_CACHE=file OPENVAULT_NO_PROMPT=1
export OPENVAULT_PASSPHRASE="bench-only passphrase, not secret" OPENVAULT_TEST_SCRYPT_LOG_N=10
"$OV" init --unlock passphrase --recovery-file "$TMP/recovery" 2>/dev/null
export OPENVAULT_IDENTITY="$(cat "$TMP/recovery")"
unset OPENVAULT_PASSPHRASE

printf 'ghp_benchmark_token_value_0123456789' | "$OV" add github/token --desc "bench token" 2>/dev/null
for i in $(seq 1 99); do
  printf 'value-%04d-xxxxxxxxxxxxxxxx' "$i" | "$OV" add "svc$((i % 10))/key-$i" --desc "service $i" 2>/dev/null
done

# Optional head-to-head with alternatives, only if they are installed/configured:
#   pass + gpg      -> set up automatically in a throwaway GNUPGHOME / store
#   OV_BENCH_OP_REF -> e.g. op://Private/GitHub/token   (1Password CLI, signed in)
#   OV_BENCH_BW_ID  -> a Bitwarden item id                (bw, BW_SESSION exported)
EXTRA=()
if command -v pass >/dev/null && command -v gpg >/dev/null; then
  export GNUPGHOME="$TMP/gnupg" PASSWORD_STORE_DIR="$TMP/pass"
  mkdir -m 700 "$GNUPGHOME"
  gpg --batch --quiet --passphrase '' --quick-gen-key bench@openvault.invalid default default never 2>/dev/null
  pass init bench@openvault.invalid >/dev/null
  printf 'ghp_benchmark_token_value_0123456789\n' | pass insert -m github/token >/dev/null
  EXTRA+=(-n "pass show (gpg-agent warm)" "pass show github/token")
fi
[ -n "${OV_BENCH_OP_REF:-}" ] && EXTRA+=(-n "op read" "op read $OV_BENCH_OP_REF")
[ -n "${OV_BENCH_BW_ID:-}" ] && EXTRA+=(-n "bw get password" "bw get password $OV_BENCH_BW_ID")

hyperfine --warmup 20 --min-runs 200 -N "$@" \
  -n "version (cold start)" "$OV --version" \
  -n "get --reveal (1 of 100)" "$OV get --reveal github/token" \
  -n "run --only -- true" "$OV run --only github/token -- true" \
  -n "ls (100 secrets)" "$OV ls" \
  -n "search (100 secrets)" "$OV search token" \
  "${EXTRA[@]}"
