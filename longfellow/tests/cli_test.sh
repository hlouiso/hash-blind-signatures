#!/bin/sh
# The blindsig binary across process boundaries, in both schemes:
#   sh tests/cli_test.sh build/blindsig
# The stateless half proves with the cached SLH-DSA circuit, which the first
# run compiles (about a minute and 16 GB of memory). The stateful key has the
# fixed XMSS height 24: keygen, and sign without a valid cache, sweep its 2^24
# leaves, about a minute each, so the stateful half does that twice.
set -u
bin=$1
dir=$(mktemp -d "${TMPDIR:-/tmp}/longfellow-cli.XXXXXX")
trap 'rm -rf "$dir"' EXIT
printf 'blind signature CLI integration test' > "$dir/msg"
printf 'different' > "$dir/other"
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { "$bin" "$@" > "$dir/out" 2>&1 || { cat "$dir/out" >&2; fail "$*"; }; }
bad() { "$bin" "$@" > "$dir/out" 2>&1 && fail "$* should fail"; grep -q "$expect" "$dir/out" || { cat "$dir/out" >&2; fail "$*: no '$expect'"; }; }

session() {  # <subdir> <keygen flags...>
  d=$dir/$1; shift
  mkdir -p "$d"
  ok keygen "$@" -d "$d"
  [ -e "$d/signer_cache.bin" ] || fail "keygen wrote no signer_cache.bin"
  ok commit "$dir/msg" -d "$d"
  ok sign -d "$d"
  grep -q "from signer_cache.bin" "$dir/out" || fail "sign did not use the cache"
  ok prove -d "$d"
  ok verify "$dir/msg" -d "$d"
  grep -q PASS "$dir/out" || fail "verify did not print PASS"
  expect=FAIL bad verify "$dir/other" -d "$d"
}

# A corrupted cache, and with "missing" a missing one, only costs time: sign
# rebuilds and rewrites it.
cache_is_rebuilt() {  # <dir> [missing]
  d=$1
  cp "$d/signer_cache.bin" "$dir/cache"
  printf '\001' | dd of="$d/signer_cache.bin" bs=1 seek=40 conv=notrunc 2>/dev/null
  ok sign -d "$d"
  grep -q rebuilt "$dir/out" || fail "a corrupted cache was used"
  cmp -s "$dir/cache" "$d/signer_cache.bin" || fail "the rebuilt cache differs"
  ok prove -d "$d"
  [ "${2:-}" = missing ] || return 0
  rm "$d/signer_cache.bin"
  ok sign -d "$d"
  grep -q rebuilt "$dir/out" || fail "sign without a cache did not rebuild"
  cmp -s "$dir/cache" "$d/signer_cache.bin" || fail "the rewritten cache differs"
  ok prove -d "$d"
}

session stateful
[ -e "$dir/stateful/slh_sig.bin" ] && fail "stateful sign wrote slh_sig.bin"
cache_is_rebuilt "$dir/stateful"
# A state committed under the stateful key does not mix with a stateless key.
d=$dir/stateful
ok commit "$dir/msg" -d "$d"
ok keygen --stateless -d "$d"
expect="run commit again" bad prove -d "$d"

session stateless --stateless
d=$dir/stateless
key=$(cksum < "$d/signer_key.bin")
cp "$d/slh_sig.bin" "$dir/first"
ok sign -d "$d"
[ "$(cksum < "$d/signer_key.bin")" = "$key" ] || fail "stateless sign rewrote the key"
cmp -s "$dir/first" "$d/slh_sig.bin" && fail "a second signature should be fresh"
ok prove -d "$d"
cache_is_rebuilt "$d" missing

mkdir -p "$dir/flags"
expect="mutually exclusive" bad keygen --stateful --stateless -d "$dir/flags"
expect="unknown option" bad keygen --height 10 -d "$dir/flags"
expect="keygen options" bad sign --stateless -d "$dir/flags"
expect="run keygen first" bad commit "$dir/msg" -d "$dir/flags"
echo "CLI round trips in both schemes, tree caches, scheme checks and flag validation passed"
