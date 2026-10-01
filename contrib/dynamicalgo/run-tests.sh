#!/usr/bin/env bash
# Assert the dynamic-algo ABI behaviours end to end. Invoked by `make check`.
#
# This exercises the NODE's own code paths -- dynamicalgo::RunAlgoVerify and
# dynamicalgo::ModuleStore, linked into the harnesses -- not a reimplementation, so a
# pass here means the consensus bridge and the materialization pipeline agree with
# the documented ABI (doc/dynamic-algo-mining.md sec 3, 3.1, 8.7).
#
# Needs: the .wasm and .aot built (make, make aot) and the harnesses (make harness).

set -u
cd "$(dirname "$0")"

WAMRC=${WAMRC:-../../src/wamr/build-wamrc/wamrc}
pass=0 fail=0

# expect <label> <actual> <expected>
expect() {
    if [ "$2" = "$3" ]; then
        printf '  ok    %s\n' "$1"
        pass=$((pass + 1))
    else
        printf '  FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$3" "$2"
        fail=$((fail + 1))
    fi
}

# field <output> <name>  ->  the value of name=... in the harness output
field() { printf '%s\n' "$1" | grep -oE "$2=[^ ]+" | head -1 | cut -d= -f2; }

need() {
    for f in "$@"; do
        [ -e "$f" ] || { echo "missing $f -- run: make && make aot && make harness"; exit 2; }
    done
}
need keccak_algo.aot whirlpool_algo.aot chain_probe.aot aot_harness store_harness

echo "== algo self-tests (hash core + verify glue) =="
for a in keccak_algo whirlpool_algo; do
    clang -O2 -DTEST -o "/tmp/$a.native" "$a.c" 2>/dev/null \
        && "/tmp/$a.native" >/dev/null 2>&1
    expect "$a native vectors" "$?" "0"
    clang --target=wasm32 -O2 -nostdlib -DWASM_SELFTEST -Wl,--no-entry \
        -o "/tmp/$a.st.wasm" "$a.c" 2>/dev/null
    expect "$a wasm32 selftest" \
        "$(wasmtime run --invoke selftest "/tmp/$a.st.wasm" 2>/dev/null | tail -1)" "0"
done

echo "== reward path through the node bridge =="
# A valid solution pays the dynamic miner alpha=0.5 and the primitive miner beta=0.5;
# with no valid solution alpha drops to 0 while beta is unchanged (doc sec 3-4).
for a in keccak_algo whirlpool_algo; do
    o=$(./aot_harness "$a.aot" 2100ffff 2>/dev/null)
    expect "$a easy target: ok"       "$(field "$o" ok)" "1"
    expect "$a easy target: valid"    "$(field "$o" solution_valid)" "1"
    expect "$a easy target: alpha"    "$(field "$o" alpha)" "0x80000000"
    expect "$a easy target: beta"     "$(field "$o" beta)" "0x80000000"
    o=$(./aot_harness "$a.aot" 03000001 2>/dev/null)
    expect "$a hard target: ok"       "$(field "$o" ok)" "1"
    expect "$a hard target: invalid"  "$(field "$o" solution_valid)" "0"
    expect "$a hard target: alpha=0"  "$(field "$o" alpha)" "0x00000000"
    expect "$a hard target: beta"     "$(field "$o" beta)" "0x80000000"
done

echo "== chain accessors (chain.slot_block_count / chain.slot_block) =="
o=$(./aot_harness chain_probe.aot 0 7 200 2>/dev/null)
expect "slot_block_count == 7"        "$(field "$o" alpha)" "0x00000007"
expect "count costs no I/O"           "$(field "$o" io_calls)" "0"

o=$(./aot_harness chain_probe.aot 1 7 200 2>/dev/null)
expect "fetch returns size 200"       "$(field "$o" alpha)" "0x000000c8"
expect "fetch wrote the bytes"        "$(field "$o" beta)" "0x000000a0"
expect "fetch charged 1 call"         "$(field "$o" io_calls)" "1"
expect "fetch charged 200 bytes"      "$(field "$o" io_bytes)" "200"

o=$(./aot_harness chain_probe.aot 2 7 200 2>/dev/null)
expect "out-of-range index -> -1"     "$(field "$o" alpha)" "0xffffffff"
expect "out-of-range reads no block"  "$(field "$o" host_reads)" "0"

o=$(./aot_harness chain_probe.aot 3 7 200 2>/dev/null)
expect "cap too small -> -3"          "$(field "$o" alpha)" "0xfffffffd"
expect "cap too small still charged"  "$(field "$o" host_reads)" "1"

# An out-of-bounds destination traps rather than returning a code: the engine's
# bounds check raises the exception itself (doc sec 3.1).
o=$(./aot_harness chain_probe.aot 4 7 200 2>/dev/null)
expect "bad pointer traps"            "$(field "$o" ok)" "0"

echo "== I/O budgets (GAS_IO_CALLS=1024, GAS_IO_BYTES=256MiB) =="
# Small blocks: the call cap binds first. Charged before the lookup, so the budget is
# exceeded at limit+1 while only `limit` blocks were actually read from disk.
o=$(./aot_harness chain_probe.aot 5 7 200 2>/dev/null)
expect "calls budget trips"           "$(field "$o" out_of_gas)" "1"
expect "calls budget class id"        "$(field "$o" gas_class)" "18"
expect "calls charged limit+1"        "$(field "$o" io_calls)" "1025"
expect "only limit reads happened"    "$(field "$o" host_reads)" "1024"

# 1 MiB blocks: the byte cap binds first, well before 1024 calls.
o=$(./aot_harness chain_probe.aot 6 7 1048576 2>/dev/null)
expect "bytes budget trips"           "$(field "$o" out_of_gas)" "1"
expect "bytes budget class id"        "$(field "$o" gas_class)" "19"
expect "bytes exceeded the cap"       "$([ "$(field "$o" io_bytes)" -gt 268435456 ] && echo yes)" "yes"
expect "calls stayed under its cap"   "$([ "$(field "$o" io_calls)" -lt 1024 ] && echo yes)" "yes"

echo "== unreadable slot block is a LOCAL fault, not invalidity =="
# It must be distinguishable from out-of-gas so the node escalates (fatal error)
# instead of rejecting a block the rest of the network accepts.
o=$(./aot_harness chain_probe.aot 1 7 200 failread 2>/dev/null)
expect "reports chain_unavailable"    "$(field "$o" chain_unavailable)" "1"
expect "not reported as out-of-gas"   "$(field "$o" out_of_gas)" "0"

echo "== materialization pipeline (ModuleStore + wamrc) =="
store=$(mktemp -d)
trap 'rm -rf "$store"' EXIT
if [ -x "$WAMRC" ]; then
    o=$(./store_harness keccak_algo.wasm "$store" "$WAMRC" 2>/dev/null)
    expect "first use: not cached"     "$(field "$o" "cached before")" "0"
    expect "first use: runs"           "$(printf '%s\n' "$o" | grep -oE 'ok=[01]' | head -1 | cut -d= -f2)" "1"
    o=$(./store_harness keccak_algo.wasm "$store" "$WAMRC" 2>/dev/null)
    expect "second use: cache hit"     "$(field "$o" "cached before")" "1"
else
    echo "  skip  wamrc not built at $WAMRC"
fi
# Without a compiler the store must fail loudly and print a usable wamrc command,
# never silently serve nothing.
o=$(./store_harness keccak_algo.wasm "$(mktemp -d)" - 2>/dev/null)
expect "no compiler: fails"           "$(printf '%s\n' "$o" | grep -c 'GetOrCompile FAILED')" "1"
expect "no compiler: names command"   "$(printf '%s\n' "$o" | grep -c 'wamrc --target=')" "1"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
