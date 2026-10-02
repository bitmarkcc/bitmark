# Dynamic-algo reference verifiers and fixtures

Reference implementations of the Bitmark dynamic-algo ("proof of useful work")
`verify()` ABI, plus the fixtures and harnesses used to exercise it. None of this is
built or shipped by `bitmarkd` — it is reference material for anyone writing an algo,
and the means of testing the node's side of the contract.

The ABI itself is specified in [`doc/dynamic-algo-mining.md`](../../doc/dynamic-algo-mining.md)
§3 (the I/O contract), §3.1 (chain access), §8.3 (pinned AOT targets) and §8.7 (the
gas and I/O budgets). This README covers only how to build and run what is here.

## Contents

| File | What it is |
|---|---|
| `keccak_algo.c` | Reference algo: Keccak-256 PoW. Stateless, imports nothing. The simplest complete implementation of the money path. |
| `whirlpool_algo.c` | Reference algo: Whirlpool PoW. Same shape as above. |
| `chain_probe.c` | NOT an algo — a fixture that drives every `chain.*` accessor case (count, fetch, out-of-range, buffer-too-small, bad pointer, and both I/O budgets) and reports what it observed through `out_ab`. |
| `aot_harness.cpp` | Runs a `.aot` through the node's real `RunAlgoVerify`, with a stub slot-block source. Tests the bridge without a running node. |
| `store_harness.cpp` | Runs the full materialization pipeline: on-chain `.wasm` → `ModuleStore` (execs `wamrc`) → `.aot` → `RunAlgoVerify`. |

## Building

```sh
make              # the .wasm modules
make selftest     # each algo's self-test, native and wasm32
make aot          # compile the .wasm to .aot with the in-tree wamrc
make harness      # the two harnesses (needs the main tree built)
```

`make` needs `clang` with a wasm32 target; `make selftest` also needs `wasmtime`;
`make aot` and `make harness` need the main tree built first, since they use
`src/wamr/build-wamrc/wamrc` and `src/wamr/build/libvmlib.a`.

The algos are compiled **freestanding** — `--target=wasm32 -O2 -nostdlib
-Wl,--no-entry` — with no libc and no start function. Exports come from
`__attribute__((export_name(...)))`, so no linker export flags are needed.

## Why there is a wamrc step at all

What lives on the chain is a `.wasm`. What the node can execute is a `.aot`, because
the vendored WAMR runtime is built AOT-only. Feeding a `.wasm` straight to the
runtime fails with *"magic header not detected"*. The node therefore compiles each
activated algo once, with `wamrc`, into its module store — see
`src/dynamicalgo/modulestore.h`.

`make aot` uses the same pinned flags the node uses
(`dynamicalgo::PinnedAotTarget()`): `--target=x86_64 --cpu=x86-64-v2 --opt-level=3
--size-level=3` on x86-64. `-mcpu=native` is **forbidden**: an `+avx2` `.aot`
SIGILLs on a host without AVX2. Those flags are consensus parameters (§8.3), so if
you change them here they must change in `modulestore.cpp` too.

## Running the harnesses

```sh
# bridge only, against a prebuilt .aot
./aot_harness keccak_algo.aot 2100ffff          # easy target  -> valid, alpha=beta=0.5
./aot_harness keccak_algo.aot 03000001          # hard target  -> invalid, alpha=0

# chain accessors: args are <aot> <mode> <slot_block_count> <block_size> [failread]
./aot_harness chain_probe.aot 0 7 200           # mode 0: alpha = slot_block_count()
./aot_harness chain_probe.aot 1 7 200           # mode 1: fetch block 0
./aot_harness chain_probe.aot 2 7 200           # out-of-range index  -> -1
./aot_harness chain_probe.aot 3 7 200           # cap too small       -> -3
./aot_harness chain_probe.aot 5 7 200           # burn the CALLS budget
./aot_harness chain_probe.aot 6 7 1048576       # burn the BYTES budget
./aot_harness chain_probe.aot 1 7 200 failread  # unreadable block -> chain_unavailable

# full pipeline: compile if absent, then run. A second run must hit the cache.
./store_harness keccak_algo.wasm /tmp/store ../../src/wamr/build-wamrc/wamrc
./store_harness keccak_algo.wasm /tmp/store -    # '-' = no compiler, prints the
                                                 # manual wamrc command to run
```

`chain_probe` reuses the ABI's `nbits` argument as a mode selector, which is why a
"target" is passed where a mode is meant. That keeps one small module able to drive
every case.

## Writing an algo

Start from `keccak_algo.c`. The contract in brief:

- Export `verify(anchor_hash, payout, payout_len, nbits, nonce, nonce_len, out_ab)`
  returning 0 when the solution meets the target.
- `anchor_hash` is the previous block of **your own slot**, not the immediate parent,
  so your seed changes about every 16 minutes rather than every 120 seconds (§2.1bis).
  `seed = Hash256(payout || anchor_hash)`.
- Write α then β into `out_ab` as two little-endian `u32` in Q32 fixed point
  (`0.5 == 0x80000000`). The whole `u32` range maps to `[0,1)`, so `0 ≤ α,β < 1` is
  automatic and no float ever crosses the ABI.
- Be integer-only and deterministic. `f32` is permitted inside the module (wasm's
  IEEE-754 is exact) but never at the boundary.
- α and β may be constant or may depend on the solution — that is your choice. The
  only hard rule is that they must be **defined for an empty solution**, since the
  node calls `verify()` with no solution purely to read them for the no-solution
  branch. Note the incentive if you vary α: a pool keeps `r − α·r`, so among valid
  candidates it prefers the lowest α (§3).
- Your payout scriptPubKey is grindable against the seed, and a slot-length anchor
  gives ~8× more grinding time than the old per-block one — so validation-set (or
  equivalent) selection must be grinding-resistant (§8.7).
- If you need earlier blocks of your own slot, use the `chain.*` imports — the
  commented idiom at the end of `keccak_algo.c` is the template. Mind the per-call
  budgets (§8.7): 1024 fetches and 256 MiB, which deliberately do **not** allow
  reading the whole 32850-block window in one call.

## Regenerating after an edit

The `.wasm` and `.aot` outputs are build artifacts and are not checked in (`clang`
output is not reproducible across compiler versions anyway). Run `make` and
`make selftest` after changing a `.c` file; `make selftest` is the fast check that an
algo's hash core and its `verify()` glue still agree.
