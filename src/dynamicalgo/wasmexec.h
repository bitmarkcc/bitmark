// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_WASMEXEC_H
#define BITCOIN_DYNAMICALGO_WASMEXEC_H

#include <dynamicalgo/gasclasses.h>
#include <span.h>

#include <cstdint>
#include <string>

// Execution bridge for dynamic-algo "proof of useful work" verifier modules,
// backed by WAMR's AOT runtime (src/wamr). See doc/dynamic-algo-mining.md sec 8.
//
// A dynamic algo is a freestanding, import-free WebAssembly module that exports:
//
//   int verify(const u8 *prev_hash,                 // 32 bytes
//              const u8 *payout,  u32 payout_len,
//              u32 nbits,
//              const u8 *txs,     u32 txs_len,
//              const u8 *last_n,  u32 last_n_len,
//              const u8 *nonce,   u32 nonce_len,
//              u8 *out_ab)                           // 8 bytes written back
//
// returning 0 when the supplied solution meets the nBits target (else non-zero),
// and writing the reward fractions alpha then beta into out_ab as two
// little-endian u32 in Q32 fixed point (value = u32 / 2^32; the whole u32 range
// maps to [0,1), so 0 <= alpha,beta < 1 is automatic). Modules are integer-only
// and freestanding, so execution is deterministic across nodes (verified
// bit-identical across engines; see doc sec 8.2). The pointer arguments are byte
// offsets into the module's own linear memory; this bridge marshals each input in
// via wasm_runtime_module_malloc, calls verify(), then reads back the i32 result
// and out_ab.
//
// In production the module is a WAMR .aot precompiled offline by wamrc with the
// pinned per-arch target flags (doc sec 8.3); wasm_runtime_load also accepts a
// plain .wasm (JIT/interp builds), which is useful for tests.
//
// CPU is bounded by PER-CLASS gas (doc sec 8.6): the module is instrumented before
// AOT compilation to call an imported host function `metering.usegas(i32 class,
// i32 n)` at each basic block, once per opcode class present, charging that block's
// per-class execution count (and, for the combined BULK budget, the runtime size N
// of each bulk op). This bridge supplies `usegas`, accumulates each class's usage,
// and traps the moment ANY class exceeds its consensus limit (dynamicalgo::GAS_LIMIT
// / GAS_BULK_LIMIT) -- so execution can never exceed the caps, deterministically on
// every node. A module that is not instrumented never calls usegas (usage stays 0).
// Set meter_uncapped to *measure* an algo's per-class cost without capping it (used
// offline at algo approval, never on the consensus path).
struct AlgoVerifyResult {
    bool ok{false};             //!< engine loaded the module and ran verify() cleanly
    bool solution_valid{false}; //!< verify() returned 0 (solution meets target)
    uint32_t alpha_q32{0};      //!< dynamic-miner fraction of the reward, Q32
    uint32_t beta_q32{0};       //!< primitive-miner fraction of (1-alpha), Q32
    uint64_t gas_used{0};       //!< total count-class executions charged (0 if uninstrumented)
    uint64_t class_used[dynamicalgo::GC_COUNT_N]{}; //!< per-count-class executions (index by GasClass 0..14)
    uint64_t bulk_bytes{0};     //!< combined BULK bytes charged (memory+table fill/copy/init/grow)
    int32_t gas_class{-1};      //!< class id that hit its cap (a GasClass), or -1 if none
    bool out_of_gas{false};     //!< execution was aborted by a gas cap
    std::string error;          //!< human-readable reason when !ok
};

//! Run a dynamic-algo verifier module under the per-class gas caps. On any
//! engine-level failure (bad module, missing export, marshaling failure,
//! out-of-gas, other trap) the result has ok=false and a populated error; callers
//! must treat that as "no valid dynamic solution", never as a valid one. The gas
//! limits are consensus constants (dynamicalgo::GAS_LIMIT / GAS_BULK_LIMIT, doc sec
//! 8.6), not a parameter. meter_uncapped disables the caps for offline measurement
//! only and MUST be false on the consensus path.
AlgoVerifyResult RunAlgoVerify(Span<const unsigned char> module_bytes,
                               Span<const unsigned char> prev_hash,
                               Span<const unsigned char> payout,
                               uint32_t nbits,
                               Span<const unsigned char> txs,
                               Span<const unsigned char> last_n_blocks,
                               Span<const unsigned char> solution,
                               bool meter_uncapped = false);

#endif // BITCOIN_DYNAMICALGO_WASMEXEC_H
