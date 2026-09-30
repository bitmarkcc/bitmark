// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_GASCLASSES_H
#define BITCOIN_DYNAMICALGO_GASCLASSES_H

#include <cstdint>

// Canonical opcode-class taxonomy for dynamic-algo gas metering
// (doc/dynamic-algo-mining.md sec 8.6). This is the single source of truth for
// the class IDs, the per-class execution limits, and the bulk byte-factors,
// SHARED by two components that must agree exactly:
//
//   * the offline instrumenter (gasinstrument.cpp), which bakes a class id into
//     the rewritten module as the first argument of every metering.usegas call, and
//   * the runtime enforcement bridge (wasmexec.cpp), which reads that class id back
//     and charges the matching per-class budget.
//
// The header is deliberately dependency-free (only <cstdint>) so the standalone
// offline tool can include it without any other bitcoin headers.
//
// There are 15 "count" classes (charged 1 per execution; members share ~equal
// worst-case per-op time) plus a single combined BULK budget measured in bytes.
// The instrumenter distinguishes three bulk *sub-kinds* only so the runtime can
// convert each op's native size operand N to bytes; all three fold into the one
// BULK budget. All values are CONSENSUS constants, fixed network-wide.

namespace dynamicalgo {

enum GasClass : int32_t {
    // -- 15 count classes (ids 0..14), charged by execution count ------------
    GC_NOP = 0,   //!< structural no-ops (nop, drop, block/loop/end, ref.*): 0 time
    GC_ICONST,    //!< i32/i64.const (~0.25 ns: immediate / reg mov)
    GC_VAR,       //!< local.get/set/tee, f32/f64.const (~1 ns: spill / const-pool)
    GC_BRANCH,    //!< br/br_if/br_table/return/select/if/else
    GC_CALL,      //!< call, call_indirect
    GC_INT,       //!< i32/i64 add/sub/logic/shift/cmp/clz/ctz/popcnt/wrap/extend
    GC_IMUL,      //!< i32/i64 mul
    GC_IDIV,      //!< i32/i64 div/rem
    GC_FADD,      //!< f32/f64 add/sub/mul/neg/abs/min/max/copysign/cmp
    GC_FDIV,      //!< f32/f64 div, sqrt
    GC_FCVT,      //!< ceil/floor/trunc/nearest, convert/promote/demote, trunc_sat
    GC_MEM,       //!< scalar loads/stores, global.get/set, memory.size, table.get/set
    GC_SIMD,      //!< v128 arith/logic/cmp/splat/lane
    GC_SIMD_DIV,  //!< v128 div/sqrt
    GC_SIMD_MEM,  //!< v128 loads/stores/lane
    GC_COUNT_N = 15, //!< number of count classes (ids 0..14)

    // -- bulk sub-kinds (ids 15..17): the instrumenter passes the RAW size
    //    operand N with one of these ids; the runtime multiplies N by the
    //    matching GAS_BULK_FACTOR to get bytes and folds all three into the one
    //    combined BULK budget (GAS_BULK_LIMIT). Never charged per-block.
    GC_BULK_MEM = 15,   //!< memory.fill/copy/init      (N = bytes,        x1)
    GC_BULK_GROW = 16,  //!< memory.grow                (N = 64 KiB pages, x65536)
    GC_BULK_TABLE = 17, //!< table.fill/copy/init/grow  (N = elements,     x8)
    //! One past the last id the instrumenter may emit through usegas. Everything
    //! above is charged by the HOST, never by instrumented guest code.
    GC_USEGAS_MAX = 18,

    // -- host-charged chain-access budgets (ids 18..19): charged by the exec
    //    bridge when the module calls a `chain` import (doc sec 8.7). Never
    //    emitted by usegas, so an instrumented module cannot touch them.
    GC_IO_CALLS = 18,   //!< one charge per chain.slot_block() fetch
    GC_IO_BYTES = 19,   //!< block bytes delivered by chain.slot_block()
    GC_CLASS_MAX = 20,
};

//! Per-class execution limits (max executions), doc sec 8.6. Indexed by the count
//! classes 0..14. Rule: limit = max(2 x trunk-count, count-for-a-0.5 s time slice);
//! NOP is a pure count cap (0 time). Safe because the algo is data-oblivious, so
//! per-input counts are fixed and one measurement bounds every input.
static constexpr uint64_t GAS_LIMIT[GC_COUNT_N] = {
    /* GC_NOP      */ 16000000000ull,
    /* GC_ICONST   */  8000000000ull,
    /* GC_VAR      */ 16000000000ull,
    /* GC_BRANCH   */  1600000000ull,
    /* GC_CALL     */   320000000ull,
    /* GC_INT      */  8000000000ull,
    /* GC_IMUL     */   512000000ull,
    /* GC_IDIV     */    64000000ull,
    /* GC_FADD     */   512000000ull,
    /* GC_FDIV     */   100000000ull,
    /* GC_FCVT     */   320000000ull,
    /* GC_MEM      */   320000000ull,
    /* GC_SIMD     */  5000000000ull,
    /* GC_SIMD_DIV */   128000000ull,
    /* GC_SIMD_MEM */  5000000000ull,
};

//! Combined bulk-bytes budget: 8 GiB across memory/table fill+copy+init+grow.
static constexpr uint64_t GAS_BULK_LIMIT = 8ull * 1024 * 1024 * 1024;

//! Chain-access budgets, per verify() call (doc sec 8.7).
//!
//! Neither GAS_LIMIT[GC_CALL] nor the memory cap bounds disk reads: a chain fetch
//! costs the module ONE `call` instruction but costs the node a block read, so the
//! 320M CALL budget would permit ~320M reads, and a module can fetch every block
//! into the same buffer so its memory footprint stays flat. These two budgets are
//! what bound it, and they bound different things:
//!
//!   CALLS - the fixed per-fetch overhead (block-index walk, file seek,
//!           deserialization) that even a tiny block pays; bounds IOPS.
//!   BYTES - transfer volume; bounds throughput.
//!
//! They cross over usefully: 1024 x MAX_BLOCK_SERIALIZED_SIZE far exceeds the byte
//! cap, so BYTES binds for large blocks and CALLS binds for small ones. Worst case
//! is ~10 s on a spinning disk (1024 seeks at ~150 IOPS + 256 MiB at ~100 MB/s),
//! an order below the ~38 s compute budget, and negligible on an SSD.
//!
//! NOTE: these caps deliberately do NOT permit folding the whole accessible window
//! (MIN_SLOT_BLOCKS_ON_DISK = 32850 blocks) in one call -- that would be minutes of
//! I/O per block on any budget worth having. The window is REACHABLE (any index),
//! not traversable in a single verify(); a stateful algo must receive its history
//! pre-folded (on-chain checkpoint epochs or node-held state), not re-derive it.
//! CONSENSUS constants, fixed network-wide.
static constexpr uint64_t GAS_IO_CALLS_LIMIT = 1024;
static constexpr uint64_t GAS_IO_BYTES_LIMIT = 256ull * 1024 * 1024;

//! Byte-factor for a bulk sub-kind: multiply the raw N size operand to get bytes.
//! memory ops already count bytes; memory.grow counts 64 KiB pages; table ops
//! count pointer-sized (8 B) elements.
constexpr uint64_t GasBulkFactor(int32_t cls)
{
    return cls == GC_BULK_GROW ? 65536ull
         : cls == GC_BULK_TABLE ? 8ull
         : 1ull; // GC_BULK_MEM
}

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_GASCLASSES_H
