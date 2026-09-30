// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_WASMEXEC_H
#define BITCOIN_DYNAMICALGO_WASMEXEC_H

#include <dynamicalgo/gasclasses.h>
#include <span.h>

#include <cstdint>
#include <string>
#include <vector>

// Execution bridge for dynamic-algo "proof of useful work" verifier modules,
// backed by WAMR's AOT runtime (src/wamr). See doc/dynamic-algo-mining.md sec 8.
//
// A dynamic algo is a freestanding WebAssembly module that exports:
//
//   int verify(const u8 *prev_hash,                 // 32 bytes
//              const u8 *payout,  u32 payout_len,
//              u32 nbits,
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
// CHAIN ACCESS (doc sec 2.5, 3). An algo may also read the FULL BLOCK DATA of its
// own mPoW slot's previous blocks -- that is how a multi-block algo reads earlier
// OP_SOLUTION chunks (e.g. an accumulating LLM LoRA stream). Those are NOT passed
// as a buffer: the window is up to MIN_SLOT_BLOCKS_ON_DISK (32850, ~1 year of one
// slot) blocks, far too much to marshal per call. Instead the module imports two
// accessors and pulls only what it needs:
//
//   chain.slot_block_count() -> i32
//       How many of the slot's blocks are addressable: min(the slot's blocks back
//       to the Multi-PoW fork, MIN_SLOT_BLOCKS_ON_DISK). A deterministic function
//       of the chain, NOT of what this node has on disk -- the per-slot prune-lock
//       floor (pushcodedb.h) guarantees the whole window is retained, so a pruned
//       and an archival node return the same number. It reaches 32850 about a year
//       after the fork; before that it is the smaller true count.
//
//   chain.slot_block(i32 index, i32 ptr, i32 cap) -> i32
//       Writes the serialized block at `index` (0 == newest, i.e. this block's
//       parent-most recent slot block) to `ptr`, returning its size; or one of the
//       SLOT_BLOCK_* codes below, in which case nothing is written.
//
// Reads are metered by their own budgets (GAS_IO_CALLS_LIMIT / GAS_IO_BYTES_LIMIT),
// because a fetch is one guest instruction but a real disk read -- see gasclasses.h.
// Exceeding either traps, exactly like a count-class overrun. A block inside the
// window that this node CANNOT read is a local fault (corruption, a violated prune
// lock), never block invalidity: the result reports chain_unavailable and the
// consensus caller must raise a fatal error rather than reject the block.
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
//! `chain.slot_block` failure codes. Negative == nothing was written. These are
//! part of the consensus ABI (doc sec 3): a module compiled against them must see
//! the same values on every node.
static constexpr int32_t SLOT_BLOCK_NO_BLOCK = -1;  //!< index >= slot_block_count()
static constexpr int32_t SLOT_BLOCK_BAD_ADDR = -2;  //!< [ptr, ptr+size) outside module memory
static constexpr int32_t SLOT_BLOCK_TOO_SMALL = -3; //!< cap < the block's serialized size

//! The slot's own previous blocks, as seen by a verifier module. Supplied by the
//! consensus caller; kept abstract so this bridge (which lives in libbitcoinkernel)
//! does not depend on the block index or block storage.
class SlotBlockSource
{
public:
    virtual ~SlotBlockSource() = default;

    //! Addressable window size: min(the slot's blocks back to the Multi-PoW fork,
    //! MIN_SLOT_BLOCKS_ON_DISK). Must be a function of the chain alone, never of
    //! local disk state, or nodes will disagree.
    virtual uint32_t Count() const = 0;

    //! Serialize the slot's block at `index` (0 == newest) into `out`. Returning
    //! false means a block consensus says is in the window could not be read here:
    //! a LOCAL fault, which the caller must escalate (never treat as invalidity).
    //! `index < Count()` is guaranteed by the bridge.
    virtual bool Read(uint32_t index, std::vector<unsigned char>& out) const = 0;
};

struct AlgoVerifyResult {
    bool ok{false};             //!< engine loaded the module and ran verify() cleanly
    bool solution_valid{false}; //!< verify() returned 0 (solution meets target)
    uint32_t alpha_q32{0};      //!< dynamic-miner fraction of the reward, Q32
    uint32_t beta_q32{0};       //!< primitive-miner fraction of (1-alpha), Q32
    uint64_t gas_used{0};       //!< total count-class executions charged (0 if uninstrumented)
    uint64_t class_used[dynamicalgo::GC_COUNT_N]{}; //!< per-count-class executions (index by GasClass 0..14)
    uint64_t bulk_bytes{0};     //!< combined BULK bytes charged (memory+table fill/copy/init/grow)
    uint64_t io_calls{0};       //!< chain.slot_block() fetches charged
    uint64_t io_bytes{0};       //!< block bytes delivered by chain.slot_block()
    int32_t gas_class{-1};      //!< class id that hit its cap (a GasClass), or -1 if none
    bool out_of_gas{false};     //!< execution was aborted by a gas cap
    //! A block inside the consensus window could not be read on THIS node. A local
    //! fault (corruption / violated prune lock), not a property of the block being
    //! validated: the caller must raise a fatal error, never reject the block.
    bool chain_unavailable{false};
    std::string error;          //!< human-readable reason when !ok
};

//! Run a dynamic-algo verifier module under the per-class gas caps. On any
//! engine-level failure (bad module, missing export, marshaling failure,
//! out-of-gas, other trap) the result has ok=false and a populated error; callers
//! must treat that as "no valid dynamic solution", never as a valid one. The gas
//! limits are consensus constants (dynamicalgo::GAS_LIMIT / GAS_BULK_LIMIT, doc sec
//! 8.6), not a parameter. meter_uncapped disables the caps for offline measurement
//! only and MUST be false on the consensus path.
//! `chain` supplies the slot's previous blocks for the chain-access imports; a null
//! source makes slot_block_count() read 0 and every fetch return SLOT_BLOCK_NO_BLOCK
//! (used by tests and by offline measurement of algos that ignore the chain).
AlgoVerifyResult RunAlgoVerify(Span<const unsigned char> module_bytes,
                               Span<const unsigned char> prev_hash,
                               Span<const unsigned char> payout,
                               uint32_t nbits,
                               Span<const unsigned char> solution,
                               const SlotBlockSource* chain = nullptr,
                               bool meter_uncapped = false);

#endif // BITCOIN_DYNAMICALGO_WASMEXEC_H
