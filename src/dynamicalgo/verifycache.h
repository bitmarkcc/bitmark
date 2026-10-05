// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_VERIFYCACHE_H
#define BITCOIN_DYNAMICALGO_VERIFYCACHE_H

#include <span.h>
#include <sync.h>
#include <uint256.h>
#include <util/hasher.h>

#include <cstdint>
#include <deque>
#include <unordered_map>

// Memoization of dynamic-algo verify() results (doc/dynamic-algo-mining.md sec 8.9).
//
// REQUIRED, not an optimization. One verify() costs up to ~38 s of reference-core CPU
// (doc sec 8.6), and getblocktemplate rebuilds a template on every new tip, at most every
// 5 s when the mempool changes, AND on every change of the requested algo -- against a
// one-entry template cache, so a pool rotating 8 algos rebuilds on every single call.
// Each rebuild runs verify() TWICE: once in ResolveAlgoReward to price the coinbase, once
// more inside TestBlockValidity. Without this cache an activated expensive algo cannot be
// mined at all (~3 s per call per algo for the LLM trunk; ~76 s at the gas limits).
//
// verify() is a pure function of a small, fully enumerable input set, so caching it
// cannot change a verdict -- only skip recomputing one. That is why, unlike the
// activation store, a cache that is cold, dropped, or sized differently from node to node
// carries NO divergence risk.

namespace dynamicalgo {

//! The part of an AlgoVerifyResult that is a pure function of the cache key. The gas
//! counters and the error string are diagnostics of a particular run, not results, so
//! they are deliberately not cached -- a hit leaves them at their defaults.
//!
//! `chain_unavailable` is NOT here and must NEVER be cached: it means THIS node could not
//! read a block consensus says it retains, which is a property of local storage, not of
//! the inputs. Caching it would make a transient local fault permanent, and would survive
//! the repair. Callers must therefore only Put() results whose chain_unavailable is false.
struct VerifyVerdict {
    bool ok{false};             //!< the module loaded and verify() ran to completion
    bool solution_valid{false}; //!< verify() returned 0
    bool out_of_gas{false};     //!< !ok because a gas class hit its cap (kept so a cache
                                //!< hit reports the same reject reason as a fresh run)
    uint32_t alpha_q32{0};
    uint32_t beta_q32{0};
};

//! Bounded, content-addressed cache of verify() verdicts. Thread-safe on its own; callers
//! need not hold cs_main for it (they generally do, for other reasons).
class VerifyCache
{
public:
    //! Entries are ~70 bytes, and the live working set is tiny -- one entry per slot per
    //! tip for the no-solution alpha/beta, plus one per solution candidate considered --
    //! so this is a generous bound at well under a megabyte. A hard cap rather than a
    //! memory target: Put() evicts before it grows.
    static constexpr size_t DEFAULT_MAX_ENTRIES{4096};

    explicit VerifyCache(size_t max_entries = DEFAULT_MAX_ENTRIES);

    //! The content key. Must cover EVERY input verify() can see, or a hit could return a
    //! verdict for a different computation:
    //!   * `branch` fixes the module (an OP_PUSHCODE branch tip is a content hash);
    //!   * `anchor`, `nbits`, `payout` and `solution` are verify()'s literal arguments
    //!     (doc sec 3);
    //!   * `algo` names the slot, and with `anchor` fixes the slot-block window reached
    //!     through the chain.* imports (doc sec 3.1). The window is NOT a further input:
    //!     for any parent between two blocks of the slot, the newest same-algo block at or
    //!     below it IS the anchor, so (branch, algo, anchor) determines both the window and
    //!     slot_block_count(). A reorg below the anchor changes the anchor hash, since a
    //!     block hash commits to its ancestors.
    //! `payout` and `solution` are length-framed, so no two distinct pairs can hash alike
    //! by running into each other.
    //!
    //! Keyed on a txid would be WRONG: txids are malleable, so the same solution rewrapped
    //! under a new txid (different funding input, a 1-satoshi output change, reordered
    //! outputs) would be handed a fresh ~38 s run each time (doc sec 2.1quater).
    static uint256 Key(const uint256& branch, uint8_t algo, const uint256& anchor,
                       uint32_t nbits, Span<const unsigned char> payout,
                       Span<const unsigned char> solution);

    //! Fills `out` and returns true on a hit.
    bool Get(const uint256& key, VerifyVerdict& out) const;

    //! Record a verdict, evicting the oldest entry when full. Insertion order eviction
    //! (not LRU): O(1), and the access pattern here is "recent keys are the live ones",
    //! which insertion order already tracks.
    void Put(const uint256& key, const VerifyVerdict& verdict);

    size_t Size() const;

private:
    mutable Mutex m_mutex;
    const size_t m_max_entries;
    //! The full 256-bit key decides equality; SaltedTxidHasher only buckets, salted so
    //! key material an attacker influences cannot be ground into a single bucket.
    std::unordered_map<uint256, VerifyVerdict, SaltedTxidHasher> m_map GUARDED_BY(m_mutex);
    std::deque<uint256> m_order GUARDED_BY(m_mutex); //!< insertion order, for eviction
};

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_VERIFYCACHE_H
