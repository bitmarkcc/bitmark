// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_SELECTION_H
#define BITCOIN_DYNAMICALGO_SELECTION_H

#include <sync.h>
#include <uint256.h>

#include <array>
#include <cstdint>

// Cost control for solution-candidate selection (doc/dynamic-algo-mining.md sec
// 2.1quater rule 1).
//
// A miner must run verify() on a mempool solution candidate to learn its alpha, and one
// run costs up to ~38 s (doc sec 8.6) -- while the algos this exists for are
// data-oblivious, so garbage costs the same as a real solution and there is no fast
// rejection. Anyone can publish candidates, so the number of runs a node is willing to
// spend has to be bounded, and bounded by something an attacker cannot inflate.
//
// NOT per template: getblocktemplate rebuilds every few seconds and on every change of
// requested algo (rpc/mining.cpp), a rate set by how often pools poll, which has nothing
// to do with what a run costs. A per-template cap would therefore scale the cost with
// polling -- precisely the thing that needed bounding.
//
// So the budget is per SLOT per ANCHOR EPOCH: the ~16 minutes during which one slot's
// seed is fixed (doc sec 2.1bis). Because verify() results are memoized (verifycache.h),
// a candidate already judged in this epoch costs nothing to judge again, so the budget is
// spent only on genuinely new content and the bound holds across every template in the
// epoch.

namespace dynamicalgo {

//! Per-slot count of candidate verifier runs spent in the current anchor epoch. Tiny and
//! self-resetting: one entry per slot, and a new anchor (i.e. the slot produced a block,
//! which also means a new seed and new solutions) starts the count over.
class CandidateBudget
{
public:
    //! Account for one candidate verification on `slot` in the epoch anchored at
    //! `anchor`. Returns false when `budget` runs have already been spent there, in which
    //! case nothing is recorded and the caller must leave the candidate unjudged.
    //! `budget <= 0` disables candidate verification entirely.
    bool TrySpend(int slot, const uint256& anchor, int budget);

    //! Runs spent on `slot` in the epoch anchored at `anchor` (0 for any other epoch).
    int Spent(int slot, const uint256& anchor) const;

private:
    static constexpr size_t MAX_SLOTS{8}; // NUM_ALGOS; asserted against it at the call site

    struct Slot {
        uint256 anchor;    //!< the epoch `spent` belongs to (null == none yet)
        int spent{0};
    };

    mutable Mutex m_mutex;
    std::array<Slot, MAX_SLOTS> m_slots GUARDED_BY(m_mutex);
};

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_SELECTION_H
