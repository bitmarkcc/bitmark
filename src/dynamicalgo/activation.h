// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_ACTIVATION_H
#define BITCOIN_DYNAMICALGO_ACTIVATION_H

#include <consensus/amount.h>
#include <dynamicalgo/activationdb.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <optional>

// Dynamic-algo activation resolution (Bitmark, phase 6.5b step 3).
//
// Computes, incrementally as blocks connect, which OP_PUSHCODE branch is the active algo
// for each mPoW slot (doc/dynamic-algo-voting.md sec "Activation"):
//
//   * An ANCHORED WINDOW for a slot is [f, f+VP-1] whose FIRST block f carries a vote for
//     that slot. A branch b WINS it with >= 75% of the window's fee-weight AND >= 75% of
//     its stake, both totals > 0 and the fee total at or above the participation floor.
//   * The window's ACTIVATION height is (f + VP - 1) + 720 + 1 = f + VP + 720, so the
//     window that activates at height t is the one starting at f = t - VP - 720 (its last
//     block is t-721). It therefore slides by exactly one block per height, which is what
//     makes O(1)-per-block tracking possible.
//   * At the activation height the winner must also ASSEMBLE (getpushcode == complete);
//     a winner that cannot be assembled voids the activation and the slot keeps its
//     previous algo. Assembly is a pure function of the confirmed chain, so this stays
//     deterministic across nodes. Runtime gas/memory limits are NOT part of this: they are
//     per-solution, input-dependent and enforced per block, and never de-activate a branch.
//   * A later winning window supersedes an earlier one; otherwise the slot keeps its
//     current algo (primitive-only if never activated).
//   * The participation floor is 6.25% of an AVERAGE window's fees, normalized by the
//     number of blocks actually recorded (see VoteFeeFloor). Since the store only records
//     fees from fork activation onward, no activation may land until at least one voting
//     period of fee history exists, so the floor is never averaged over a block or two.

namespace dynamicalgo {

//! Consensus parameters the activation rule needs.
struct ActivationParams {
    int voting_period{0};        //!< consensus.nVotingPeriod (VP): the anchored window length
    int activation_delay{720};   //!< blocks between the window's end and activation
    int year_blocks{720 * 365};  //!< fee-floor averaging horizon
    int num_slots{8};            //!< NUM_ALGOS
    //! How far below the oldest height the running sums still need, per-block records are
    //! retained, so a reorg of up to this depth can be undone.
    int reorg_margin{1000};
};

//! Can this branch be assembled to completion right now? (AssemblePushCode == COMPLETE.)
using BranchAssembler = std::function<bool(const uint256& branch)>;

//! Compute the store write for CONNECTING the block at `height`, whose total fees and
//! per-slot votes are supplied (both derived from the block and its undo data). Reads the
//! prior incremental state from `db`, slides the window and the fee sum by one block, and
//! decides any activations landing at `height`.
//!
//! Returns false if the store's state does not correspond to `height - 1` (the caller must
//! reconcile or reindex); the store is not modified either way -- the caller applies `out`.
bool ComputeConnect(const CActivationDB& db, const ActivationParams& params,
                    int32_t height, CAmount block_fees, const CBlockVotes& votes,
                    const uint256& block_hash, const BranchAssembler& assembles,
                    CConnectWrite& out);

//! Compute the store write for DISCONNECTING the block at `height`: reverses the slide and
//! restores the per-slot activations recorded in that block's undo record. Returns false if
//! the store's state does not correspond to `height`.
bool ComputeDisconnect(const CActivationDB& db, const ActivationParams& params,
                       int32_t height, const uint256& parent_hash,
                       CDisconnectWrite& out);

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_ACTIVATION_H
