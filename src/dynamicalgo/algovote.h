// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_ALGOVOTE_H
#define BITCOIN_DYNAMICALGO_ALGOVOTE_H

#include <consensus/amount.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

class CBlock;
class CBlockUndo;

// Dynamic-algo vote tally primitives (doc/dynamic-algo-voting.md). Pure, deterministic
// helpers shared by the informational `getalgovote` RPC and the consensus activation
// resolver (Phase 6.5b), so both read votes and pick window winners the same way.
//
// Two vote-output constituencies for a slot (both recognized by Solver):
//   FEE_VOTE   (OP_RETURN OP_VOTE <branch:32> <slot>): weight = floor(tx_fee/num_outputs)
//              per output, so a coinjoin's shared fee is not over-credited. Needs the
//              spent-input values (block undo data).
//   STAKE_VOTE (<lock> OP_CSV OP_DROP OP_VOTE <branch:32> OP_DROP <slot> OP_DROP <payout>):
//              weight = the output value, counted only when the relative lock is at least
//              one voting period (real BIP68-locked coins -- the Sybil-resistant side).

namespace dynamicalgo {

//! Accumulated vote weight for one branch (content hash) within a slot's window.
struct VoteTally {
    CAmount fee_weight{0}; //!< sum of floor(fee/num_outputs) over this branch's FEE_VOTE outputs
    CAmount stake{0};      //!< sum of qualifying STAKE_VOTE output values for this branch
};

//! Slot index from a vote's Solver `slot` push (1 byte; empty push == slot 0).
int DecodeVoteSlot(const std::vector<unsigned char>& v);

//! Relative timelock from a STAKE_VOTE's Solver `lock` push (CScriptNum, up to 5 bytes).
int64_t DecodeVoteLock(const std::vector<unsigned char>& v);

//! Total transaction fees in a block: sum of (inputs - outputs) over non-coinbase txs,
//! using the block's undo data for the spent-input values. For the year-fees running sum
//! that the fee floor is measured against.
CAmount BlockTotalFees(const CBlock& block, const CBlockUndo& undo);

//! This block's per-branch vote tallies for `slot`. `voting_period` is the minimum
//! relative lock a STAKE_VOTE must carry to count (consensus.nVotingPeriod). Empty when
//! the block carries no votes for the slot. `undo` supplies the input values FEE_VOTE
//! fee-shares need; it must be the undo for `block`.
std::map<uint256, VoteTally> BlockVotesForSlot(const CBlock& block, const CBlockUndo& undo,
                                               int slot, int voting_period);

//! The fee participation floor: 6.25% of an average voting window's fees over the trailing
//! year == year_fees / 730 (doc sec "Fee participation floor").
CAmount VoteFeeFloor(CAmount year_fees);

//! The unique winning branch of a window from its accumulated per-branch tallies and the
//! window's fee floor: the branch with >= 75% of total fee-weight AND >= 75% of total
//! stake, with both totals > 0 and total fee-weight >= fee_floor. nullopt if none.
//! Uniqueness holds because 2 * 0.75 > 1 (at most one branch can hold >= 75% of a total).
std::optional<uint256> VoteWindowWinner(const std::map<uint256, VoteTally>& tallies,
                                        CAmount fee_floor);

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_ALGOVOTE_H
