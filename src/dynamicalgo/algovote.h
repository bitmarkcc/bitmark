// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_ALGOVOTE_H
#define BITCOIN_DYNAMICALGO_ALGOVOTE_H

#include <consensus/amount.h>
#include <serialize.h>
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
//! Serializable so the activation store can persist per-block and running tallies.
struct VoteTally {
    CAmount fee_weight{0}; //!< sum of floor(fee/num_outputs) over this branch's FEE_VOTE outputs
    CAmount stake{0};      //!< sum of qualifying STAKE_VOTE output values for this branch

    SERIALIZE_METHODS(VoteTally, obj) { READWRITE(obj.fee_weight, obj.stake); }

    bool IsEmpty() const { return fee_weight == 0 && stake == 0; }
    VoteTally& operator+=(const VoteTally& o) { fee_weight += o.fee_weight; stake += o.stake; return *this; }
    VoteTally& operator-=(const VoteTally& o) { fee_weight -= o.fee_weight; stake -= o.stake; return *this; }
};

//! Slot index from a vote's Solver `slot` push (1 byte; empty push == slot 0).
int DecodeVoteSlot(const std::vector<unsigned char>& v);

//! Relative timelock from a STAKE_VOTE's Solver `lock` push (CScriptNum, up to 5 bytes).
int64_t DecodeVoteLock(const std::vector<unsigned char>& v);

//! Total transaction fees in a block: sum of (inputs - outputs) over non-coinbase txs,
//! using the block's undo data for the spent-input values. For the year-fees running sum
//! that the fee floor is measured against.
CAmount BlockTotalFees(const CBlock& block, const CBlockUndo& undo);

//! Every slot's per-branch vote tallies from one block, keyed slot -> branch -> tally, in
//! a single pass over the block. `voting_period` is the minimum relative lock a STAKE_VOTE
//! must carry to count (consensus.nVotingPeriod). `undo` supplies the input values the
//! FEE_VOTE fee-shares need; it must be the undo for `block`. Empty when the block carries
//! no votes. This is the single parse implementation; the per-slot form below filters it.
std::map<int, std::map<uint256, VoteTally>> BlockVotesAllSlots(const CBlock& block,
                                                               const CBlockUndo& undo,
                                                               int voting_period);

//! This block's per-branch vote tallies for one `slot`. Empty when the block carries no
//! votes for it.
std::map<uint256, VoteTally> BlockVotesForSlot(const CBlock& block, const CBlockUndo& undo,
                                               int slot, int voting_period);

//! The fee participation floor: 6.25% of an AVERAGE voting window's fees, measured over
//! the recorded fee history (doc sec "Fee participation floor"):
//!
//!     floor = 0.0625 * (fees_sum / num_blocks) * voting_period
//!
//! `fees_sum` is the total block fees over `num_blocks` consecutive blocks. With a full
//! year recorded (num_blocks == 720*365 and voting_period == 5760) this is exactly
//! year_fees / 730, the doc's formula. Normalizing by num_blocks keeps the floor's
//! meaning when less than a year of history exists -- consensus can only record fees
//! from the fork-activation height onward (pre-fork fees would need a full year of undo
//! data, unavailable on a pruned node), so a raw truncated sum would leave the floor
//! near zero for the first year. Returns 0 when there is no history.
CAmount VoteFeeFloor(CAmount fees_sum, int64_t num_blocks, int voting_period);

//! The unique winning branch of a window from its accumulated per-branch tallies and the
//! window's fee floor: the branch with >= 75% of total fee-weight AND >= 75% of total
//! stake, with both totals > 0 and total fee-weight >= fee_floor. nullopt if none.
//! Uniqueness holds because 2 * 0.75 > 1 (at most one branch can hold >= 75% of a total).
std::optional<uint256> VoteWindowWinner(const std::map<uint256, VoteTally>& tallies,
                                        CAmount fee_floor);

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_ALGOVOTE_H
