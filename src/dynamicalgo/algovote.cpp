// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/algovote.h>

#include <coins.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <undo.h>

namespace dynamicalgo {

int DecodeVoteSlot(const std::vector<unsigned char>& v)
{
    return v.empty() ? 0 : v[0];
}

int64_t DecodeVoteLock(const std::vector<unsigned char>& v)
{
    if (v.empty()) return 0;
    // The lock is a CScriptNum (BIP68 relative timelock), up to 5 bytes. Not required to
    // be minimally encoded (it lives in a spendable script, not a push we authored).
    return CScriptNum(v, /*fRequireMinimal=*/false, /*nMaxNumSize=*/5).GetInt64();
}

CAmount BlockTotalFees(const CBlock& block, const CBlockUndo& undo)
{
    CAmount fees{0};
    for (size_t i = 1; i < block.vtx.size(); ++i) { // skip coinbase
        if (i - 1 >= undo.vtxundo.size()) break;
        CAmount in{0}, out{0};
        for (const Coin& c : undo.vtxundo[i - 1].vprevout) in += c.out.nValue;
        for (const CTxOut& o : block.vtx[i]->vout) out += o.nValue;
        if (in > out) fees += in - out;
    }
    return fees;
}

std::map<uint256, VoteTally> BlockVotesForSlot(const CBlock& block, const CBlockUndo& undo,
                                               int slot, int voting_period)
{
    std::map<uint256, VoteTally> out;
    for (size_t i = 1; i < block.vtx.size(); ++i) { // skip coinbase
        const CTransaction& tx = *block.vtx[i];
        // The FEE_VOTE weight is this tx's fee split evenly across its outputs, so a
        // coinjoin's shared fee is not over-credited. Needs the input values from undo.
        CAmount fee_share{0};
        if (i - 1 < undo.vtxundo.size() && !tx.vout.empty()) {
            CAmount in{0}, o{0};
            for (const Coin& c : undo.vtxundo[i - 1].vprevout) in += c.out.nValue;
            for (const CTxOut& v : tx.vout) o += v.nValue;
            const CAmount fee{in - o};
            if (fee > 0) fee_share = fee / (CAmount)tx.vout.size();
        }
        for (const CTxOut& v : tx.vout) {
            std::vector<std::vector<unsigned char>> sols;
            const TxoutType type{Solver(v.scriptPubKey, sols)};
            if (type == TxoutType::FEE_VOTE && DecodeVoteSlot(sols[1]) == slot) {
                out[uint256(sols[0])].fee_weight += fee_share;
            } else if (type == TxoutType::STAKE_VOTE && DecodeVoteSlot(sols[1]) == slot
                       && DecodeVoteLock(sols[2]) >= voting_period) {
                // For now a STAKE_VOTE contributes ONLY to stake, not to fee_weight -- its
                // tx's fee-share is not also credited to the fee constituency. Possible
                // future amendment: also add fee_share here so a stake-voting tx's fee
                // counts on the fee side too. Keeping the split simple until it works.
                out[uint256(sols[0])].stake += v.nValue;
            }
        }
    }
    return out;
}

CAmount VoteFeeFloor(CAmount year_fees)
{
    return year_fees / 730;
}

std::optional<uint256> VoteWindowWinner(const std::map<uint256, VoteTally>& tallies,
                                        CAmount fee_floor)
{
    CAmount ftot{0}, ktot{0};
    for (const auto& [branch, t] : tallies) { ftot += t.fee_weight; ktot += t.stake; }
    if (ftot <= 0 || ktot <= 0 || ftot < fee_floor) return std::nullopt;
    for (const auto& [branch, t] : tallies) {
        // 75% thresholds as 4*part >= 3*total. All values are <= MAX_MONEY (28e6 * COIN,
        // < 2^52), so 4*part and 3*total stay well within int64 -- no overflow, and no
        // need for __int128 (keeps this portable to a 32-bit node).
        if (int64_t{4} * t.fee_weight >= int64_t{3} * ftot
            && int64_t{4} * t.stake >= int64_t{3} * ktot) {
            return branch; // unique: 2 * 0.75 > 1
        }
    }
    return std::nullopt;
}

} // namespace dynamicalgo
