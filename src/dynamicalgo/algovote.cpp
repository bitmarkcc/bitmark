// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/algovote.h>

#include <arith_uint256.h>
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

std::map<int, std::map<uint256, VoteTally>> BlockVotesAllSlots(const CBlock& block,
                                                               const CBlockUndo& undo,
                                                               int voting_period)
{
    std::map<int, std::map<uint256, VoteTally>> out;
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
            if (type == TxoutType::FEE_VOTE) {
                out[DecodeVoteSlot(sols[1])][uint256(sols[0])].fee_weight += fee_share;
            } else if (type == TxoutType::STAKE_VOTE && DecodeVoteLock(sols[2]) >= voting_period) {
                // For now a STAKE_VOTE contributes ONLY to stake, not to fee_weight -- its
                // tx's fee-share is not also credited to the fee constituency. Possible
                // future amendment: also add fee_share here so a stake-voting tx's fee
                // counts on the fee side too. Keeping the split simple until it works.
                out[DecodeVoteSlot(sols[1])][uint256(sols[0])].stake += v.nValue;
            }
        }
    }
    return out;
}

std::map<uint256, VoteTally> BlockVotesForSlot(const CBlock& block, const CBlockUndo& undo,
                                               int slot, int voting_period)
{
    std::map<int, std::map<uint256, VoteTally>> all{BlockVotesAllSlots(block, undo, voting_period)};
    const auto it = all.find(slot);
    if (it == all.end()) return {};
    return std::move(it->second);
}

CAmount VoteFeeFloor(CAmount fees_sum, int64_t num_blocks, int voting_period)
{
    if (fees_sum <= 0 || num_blocks <= 0 || voting_period <= 0) return 0;
    // floor = (fees_sum / num_blocks) * voting_period / 16, evaluated as
    //     (fees_sum * voting_period) / (num_blocks * 16)
    // so the per-block average is not truncated first. The product needs a wide
    // intermediate: fees_sum can reach MAX_MONEY (~2^51) and voting_period 5760 (~2^13),
    // which overflows int64. arith_uint256 is already used for consensus money math and
    // is portable (no __int128).
    arith_uint256 acc{static_cast<uint64_t>(fees_sum)};
    acc *= arith_uint256{static_cast<uint64_t>(voting_period)};
    acc /= arith_uint256{static_cast<uint64_t>(num_blocks) * 16};
    return static_cast<CAmount>(acc.GetLow64());
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
