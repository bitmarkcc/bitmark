// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <node/blockstorage.h>
#include <primitives/algo.h>
#include <primitives/block.h>
#include <pushcodedb.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <undo.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

// Informational tally of OP_VOTE dynamic-algo votes (Bitmark). NON-CONSENSUS: this
// RPC reads the chain and reports the fee-weighted and stake-weighted tally for a
// slot's voting window so votes can be watched on testnet before the tally becomes
// consensus. See doc/dynamic-algo-voting.md for the rules.

namespace {

constexpr int VOTING_PERIOD = 720 * 8;   // 5760 blocks (~8 days), the sliding window
constexpr int ACTIVATION_DELAY = 720;    // blocks between a supermajority and activation

// Decode a stack number pushed either as a small-int opcode (OP_0/OP_1..OP_16) or a
// data push (<=len bytes). Returns false on anything else.
bool DecodeNum(opcodetype op, const std::vector<unsigned char>& data, int max_bytes, int64_t& out)
{
    if (!data.empty()) {
        if ((int)data.size() > max_bytes) return false;
        out = CScriptNum(data, /*fRequireMinimal=*/false, max_bytes).getint();
        return true;
    }
    if (op == OP_0) { out = 0; return true; }
    if (op >= OP_1 && op <= OP_16) { out = op - (OP_1 - 1); return true; }
    return false;
}

// Match a vote output: OP_RETURN OP_VOTE <branch_hash:32> <slot> and nothing else.
bool ParseVoteOutput(const CScript& spk, uint256& branch, int64_t& slot)
{
    CScript::const_iterator it = spk.begin();
    opcodetype op;
    std::vector<unsigned char> data;
    if (!spk.GetOp(it, op, data) || op != OP_RETURN) return false;
    if (!spk.GetOp(it, op, data) || op != OP_VOTE) return false;
    if (!spk.GetOp(it, op, data) || data.size() != 32) return false;
    branch = uint256(data);
    if (!spk.GetOp(it, op, data) || !DecodeNum(op, data, 4, slot)) return false;
    if (spk.GetOp(it, op, data)) return false; // trailing data => not a vote
    return slot >= 0 && slot < NUM_ALGOS;
}

// Match a stake output: <lock> OP_CHECKSEQUENCEVERIFY OP_DROP <payout scriptPubKey>.
// Fills the relative timelock `lock`; the staked amount is the output's nValue.
bool ParseStakeOutput(const CScript& spk, int64_t& lock)
{
    CScript::const_iterator it = spk.begin();
    opcodetype op;
    std::vector<unsigned char> data;
    if (!spk.GetOp(it, op, data) || !DecodeNum(op, data, 5, lock)) return false;
    if (!spk.GetOp(it, op, data) || op != OP_CHECKSEQUENCEVERIFY) return false;
    if (!spk.GetOp(it, op, data) || op != OP_DROP) return false;
    return it < spk.end(); // a non-empty payout scriptPubKey must follow
}

struct Tally {
    CAmount fee_weight{0}; // sum of floor(fee / num_outputs)
    CAmount stake{0};      // sum of locked stake amounts
};

} // namespace

static RPCHelpMan getalgovote()
{
    return RPCHelpMan{
        "getalgovote",
        "\nTally the dynamic-algo votes for an mPoW slot over its sliding voting\n"
        "window (the last " + strprintf("%d", VOTING_PERIOD) + " blocks ending at `height`). INFORMATIONAL and\n"
        "NON-CONSENSUS: reports the fee-weighted and stake-weighted support for each\n"
        "candidate branch and which (if any) clears the 75% supermajority on BOTH.\n"
        "A vote is an output OP_RETURN OP_VOTE <branch> <slot>; fee weight is\n"
        "floor(tx_fee / num_outputs); stake weight is the sum of the tx's outputs\n"
        "locked (OP_CHECKSEQUENCEVERIFY) for at least the voting period.\n",
        {
            {"slot", RPCArg::Type::NUM, RPCArg::Optional::NO, "The mPoW slot (0.." + strprintf("%d", NUM_ALGOS - 1) + ")"},
            {"height", RPCArg::Type::NUM, RPCArg::DefaultHint{"tip"}, "End height of the voting window"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "slot", "The slot tallied"},
                {RPCResult::Type::OBJ, "window", "", {
                    {RPCResult::Type::NUM, "from", "First block height in the window"},
                    {RPCResult::Type::NUM, "to", "Last block height in the window (== height)"},
                }},
                {RPCResult::Type::STR_AMOUNT, "fee_total", "Total fee weight cast for this slot"},
                {RPCResult::Type::STR_AMOUNT, "stake_total", "Total stake cast for this slot"},
                {RPCResult::Type::ARR, "candidates", "Per-branch tallies, most fee-weight first", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "branch", "The voted branch content hash"},
                        {RPCResult::Type::STR_AMOUNT, "fee_weight", "Fee weight for this branch"},
                        {RPCResult::Type::NUM, "fee_pct", "Fee weight as a fraction of fee_total"},
                        {RPCResult::Type::STR_AMOUNT, "stake_weight", "Stake for this branch"},
                        {RPCResult::Type::NUM, "stake_pct", "Stake as a fraction of stake_total"},
                        {RPCResult::Type::BOOL, "assemblable", "Whether the branch currently assembles (getpushcode complete)"},
                    }},
                }},
                {RPCResult::Type::STR_HEX, "winner", /*optional=*/true, "Branch clearing 75% of BOTH tallies, or null"},
                {RPCResult::Type::NUM, "would_activate_at", /*optional=*/true, "Height the winner would take effect (height + delay), or null"},
            }
        },
        RPCExamples{
            HelpExampleCli("getalgovote", "5") +
            HelpExampleRpc("getalgovote", "5, 200000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const int slot{request.params[0].getInt<int>()};
            if (slot < 0 || slot >= NUM_ALGOS) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("slot out of range (0..%d)", NUM_ALGOS - 1));
            }
            ChainstateManager& chainman = EnsureAnyChainman(request.context);

            std::map<uint256, Tally> cand;
            CAmount fee_total{0}, stake_total{0};
            int win_from{0}, win_to{0};

            {
                LOCK(cs_main);
                const CChain& chain = chainman.ActiveChain();
                const int tip_height{chain.Height()};
                int E{tip_height};
                if (!request.params[1].isNull()) {
                    E = request.params[1].getInt<int>();
                    if (E < 0 || E > tip_height) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "height out of range");
                    }
                }
                win_to = E;
                win_from = std::max(0, E - (VOTING_PERIOD - 1));

                for (int h = win_from; h <= E; ++h) {
                    const CBlockIndex* pindex = chain[h];
                    if (!pindex) continue;
                    CBlock block;
                    if (!chainman.m_blockman.ReadBlockFromDisk(block, *pindex)) continue;
                    CBlockUndo undo;
                    const bool have_undo{pindex->nHeight > 0 &&
                                         chainman.m_blockman.UndoReadFromDisk(undo, *pindex)};

                    for (size_t i = 1; i < block.vtx.size(); ++i) { // skip coinbase (i==0)
                        const CTransaction& tx = *block.vtx[i];

                        // exactly one OP_VOTE output, targeting this slot
                        uint256 branch;
                        int votes{0};
                        bool for_slot{false};
                        for (const CTxOut& o : tx.vout) {
                            uint256 b;
                            int64_t s;
                            if (ParseVoteOutput(o.scriptPubKey, b, s)) {
                                ++votes;
                                branch = b;
                                for_slot = (s == slot);
                            }
                        }
                        if (votes != 1 || !for_slot) continue;

                        // fee weight = floor(fee / num_outputs)
                        CAmount fw{0};
                        if (have_undo && i - 1 < undo.vtxundo.size()) {
                            CAmount in{0}, out{0};
                            for (const Coin& c : undo.vtxundo[i - 1].vprevout) in += c.out.nValue;
                            for (const CTxOut& o : tx.vout) out += o.nValue;
                            const CAmount fee{in - out};
                            if (fee > 0 && !tx.vout.empty()) fw = fee / (CAmount)tx.vout.size();
                        }

                        // stake = sum of outputs locked >= VOTING_PERIOD
                        CAmount stake{0};
                        for (const CTxOut& o : tx.vout) {
                            int64_t lock;
                            if (ParseStakeOutput(o.scriptPubKey, lock) && lock >= VOTING_PERIOD) {
                                stake += o.nValue;
                            }
                        }

                        Tally& t = cand[branch];
                        t.fee_weight += fw;
                        t.stake += stake;
                        fee_total += fw;
                        stake_total += stake;
                    }
                }
            }

            // winner: 4*F(H) >= 3*Ftot AND 4*K(H) >= 3*Ktot (75% of each cast total)
            uint256 winner;
            bool have_winner{false};
            for (const auto& [h, t] : cand) {
                const bool fee_ok{(__int128)4 * t.fee_weight >= (__int128)3 * fee_total};
                const bool stake_ok{(__int128)4 * t.stake >= (__int128)3 * stake_total};
                // With empty totals the >=75% test is vacuously true; require some support.
                if (fee_ok && stake_ok && (t.fee_weight > 0 || t.stake > 0)) {
                    winner = h;
                    have_winner = true;
                    break;
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("slot", slot);
            UniValue window(UniValue::VOBJ);
            window.pushKV("from", win_from);
            window.pushKV("to", win_to);
            result.pushKV("window", window);
            result.pushKV("fee_total", ValueFromAmount(fee_total));
            result.pushKV("stake_total", ValueFromAmount(stake_total));

            UniValue arr(UniValue::VARR);
            {
                LOCK(cs_main);
                for (const auto& [h, t] : cand) {
                    UniValue c(UniValue::VOBJ);
                    c.pushKV("branch", h.GetHex());
                    c.pushKV("fee_weight", ValueFromAmount(t.fee_weight));
                    c.pushKV("fee_pct", fee_total ? (double)t.fee_weight / (double)fee_total : 0.0);
                    c.pushKV("stake_weight", ValueFromAmount(t.stake));
                    c.pushKV("stake_pct", stake_total ? (double)t.stake / (double)stake_total : 0.0);
                    std::vector<unsigned char> code;
                    std::string reason;
                    const bool assemblable{chainman.ActiveChainstate().AssemblePushCode(h, code, reason)
                                           == PushCodeStatus::COMPLETE};
                    c.pushKV("assemblable", assemblable);
                    arr.push_back(c);
                }
            }
            result.pushKV("candidates", arr);

            if (have_winner) {
                result.pushKV("winner", winner.GetHex());
                result.pushKV("would_activate_at", win_to + ACTIVATION_DELAY);
            } else {
                result.pushKV("winner", UniValue());
                result.pushKV("would_activate_at", UniValue());
            }
            return result;
        },
    };
}

void RegisterVoteRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"voting", &getalgovote},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
