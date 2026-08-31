// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key_io.h>
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
#include <script/solver.h>
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

using valtype = std::vector<unsigned char>;

// Slot is stored as a 1-byte value in vSolutions (0..NUM_ALGOS-1).
int DecodeSlot(const valtype& v) { return v.empty() ? 0 : v[0]; }

// Relative timelock (CScriptNum, up to 5 bytes) from a STAKE_VOTE's vSolutions.
int64_t DecodeLock(const valtype& v)
{
    if (v.empty()) return 0;
    return CScriptNum(v, /*fRequireMinimal=*/false, 5).getint();
}

struct Tally {
    CAmount fee_weight{0}; // sum of floor(fee / num_outputs) over this branch's FEE_VOTE outputs
    CAmount stake{0};      // sum of locked stake amounts over this branch's STAKE_VOTE outputs
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
        "Votes are PER-OUTPUT (so a coinjoin can carry many): a FEE_VOTE output\n"
        "(OP_RETURN OP_VOTE <branch> <slot>) gets fee weight floor(tx_fee/num_outputs);\n"
        "a STAKE_VOTE output (CSV-locked, self-describing) gets stake weight equal to\n"
        "its value when its timelock is at least the voting period.\n",
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

                        // Votes are per-OUTPUT (so a coinjoin can carry many). The
                        // fee-share each FEE_VOTE output gets is floor(fee/num_outputs).
                        CAmount fee_share{0};
                        if (have_undo && i - 1 < undo.vtxundo.size() && !tx.vout.empty()) {
                            CAmount in{0}, out{0};
                            for (const Coin& c : undo.vtxundo[i - 1].vprevout) in += c.out.nValue;
                            for (const CTxOut& o : tx.vout) out += o.nValue;
                            const CAmount fee{in - out};
                            if (fee > 0) fee_share = fee / (CAmount)tx.vout.size();
                        }

                        for (const CTxOut& o : tx.vout) {
                            std::vector<valtype> sols;
                            const TxoutType type{Solver(o.scriptPubKey, sols)};
                            if (type == TxoutType::FEE_VOTE) {
                                if (DecodeSlot(sols[1]) != slot) continue;
                                const uint256 branch{sols[0]};
                                cand[branch].fee_weight += fee_share;
                                fee_total += fee_share;
                            } else if (type == TxoutType::STAKE_VOTE) {
                                if (DecodeSlot(sols[1]) != slot) continue;
                                if (DecodeLock(sols[2]) < VOTING_PERIOD) continue; // not locked long enough
                                const uint256 branch{sols[0]};
                                cand[branch].stake += o.nValue;
                                stake_total += o.nValue;
                            }
                        }
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

static RPCHelpMan createfeevotescript()
{
    return RPCHelpMan{
        "createfeevotescript",
        "\nBuild a FEE_VOTE output scriptPubKey (OP_RETURN OP_VOTE <branch> <slot>) and\n"
        "return its hex. This is an unspendable output whose fee-weight in a vote tally\n"
        "comes from the transaction's fee (fee / num_outputs). Drop the hex into a raw\n"
        "transaction output; it does not need to hold value.\n",
        {
            {"branch", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte content hash of the algo branch to vote for"},
            {"slot", RPCArg::Type::NUM, RPCArg::Optional::NO, "The mPoW slot (0.." + strprintf("%d", NUM_ALGOS - 1) + ")"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The FEE_VOTE scriptPubKey"},
        }},
        RPCExamples{HelpExampleCli("createfeevotescript", "\"<branch>\" 5")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const uint256 branch{ParseHashV(request.params[0], "branch")};
            const int slot{request.params[1].getInt<int>()};
            if (slot < 0 || slot >= NUM_ALGOS) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("slot out of range (0..%d)", NUM_ALGOS - 1));
            }
            CScript script;
            script << OP_RETURN << OP_VOTE << ToByteVector(branch) << (int64_t)slot;
            std::vector<valtype> sols;
            if (Solver(script, sols) != TxoutType::FEE_VOTE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "constructed script is not a valid FEE_VOTE output");
            }
            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", HexStr(script));
            return result;
        },
    };
}

static RPCHelpMan createstakevotescript()
{
    return RPCHelpMan{
        "createstakevotescript",
        "\nBuild a STAKE_VOTE output scriptPubKey:\n"
        "  <locktime> OP_CHECKSEQUENCEVERIFY OP_DROP OP_VOTE <branch> OP_DROP <slot> OP_DROP <payout>\n"
        "It is spendable back to `address` after `locktime` relative blocks (BIP68), and\n"
        "its stake-weight in a vote tally is the output's value (counted only when\n"
        "locktime >= the voting period, " + strprintf("%d", VOTING_PERIOD) + " blocks). Put a real value on this output.\n",
        {
            {"branch", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte content hash of the algo branch to vote for"},
            {"slot", RPCArg::Type::NUM, RPCArg::Optional::NO, "The mPoW slot (0.." + strprintf("%d", NUM_ALGOS - 1) + ")"},
            {"locktime", RPCArg::Type::NUM, RPCArg::Optional::NO, "Relative timelock in blocks (>= " + strprintf("%d", VOTING_PERIOD) + " to count as stake)"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address the locked coins return to"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The STAKE_VOTE scriptPubKey"},
        }},
        RPCExamples{HelpExampleCli("createstakevotescript", "\"<branch>\" 5 5760 \"<address>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const uint256 branch{ParseHashV(request.params[0], "branch")};
            const int slot{request.params[1].getInt<int>()};
            if (slot < 0 || slot >= NUM_ALGOS) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("slot out of range (0..%d)", NUM_ALGOS - 1));
            }
            const int64_t locktime{request.params[2].getInt<int64_t>()};
            if (locktime < 0 || locktime > 0x0000ffff) { // BIP68 relative-height locks are 16-bit
                throw JSONRPCError(RPC_INVALID_PARAMETER, "locktime out of BIP68 relative-height range (0..65535)");
            }
            const CTxDestination dest{DecodeDestination(request.params[3].get_str())};
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid address");
            }
            const CScript payout{GetScriptForDestination(dest)};

            CScript script;
            script << CScriptNum(locktime) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_VOTE
                   << ToByteVector(branch) << OP_DROP << (int64_t)slot << OP_DROP;
            script.insert(script.end(), payout.begin(), payout.end());

            std::vector<valtype> sols;
            if (Solver(script, sols) != TxoutType::STAKE_VOTE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "constructed script is not a valid STAKE_VOTE output");
            }
            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", HexStr(script));
            return result;
        },
    };
}

void RegisterVoteRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"voting", &createfeevotescript},
        {"voting", &createstakevotescript},
        {"voting", &getalgovote},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
