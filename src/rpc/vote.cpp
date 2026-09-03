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
constexpr int ACTIVATION_DELAY = 720;    // blocks between a qualifying window and activation
constexpr int YEAR_BLOCKS = 720 * 365;   // 262800 blocks (~1 year), for the fee floor

using valtype = std::vector<unsigned char>;

// Slot is stored as a 1-byte value in vSolutions (0..NUM_ALGOS-1).
int DecodeSlot(const valtype& v) { return v.empty() ? 0 : v[0]; }

// Relative timelock (CScriptNum, up to 5 bytes) from a STAKE_VOTE's vSolutions.
int64_t DecodeLock(const valtype& v)
{
    if (v.empty()) return 0;
    return CScriptNum(v, /*fRequireMinimal=*/false, 5).getint();
}

// Total transaction fees in a block (sum of inputs - outputs over non-coinbase
// txs). Needs the block's undo data for the spent-input values.
CAmount BlockTotalFees(const CBlock& block, const CBlockUndo& undo)
{
    CAmount fees{0};
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if (i - 1 >= undo.vtxundo.size()) break;
        CAmount in{0}, out{0};
        for (const Coin& c : undo.vtxundo[i - 1].vprevout) in += c.out.nValue;
        for (const CTxOut& o : block.vtx[i]->vout) out += o.nValue;
        if (in > out) fees += in - out;
    }
    return fees;
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
        "\nFind the winning dynamic-algo vote for an mPoW slot. INFORMATIONAL and\n"
        "NON-CONSENSUS. Searches the last MAX_PUSHCODE_DEPTH blocks for the LATEST\n"
        "'anchored' voting window: a sequence of " + strprintf("%d", VOTING_PERIOD) + " blocks whose FIRST block\n"
        "carries a vote for slot s and branch b, where b wins that window (>=75% of the\n"
        "fee-weight AND >=75% of the stake AND the total fee-weight meets the fee floor).\n"
        "The winner's activation block is that window's LAST block + " + strprintf("%d", ACTIVATION_DELAY) + " + 1.\n"
        "Votes are PER-OUTPUT (so a coinjoin can carry many): a FEE_VOTE output\n"
        "(OP_RETURN OP_VOTE <branch> <slot>) gets fee weight floor(tx_fee/num_outputs);\n"
        "a STAKE_VOTE output (CSV-locked, self-describing) gets stake weight equal to\n"
        "its value when its timelock is at least the voting period. The fee floor is\n"
        "6.25% of an average window's total fees over the prior year.\n",
        {
            {"slot", RPCArg::Type::NUM, RPCArg::Optional::NO, "The mPoW slot (0.." + strprintf("%d", NUM_ALGOS - 1) + ")"},
            {"height", RPCArg::Type::NUM, RPCArg::DefaultHint{"tip"}, "Evaluate as of this chain height (top of the search range)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "slot", "The slot tallied"},
                {RPCResult::Type::OBJ, "search", "The block range searched for a winning anchored window", {
                    {RPCResult::Type::NUM, "from", "First block height searched (>= tip - MAX_PUSHCODE_DEPTH)"},
                    {RPCResult::Type::NUM, "to", "Last block height searched (the tip, or `height`)"},
                }},
                {RPCResult::Type::OBJ, "window", /*optional=*/true, "The reported voting window (the winning one, else the latest vote-anchored complete window); null if none", {
                    {RPCResult::Type::NUM, "from", "First block of the 5760-block window (anchor)"},
                    {RPCResult::Type::NUM, "to", "Last block of the window"},
                }},
                {RPCResult::Type::STR_AMOUNT, "fee_total", /*optional=*/true, "Total fee weight cast in the window"},
                {RPCResult::Type::STR_AMOUNT, "stake_total", /*optional=*/true, "Total stake cast in the window"},
                {RPCResult::Type::STR_AMOUNT, "fee_floor", /*optional=*/true, "Minimum fee_total to qualify: 6.25% of an average window's fees over the prior year"},
                {RPCResult::Type::BOOL, "fee_floor_met", /*optional=*/true, "Whether fee_total >= fee_floor"},
                {RPCResult::Type::ARR, "candidates", /*optional=*/true, "Per-branch tallies for the window", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "branch", "The voted branch content hash"},
                        {RPCResult::Type::STR_AMOUNT, "fee_weight", "Fee weight for this branch"},
                        {RPCResult::Type::NUM, "fee_pct", "Fee weight as a fraction of fee_total"},
                        {RPCResult::Type::STR_AMOUNT, "stake_weight", "Stake for this branch"},
                        {RPCResult::Type::NUM, "stake_pct", "Stake as a fraction of stake_total"},
                        {RPCResult::Type::BOOL, "assemblable", "Whether the branch currently assembles (getpushcode complete)"},
                    }},
                }},
                {RPCResult::Type::STR_HEX, "winner", /*optional=*/true, "Branch of the latest anchored window it wins (75% of both + fee floor, and voted in the window's first block), or null"},
                {RPCResult::Type::NUM, "activation_block", /*optional=*/true, "Height the winner takes effect: window last block + 720 + 1, or null"},
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

            // Result of the search (filled under cs_main).
            bool have_winner{false};
            uint256 winner;
            int win_f{-1};           // start of the winning anchored window
            // The window whose tally we report: the winning one, else the latest
            // vote-anchored complete window (for diagnostics).
            std::map<uint256, Tally> rep_cand;
            CAmount rep_fee_total{0}, rep_stake_total{0}, rep_fee_floor{0};
            int rep_f{-1};
            int E{0}, search_lo{0};

            {
                LOCK(cs_main);
                const CChain& chain = chainman.ActiveChain();
                const int tip_height{chain.Height()};
                E = tip_height;
                if (!request.params[1].isNull()) {
                    E = request.params[1].getInt<int>();
                    if (E < 0 || E > tip_height) throw JSONRPCError(RPC_INVALID_PARAMETER, "height out of range");
                }
                search_lo = std::max(0, E - (int)MAX_PUSHCODE_DEPTH + 1);

                // Pass 1: read [search_lo, E] once, collecting per-block vote data for
                // slot s (sparse) and per-block total fees (dense, for the floor).
                std::map<int, std::map<uint256, Tally>> votes; // height -> branch -> {fee,stake}
                std::vector<CAmount> fees(E - search_lo + 1, 0);
                for (int h = search_lo; h <= E; ++h) {
                    const CBlockIndex* pindex = chain[h];
                    if (!pindex) continue;
                    CBlock block;
                    if (!chainman.m_blockman.ReadBlockFromDisk(block, *pindex)) continue;
                    CBlockUndo undo;
                    const bool have_undo{pindex->nHeight > 0 && chainman.m_blockman.UndoReadFromDisk(undo, *pindex)};
                    if (have_undo) fees[h - search_lo] = BlockTotalFees(block, undo);

                    for (size_t i = 1; i < block.vtx.size(); ++i) { // skip coinbase
                        const CTransaction& tx = *block.vtx[i];
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
                            if (type == TxoutType::FEE_VOTE && DecodeSlot(sols[1]) == slot) {
                                votes[h][uint256(sols[0])].fee_weight += fee_share;
                            } else if (type == TxoutType::STAKE_VOTE && DecodeSlot(sols[1]) == slot
                                       && DecodeLock(sols[2]) >= VOTING_PERIOD) {
                                votes[h][uint256(sols[0])].stake += o.nValue;
                            }
                        }
                    }
                }

                // Prefix sums of block fees -> O(1) year-fee (the fee floor's basis).
                std::vector<CAmount> pref(fees.size() + 1, 0);
                for (size_t i = 0; i < fees.size(); ++i) pref[i + 1] = pref[i] + fees[i];
                auto fee_floor_at = [&](int f) -> CAmount {
                    // 6.25% of an avg window's fees over the YEAR_BLOCKS ending at f-1
                    // == year_fees / 730. (year fees may be truncated to search_lo.)
                    const int ye{f - 1};
                    if (ye < search_lo) return 0;
                    const int ys{std::max(search_lo, ye - YEAR_BLOCKS + 1)};
                    return (pref[ye - search_lo + 1] - pref[ys - search_lo]) / 730;
                };

                // Pass 2: latest anchored winning window. A candidate window starts at a
                // block f that has a vote for slot s; the window is [f, f+VOTING_PERIOD-1]
                // (must be complete: f <= E - VOTING_PERIOD + 1). H wins the window if it
                // clears 75% of both tallies + the fee floor; the anchor rule also requires
                // block f to carry a vote for that winner H.
                const int max_f{E - (VOTING_PERIOD - 1)};
                for (auto it = votes.rbegin(); it != votes.rend(); ++it) {
                    const int f{it->first};
                    if (f > max_f) continue;

                    std::map<uint256, Tally> cand;
                    CAmount ftot{0}, ktot{0};
                    for (auto jt = votes.find(f); jt != votes.end() && jt->first <= f + VOTING_PERIOD - 1; ++jt) {
                        for (const auto& [b, t] : jt->second) {
                            cand[b].fee_weight += t.fee_weight; ftot += t.fee_weight;
                            cand[b].stake += t.stake;           ktot += t.stake;
                        }
                    }
                    const CAmount floor{fee_floor_at(f)};

                    uint256 b;
                    bool found{false};
                    for (const auto& [cb, t] : cand) {
                        if (ftot > 0 && ktot > 0 && ftot >= floor
                            && (__int128)4 * t.fee_weight >= (__int128)3 * ftot
                            && (__int128)4 * t.stake >= (__int128)3 * ktot) {
                            b = cb; found = true; break;
                        }
                    }

                    if (rep_f < 0) { // latest candidate window: report it if no winner
                        rep_f = f; rep_cand = cand; rep_fee_total = ftot; rep_stake_total = ktot; rep_fee_floor = floor;
                    }
                    if (found && it->second.count(b)) { // winner voted for in the FIRST block
                        have_winner = true; winner = b; win_f = f;
                        rep_f = f; rep_cand = cand; rep_fee_total = ftot; rep_stake_total = ktot; rep_fee_floor = floor;
                        break;
                    }
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("slot", slot);
            UniValue search(UniValue::VOBJ);
            search.pushKV("from", search_lo);
            search.pushKV("to", E);
            result.pushKV("search", search);

            if (rep_f >= 0) {
                UniValue window(UniValue::VOBJ);
                window.pushKV("from", rep_f);
                window.pushKV("to", rep_f + VOTING_PERIOD - 1);
                result.pushKV("window", window);
                result.pushKV("fee_total", ValueFromAmount(rep_fee_total));
                result.pushKV("stake_total", ValueFromAmount(rep_stake_total));
                result.pushKV("fee_floor", ValueFromAmount(rep_fee_floor));
                result.pushKV("fee_floor_met", rep_fee_total >= rep_fee_floor);
                UniValue arr(UniValue::VARR);
                {
                    LOCK(cs_main);
                    for (const auto& [b, t] : rep_cand) {
                        UniValue c(UniValue::VOBJ);
                        c.pushKV("branch", b.GetHex());
                        c.pushKV("fee_weight", ValueFromAmount(t.fee_weight));
                        c.pushKV("fee_pct", rep_fee_total ? (double)t.fee_weight / (double)rep_fee_total : 0.0);
                        c.pushKV("stake_weight", ValueFromAmount(t.stake));
                        c.pushKV("stake_pct", rep_stake_total ? (double)t.stake / (double)rep_stake_total : 0.0);
                        std::vector<unsigned char> code;
                        std::string reason;
                        c.pushKV("assemblable", chainman.ActiveChainstate().AssemblePushCode(b, code, reason)
                                                == PushCodeStatus::COMPLETE);
                        arr.push_back(c);
                    }
                }
                result.pushKV("candidates", arr);
            } else {
                result.pushKV("window", UniValue());
                result.pushKV("candidates", UniValue(UniValue::VARR));
            }

            if (have_winner) {
                result.pushKV("winner", winner.GetHex());
                // last block of the sequence + 720 + 1
                result.pushKV("activation_block", (win_f + VOTING_PERIOD - 1) + ACTIVATION_DELAY + 1);
            } else {
                result.pushKV("winner", UniValue());
                result.pushKV("activation_block", UniValue());
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
