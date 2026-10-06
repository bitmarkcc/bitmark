// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <dynamicalgo/algovote.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <policy/policy.h>
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

// VOTING_PERIOD (the anchored-window length) is a per-chain consensus parameter,
// consensus.nVotingPeriod -- read it from the active chain params.
constexpr int ACTIVATION_DELAY = 720;    // blocks after a qualifying window before activation
constexpr int YEAR_BLOCKS = 720 * 365;   // 262800 blocks (~1 year), for the fee floor

using valtype = std::vector<unsigned char>;

// The vote parsing, per-block tally, fee floor and window-winner logic live in the shared
// consensus module dynamicalgo/algovote.h, so this informational RPC and the consensus
// activation resolver read votes and pick winners identically.
using Tally = dynamicalgo::VoteTally; // { fee_weight, stake }

} // namespace

static RPCHelpMan getalgovote()
{
    return RPCHelpMan{
        "getalgovote",
        "\nFind the winning dynamic-algo vote for an mPoW slot. INFORMATIONAL and\n"
        "NON-CONSENSUS. Searches the last MAX_PUSHCODE_DEPTH blocks for the LATEST\n"
        "'anchored' voting window: a voting-period-long sequence of blocks (the period\n"
        "is the consensus parameter nVotingPeriod) whose FIRST block\n"
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
                {RPCResult::Type::NUM, "activation_block", /*optional=*/true, "Height at which the activation is DECIDED and recorded (window last block + 720 + 1), or null. NOT the first height the algo applies -- see enforced_from"},
                {RPCResult::Type::NUM, "enforced_from", /*optional=*/true, "First height on this slot whose block must satisfy the algo's reward rules, i.e. activation_block + 1, or null. Which algo a slot runs is evaluated on a block's PARENT chain, so the block that records the activation is itself still judged primitively. This is the height a miner must be ready for"},
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
            const int voting_period{chainman.GetConsensus().nVotingPeriod};

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
                    if (!have_undo) undo = CBlockUndo{}; // empty on failure: fees 0, FEE_VOTE weight 0
                    fees[h - search_lo] = dynamicalgo::BlockTotalFees(block, undo);
                    std::map<uint256, Tally> bv{dynamicalgo::BlockVotesForSlot(block, undo, slot, voting_period)};
                    if (!bv.empty()) votes[h] = std::move(bv);
                }

                // Prefix sums of block fees -> O(1) year-fee (the fee floor's basis).
                std::vector<CAmount> pref(fees.size() + 1, 0);
                for (size_t i = 0; i < fees.size(); ++i) pref[i + 1] = pref[i] + fees[i];
                auto fee_floor_at = [&](int f) -> CAmount {
                    // 6.25% of an AVERAGE voting window's fees, over the fee history
                    // ending at f-1 (== year_fees / 730 once a full year is available;
                    // normalized by the number of blocks actually summed, which here may
                    // be truncated to search_lo).
                    const int ye{f - 1};
                    if (ye < search_lo) return 0;
                    const int ys{std::max(search_lo, ye - YEAR_BLOCKS + 1)};
                    return dynamicalgo::VoteFeeFloor(pref[ye - search_lo + 1] - pref[ys - search_lo],
                                                     ye - ys + 1, voting_period);
                };

                // Pass 2: latest anchored winning window. A candidate window starts at a
                // block f that has a vote for slot s; the window is [f, f+voting_period-1]
                // (must be complete: f <= E - voting_period + 1). H wins the window if it
                // clears 75% of both tallies + the fee floor; the anchor rule also requires
                // block f to carry a vote for that winner H.
                const int max_f{E - (voting_period - 1)};
                for (auto it = votes.rbegin(); it != votes.rend(); ++it) {
                    const int f{it->first};
                    if (f > max_f) continue;

                    std::map<uint256, Tally> cand;
                    CAmount ftot{0}, ktot{0};
                    for (auto jt = votes.find(f); jt != votes.end() && jt->first <= f + voting_period - 1; ++jt) {
                        for (const auto& [b, t] : jt->second) {
                            cand[b].fee_weight += t.fee_weight; ftot += t.fee_weight;
                            cand[b].stake += t.stake;           ktot += t.stake;
                        }
                    }
                    const CAmount floor{fee_floor_at(f)};

                    uint256 b;
                    bool found{false};
                    if (const auto win{dynamicalgo::VoteWindowWinner(cand, floor)}) {
                        b = *win; found = true;
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
                window.pushKV("to", rep_f + voting_period - 1);
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
                const int64_t recorded_at{(win_f + voting_period - 1) + ACTIVATION_DELAY + 1};
                result.pushKV("activation_block", recorded_at);
                // One later: a slot's algo is evaluated on a block's parent chain, so the
                // block that records the activation is still judged primitively. This is
                // the number a miner needs -- the first block it must be ready for.
                result.pushKV("enforced_from", recorded_at + 1);
            } else {
                result.pushKV("winner", UniValue());
                result.pushKV("activation_block", UniValue());
                result.pushKV("enforced_from", UniValue());
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
        "locktime >= the chain's voting period, nVotingPeriod). Put a real value on this output.\n",
        {
            {"branch", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte content hash of the algo branch to vote for"},
            {"slot", RPCArg::Type::NUM, RPCArg::Optional::NO, "The mPoW slot (0.." + strprintf("%d", NUM_ALGOS - 1) + ")"},
            {"locktime", RPCArg::Type::NUM, RPCArg::Optional::NO, "Relative timelock in blocks (>= the chain's nVotingPeriod to count as stake)"},
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

static RPCHelpMan getalgoreadiness()
{
    return RPCHelpMan{
        "getalgoreadiness",
        "\nPer-slot miner readiness for the dynamic-algo coinbase obligations.\n"
        "\n"
        "Approving an algo for a slot imposes a NEW OBLIGATION on that slot's miners:\n"
        "every block of the slot must then carry the coinbase outputs the node hands out\n"
        "in getblocktemplate's `coinbaserequired` -- the dynamic miner's payment, or the\n"
        "OP_SOLUTIONPOT output holding withheld fees. Only the POOL can add those, since\n"
        "only the pool builds the coinbase, so a pool running old software produces\n"
        "INVALID blocks from the moment its slot activates.\n"
        "\n"
        "Block nVersion does not answer this: getblocktemplate hands the pool a `version`\n"
        "field which it copies into the header without interpreting it, so a version-5\n"
        "block proves the NODE is upgraded and says nothing about the pool. Miners\n"
        "therefore signal by voluntarily adding a 0-value unspendable readiness marker to\n"
        "their coinbase (getblocktemplate's `coinbasesignal`), which demonstrates exactly\n"
        "the capability activation will demand.\n"
        "\n"
        "This is EVIDENCE FOR VOTERS, not a consensus gate. Coverage is not a threshold to\n"
        "clear: a majority of markers does not prove the remainder safe, and their absence\n"
        "does not prove activation unwise -- a large pool may simply not have bothered.\n"
        "Deliberately advisory so that no single miner can hold a slot hostage by\n"
        "declining to signal. Prefer activating slots with broad coverage and low\n"
        "hashpower concentration; a slot with no active algo is unaffected by any of this.\n",
        {
            {"blocks", RPCArg::Type::NUM, RPCArg::Default{800},
             "How many recent blocks to scan, across all slots. With 8 algos this averages\n"
             "blocks/8 per slot. Each block is read from disk, so large values are slow."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "from", "First block height scanned"},
                {RPCResult::Type::NUM, "to", "Last block height scanned (the tip)"},
                {RPCResult::Type::ARR, "slots", "One entry per mPoW slot", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "slot", "The mPoW slot"},
                        {RPCResult::Type::STR, "algo", "The slot's proof-of-work algorithm"},
                        {RPCResult::Type::NUM, "blocks", "The slot's blocks found in the range"},
                        {RPCResult::Type::NUM, "signalled", "How many of them carried the readiness marker"},
                        {RPCResult::Type::NUM, "pct", "signalled / blocks, or 0 when the slot produced none"},
                        {RPCResult::Type::BOOL, "algo_active", "Whether this slot already has a dynamic algo activated (in which case the obligation is live now)"},
                    }},
                }},
            },
        },
        RPCExamples{HelpExampleCli("getalgoreadiness", "") + HelpExampleRpc("getalgoreadiness", "2400")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            int span{800};
            if (!request.params[0].isNull()) {
                span = request.params[0].getInt<int>();
                if (span < 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "blocks must be >= 1");
            }

            LOCK(cs_main);
            const CChain& chain = chainman.ActiveChain();
            const CBlockIndex* tip = chain.Tip();
            if (!tip) throw JSONRPCError(RPC_IN_WARMUP, "no chain yet");
            const int hi{tip->nHeight};
            const int lo{std::max(0, hi - span + 1)};

            std::array<int, NUM_ALGOS> blocks{};
            std::array<int, NUM_ALGOS> signalled{};
            for (int h = lo; h <= hi; ++h) {
                const CBlockIndex* pindex = chain[h];
                if (!pindex) continue;
                const int a{static_cast<int>(pindex->GetAlgo())};
                if (a < 0 || a >= NUM_ALGOS) continue;
                CBlock block;
                if (!chainman.m_blockman.ReadBlockFromDisk(block, *pindex)) continue;
                if (block.vtx.empty()) continue;
                ++blocks[a];
                // The marker is the UNSPENDABLE form of a solution-pot output: an empty
                // vSolutions distinguishes it from a real pot carrying withheld fees,
                // which must not be counted as a signal.
                for (const CTxOut& o : block.vtx[0]->vout) {
                    std::vector<std::vector<unsigned char>> sols;
                    if (Solver(o.scriptPubKey, sols) == TxoutType::SOLUTIONPOT && sols.empty()) {
                        ++signalled[a];
                        break;
                    }
                }
            }

            UniValue arr(UniValue::VARR);
            for (int a = 0; a < NUM_ALGOS; ++a) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("slot", a);
                o.pushKV("algo", ToString(static_cast<Algo>(a)));
                o.pushKV("blocks", blocks[a]);
                o.pushKV("signalled", signalled[a]);
                o.pushKV("pct", blocks[a] > 0 ? (double)signalled[a] / (double)blocks[a] : 0.0);
                o.pushKV("algo_active",
                         chainman.ActiveChainstate().GetActiveAlgoBranch(a).has_value());
                arr.push_back(o);
            }
            UniValue result(UniValue::VOBJ);
            result.pushKV("from", lo);
            result.pushKV("to", hi);
            result.pushKV("slots", arr);
            return result;
        },
    };
}


// Bitmark: shared front half of the two pot-spend builders (doc sec 4.5 "Spend paths").
// Resolves the requested outpoints against the UTXO set, insists every one is a real
// solution pot of ONE slot, and returns their total. `selector` is the scriptSig push
// that picks the spend path, and is the only difference between the two transactions'
// inputs.
static CAmount BuildPotSpendInputs(const UniValue& inputs, ChainstateManager& chainman,
                                   int selector, CMutableTransaction& mtx, int& algo_out)
{
    if (inputs.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "no pot outputs given");
    }
    CAmount total{0};
    algo_out = -1;
    LOCK(cs_main);
    const CCoinsViewCache& coins{chainman.ActiveChainstate().CoinsTip()};
    for (size_t i = 0; i < inputs.size(); i++) {
        const UniValue& o{inputs[i].get_obj()};
        RPCTypeCheckObj(o, {{"txid", UniValueType(UniValue::VSTR)},
                            {"vout", UniValueType(UniValue::VNUM)}});
        const Txid txid{Txid::FromUint256(ParseHashO(o, "txid"))};
        const int vout{o.find_value("vout").getInt<int>()};
        if (vout < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must not be negative");
        const COutPoint outpoint{txid, static_cast<uint32_t>(vout)};

        const Coin& coin{coins.AccessCoin(outpoint)};
        if (coin.IsSpent()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s:%d is not an unspent output", txid.GetHex(), vout));
        }
        std::vector<std::vector<unsigned char>> sols;
        int algo{-1};
        if (Solver(coin.out.scriptPubKey, sols) != TxoutType::SOLUTIONPOT
            || !SolutionPotAlgo(sols, algo)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s:%d is not a solution pot output", txid.GetHex(), vout));
        }
        if (algo_out == -1) {
            algo_out = algo;
        } else if (algo != algo_out) {
            // The covenant rejects mixed slots, since the value accounting would be
            // ambiguous -- catch it here rather than hand back an unusable transaction.
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s:%d is a slot-%d pot; all inputs must be one slot (saw %d)",
                                         txid.GetHex(), vout, algo, algo_out));
        }
        total += coin.out.nValue;
        // Keyless: the scriptSig is just the selector, and nothing signs anything -- the
        // covenant settles both paths by value accounting alone. The int64_t overload
        // emits OP_0 / OP_1, which is the ONE encoding the covenant accepts: anything
        // else, including a data push of the same value, is rejected so that no third
        // party can re-encode the scriptSig and change the txid.
        CTxIn in{outpoint};
        in.scriptSig = CScript() << static_cast<int64_t>(selector);
        mtx.vin.push_back(std::move(in));
    }
    return total;
}

static RPCHelpMan createsolutionpotclaim()
{
    return RPCHelpMan{
        "createsolutionpotclaim",
        "\nBuild the transaction that releases a slot's solution pot (doc sec 4.5). Pot-only\n"
        "inputs with scriptSig selector 0, and a single 0-value OP_RETURN output, so the\n"
        "whole pot becomes transaction fee and the coinbase of the block carrying it claims\n"
        "the value.\n"
        "\nIT IS ONLY VALID IN A BLOCK THAT CARRIES A VALID DYNAMIC-ALGO SOLUTION for the\n"
        "pot's own slot. Do NOT broadcast it: a claim in the mempool would be selected on\n"
        "its (enormous) feerate by miners that have no solution, and every such block is\n"
        "invalid -- so pot spends are deliberately non-standard and will not relay. Put it\n"
        "in a block you are assembling yourself.\n"
        "\nFind a slot's pots with scantxoutset and the pot scriptPubKey, which is OP_1..OP_8\n"
        "(the slot plus one) followed by OP_SOLUTIONPOT -- e.g. slot 0 is\n"
        "scantxoutset start '[\"raw(51b7)\"]', slot 1 is raw(52b7).\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The pot outputs to release",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                        }},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The raw transaction"},
            {RPCResult::Type::NUM, "slot", "The mPoW slot whose pot this releases"},
            {RPCResult::Type::STR_AMOUNT, "amount", "Total value released, which becomes fee"},
        }},
        RPCExamples{HelpExampleCli("createsolutionpotclaim", "'[{\"txid\":\"<id>\",\"vout\":0}]'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            CMutableTransaction mtx;
            int algo{-1};
            const CAmount total{BuildPotSpendInputs(request.params[0].get_array(), chainman,
                                                    /*selector=*/0, mtx, algo)};
            // One 0-value unspendable output: with pot-only inputs that makes the fee
            // exactly the pot, which is the covenant's "released value becomes fee" rule.
            mtx.vout.emplace_back(0, CScript() << OP_RETURN);

            // Pad to the minimum relayable size. A one-input claim serializes to 62 bytes,
            // and anything below MIN_STANDARD_TX_NONWITNESS_SIZE (65, "one larger than
            // 64") will not relay -- that rule keeps 64-byte transactions off the network,
            // because one is byte-indistinguishable from two concatenated 32-byte hashes,
            // i.e. a merkle tree internal node, which is what lets an attacker forge SPV
            // merkle proofs. The covenant asks only that this output be 0-value and
            // unspendable, and OP_RETURN with a few bytes of data still is, so complying
            // costs three bytes. Computed rather than fixed: a claim with two or more
            // inputs is already past 100 bytes and pays nothing.
            const size_t bare{::GetSerializeSize(TX_NO_WITNESS(CTransaction(mtx)))};
            if (bare < MIN_STANDARD_TX_NONWITNESS_SIZE) {
                const size_t need{MIN_STANDARD_TX_NONWITNESS_SIZE - bare};
                // One byte of the growth is the push opcode itself.
                mtx.vout[0].scriptPubKey =
                    CScript() << OP_RETURN << std::vector<unsigned char>(need - 1, 0x00);
            }
            CHECK_NONFATAL(::GetSerializeSize(TX_NO_WITNESS(CTransaction(mtx)))
                           >= MIN_STANDARD_TX_NONWITNESS_SIZE);

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
            result.pushKV("slot", algo);
            result.pushKV("amount", ValueFromAmount(total));
            return result;
        },
    };
}

static RPCHelpMan createsolutionpotconsolidate()
{
    return RPCHelpMan{
        "createsolutionpotconsolidate",
        "\nBuild the transaction that merges several of a slot's solution pots into one\n"
        "(doc sec 4.5). Pot-only inputs with scriptSig selector 1, and a single pot output\n"
        "for the same slot carrying exactly the sum, so it is value-preserving and pays no\n"
        "fee.\n"
        "\nA coinbase cannot spend, so every no-solution block adds another pot output and\n"
        "something has to collapse them; this is that. Unlike a claim it needs no solution\n"
        "and is valid in any block -- but it pays no fee, so it will not relay either. Put\n"
        "it in a block you are assembling yourself.\n"
        "\nFind a slot's pots with scantxoutset -- see createsolutionpotclaim.\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The pot outputs to merge (at least two)",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                        }},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The raw transaction"},
            {RPCResult::Type::NUM, "slot", "The mPoW slot these pots belong to"},
            {RPCResult::Type::STR_AMOUNT, "amount", "Value of the merged pot"},
        }},
        RPCExamples{HelpExampleCli("createsolutionpotconsolidate", "'[{\"txid\":\"<id>\",\"vout\":0},{\"txid\":\"<id2>\",\"vout\":0}]'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const UniValue inputs{request.params[0].get_array()};
            if (inputs.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "consolidating needs at least two pot outputs");
            }
            CMutableTransaction mtx;
            int algo{-1};
            const CAmount total{BuildPotSpendInputs(inputs, chainman, /*selector=*/1, mtx, algo)};
            // Exactly the sum, to the same slot: no value created, and zero fee, so
            // consolidating cannot leak pot value to a miner.
            mtx.vout.emplace_back(total, SolutionPotScript(algo));

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
            result.pushKV("slot", algo);
            result.pushKV("amount", ValueFromAmount(total));
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
        {"voting", &getalgoreadiness},
        {"mining", &createsolutionpotclaim},
        {"mining", &createsolutionpotconsolidate},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
