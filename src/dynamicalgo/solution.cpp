// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/solution.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>

#include <utility>

namespace dynamicalgo {

namespace {

//! Assemble one transaction's OP_SOLUTION outputs. Returns false with `why_not` set when
//! that set is malformed; the callers turn that into "no solution", never an error.
bool ExtractFromTx(const CTransaction& tx, BlockSolution& out, std::string& why_not)
{
    struct Chunk { int64_t seq; std::vector<unsigned char> bytes; };
    std::vector<Chunk> chunks;

    for (const CTxOut& o : tx.vout) {
        std::vector<std::vector<unsigned char>> sols;
        if (Solver(o.scriptPubKey, sols) != TxoutType::SOLUTION) continue;
        // MatchSolution guarantees sols == [seq, chunk].
        int64_t seq;
        try {
            seq = CScriptNum(sols[0], /*fRequireMinimal=*/true, /*nMaxNumSize=*/4).GetInt64();
        } catch (const scriptnum_error&) {
            why_not = "solution seq is not a valid minimal number";
            return false;
        }
        if (seq < 0) { why_not = "negative solution seq"; return false; }
        chunks.push_back({seq, sols[1]});
    }

    if (chunks.empty()) return false; // nothing here; no why_not -- not a malformation

    // Require seq = 0..N-1: exactly N chunks, each seq in range and unique. N distinct
    // values in [0, N) with no duplicate is precisely the set {0..N-1} (contiguous).
    const size_t n = chunks.size();
    std::vector<const std::vector<unsigned char>*> by_seq(n, nullptr);
    for (const Chunk& c : chunks) {
        if (c.seq >= static_cast<int64_t>(n)) { why_not = "solution seq out of range (expected 0..N-1)"; return false; }
        if (by_seq[c.seq]) { why_not = "duplicate solution seq"; return false; }
        by_seq[c.seq] = &c.bytes;
    }

    out.found = true;
    // seq=0 is the payout scriptPubKey; seq=1..N-1 concatenated is the solution.
    out.payout = *by_seq[0];
    for (size_t i = 1; i < n; ++i) {
        out.bytes.insert(out.bytes.end(), by_seq[i]->begin(), by_seq[i]->end());
    }
    return true;
}

} // namespace

void ExtractBlockSolution(const CBlock& block, BlockSolution& out, std::string& why_not)
{
    out = BlockSolution{};
    why_not.clear();

    for (uint32_t ti = 0; ti < block.vtx.size(); ++ti) {
        if (!HasSolutionOutput(*block.vtx[ti])) continue;
        // The FIRST solution-bearing tx is the block's source, full stop. Whether its set
        // turns out to be well-formed or not, no later tx is consulted: that is what keeps
        // a block's verification cost at a single verify() run, and what stops a rival tx
        // from spoiling an honest one (doc sec 2.1quater).
        //
        // HasSolutionOutput only matches the two-byte prefix, so a tx can pass it and
        // still hold no output Solver() accepts as SOLUTION. That is not this block's
        // source -- it carries no solution data at all -- so the scan continues past it.
        BlockSolution parsed;
        if (ExtractFromTx(*block.vtx[ti], parsed, why_not)) {
            parsed.source_tx_index = ti;
            out = std::move(parsed);
            return;
        }
        if (!why_not.empty()) return; // malformed: out.found stays false (sec 7 step 3)
    }
}

void ExtractTxSolution(const CTransaction& tx, BlockSolution& out, std::string& why_not)
{
    out = BlockSolution{};
    why_not.clear();
    BlockSolution parsed;
    if (ExtractFromTx(tx, parsed, why_not)) out = std::move(parsed);
}

bool HasSolutionOutput(const CTransaction& tx)
{
    for (const CTxOut& o : tx.vout) {
        if (o.scriptPubKey.size() >= 2 && o.scriptPubKey[0] == OP_RETURN
            && o.scriptPubKey[1] == OP_SOLUTION) {
            return true;
        }
    }
    return false;
}

} // namespace dynamicalgo
