// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/solution.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>

#include <optional>

namespace dynamicalgo {

bool ExtractBlockSolution(const CBlock& block, BlockSolution& out, std::string& error)
{
    out = BlockSolution{};

    struct Chunk { int64_t seq; std::vector<unsigned char> bytes; };
    std::vector<Chunk> chunks;
    std::optional<uint32_t> src; // index of the single tx that carries the solution

    for (uint32_t ti = 0; ti < block.vtx.size(); ++ti) {
        for (const CTxOut& o : block.vtx[ti]->vout) {
            std::vector<std::vector<unsigned char>> sols;
            if (Solver(o.scriptPubKey, sols) != TxoutType::SOLUTION) continue;
            // MatchSolution guarantees sols == [seq, chunk]. All solution outputs in a
            // block must live in one source tx (coinbase or the solution tx), not mixed.
            if (src && *src != ti) { error = "solution outputs split across multiple txs"; return false; }
            src = ti;
            int64_t seq;
            try {
                seq = CScriptNum(sols[0], /*fRequireMinimal=*/true, /*nMaxNumSize=*/4).GetInt64();
            } catch (const scriptnum_error&) {
                error = "solution seq is not a valid minimal number";
                return false;
            }
            if (seq < 0) { error = "negative solution seq"; return false; }
            chunks.push_back({seq, sols[1]});
        }
    }

    if (chunks.empty()) { out.found = false; return true; } // block carries no solution

    // Require seq = 0..N-1: exactly N chunks, each seq in range and unique. N distinct
    // values in [0, N) with no duplicate is precisely the set {0..N-1} (contiguous).
    const size_t n = chunks.size();
    std::vector<const std::vector<unsigned char>*> by_seq(n, nullptr);
    for (const Chunk& c : chunks) {
        if (c.seq >= static_cast<int64_t>(n)) { error = "solution seq out of range (expected 0..N-1)"; return false; }
        if (by_seq[c.seq]) { error = "duplicate solution seq"; return false; }
        by_seq[c.seq] = &c.bytes;
    }

    out.found = true;
    out.source_tx_index = *src;
    // seq=0 is the payout scriptPubKey; seq=1..N-1 concatenated is the solution.
    out.payout = *by_seq[0];
    for (size_t i = 1; i < n; ++i) {
        out.bytes.insert(out.bytes.end(), by_seq[i]->begin(), by_seq[i]->end());
    }
    return true;
}

} // namespace dynamicalgo
