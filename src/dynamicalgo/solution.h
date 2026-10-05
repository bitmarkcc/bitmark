// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_SOLUTION_H
#define BITCOIN_DYNAMICALGO_SOLUTION_H

#include <cstdint>
#include <string>
#include <vector>

class CBlock;
class CTransaction;

// Dynamic-algo solution assembly (doc/dynamic-algo-mining.md sec 2.1, 2.2 and sec 7
// step 3). A block's solution is carried by a set of self-marking outputs
//     OP_RETURN OP_SOLUTION <seq> <chunk>
// (TxoutType::SOLUTION), all in a SINGLE source transaction -- either the coinbase
// (sec 2.2) or one dedicated non-coinbase solution tx (sec 2.1), never mixed across
// txs. The verifier collects every such output in the block and requires seq = 0..N-1
// (contiguous and unique). By the ABI (sec 2.1):
//   * the seq = 0 chunk IS the payout scriptPubKey (the dynamic miner's payment
//     target, bound into the solution's seed), and
//   * the seq = 1..N-1 chunks concatenated (in seq order) are the solution bytes fed
//     to verify().
// A block with no OP_SOLUTION outputs simply has no solution (found == false).
//
// No dynamic-algo-specific size cap is imposed: the assembled solution is already
// bounded by the block weight limit (a solution tx is an ordinary tx), and the cost
// of running verify() on it is bounded by gas (sec 8.6). A per-tx RELAY cap would be
// a policy concern for p2p relay of solution txs (sec 2.1), not a consensus one.

namespace dynamicalgo {

struct BlockSolution {
    bool found{false};                 //!< at least one OP_SOLUTION output was present
    uint32_t source_tx_index{0};       //!< index in block.vtx of the single source tx (0 == coinbase)
    std::vector<unsigned char> payout; //!< seq=0 chunk: the payout scriptPubKey (empty if !found)
    std::vector<unsigned char> bytes;  //!< seq=1..N-1 concatenated: the solution fed to verify()
};

//! Scan a block for its OP_SOLUTION outputs and split them into the payout (seq=0) and
//! the assembled solution bytes (seq=1..N-1). Returns false and sets `error` if the
//! outputs are malformed as a set: split across more than one tx, or a non-contiguous /
//! duplicated seq. Returns true with out.found == false when there are none.
bool ExtractBlockSolution(const CBlock& block, BlockSolution& out, std::string& error);

//! Cheap test for "this transaction carries at least one OP_SOLUTION output", for callers
//! that must classify every transaction they see rather than parse a solution. Matches the
//! two-byte OP_RETURN OP_SOLUTION prefix directly instead of running Solver() per output:
//! a hit is rare, and the full parse above is only worth paying for once a tx is known to
//! carry one. A tx this returns true for may still be malformed as a solution.
bool HasSolutionOutput(const CTransaction& tx);

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_SOLUTION_H
