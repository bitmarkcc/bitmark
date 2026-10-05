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
// (TxoutType::SOLUTION) in ONE transaction: the FIRST transaction in block order that
// has any -- the coinbase (sec 2.2) or a dedicated solution tx (sec 2.1). Within it the
// outputs must run seq = 0..N-1 (contiguous and unique). By the ABI (sec 2.1):
//   * the seq = 0 chunk IS the payout scriptPubKey (the dynamic miner's payment
//     target, bound into the solution's seed), and
//   * the seq = 1..N-1 chunks concatenated (in seq order) are the solution bytes fed
//     to verify().
//
// EVERY LATER solution-bearing tx is ignored outright -- not parsed, not verified, not
// an error. Two reasons, and they are the heart of sec 2.1quater:
//   * Cost. Deciding WHICH of several rival solutions is the valid one would mean a
//     verifier run each, and one run can consume the whole per-block gas budget (~38 s,
//     sec 8.6). A solution tx needs only an input and one OP_RETURN output, so a 1 MB
//     block could hold thousands of them. Scoping to one tx holds a block's cost at one
//     run no matter what it contains.
//   * Safety. Anyone can relay a solution tx, so if a rival could spoil the block the
//     mempool would be a minefield for any miner doing ordinary feerate selection. The
//     miner controls block order, so it decides which one counts.
//
// Hence this CANNOT FAIL, and says so in its signature: a block whose solution data is
// malformed simply HAS NO SOLUTION and takes the no-solution reward branch. No solution
// data can make a block invalid (sec 7 steps 3-4), and that property is worth having in
// the type rather than in a bool a caller might mishandle.
//
// No dynamic-algo-specific size cap is imposed: the assembled solution is already
// bounded by the block weight limit (a solution tx is an ordinary tx), and the cost
// of running verify() on it is bounded by gas (sec 8.6). A per-tx RELAY cap would be
// a policy concern for p2p relay of solution txs (sec 2.1), not a consensus one.

namespace dynamicalgo {

struct BlockSolution {
    bool found{false};                 //!< a well-formed solution was present
    uint32_t source_tx_index{0};       //!< index in block.vtx of the source tx (0 == coinbase)
    std::vector<unsigned char> payout; //!< seq=0 chunk: the payout scriptPubKey (empty if !found)
    std::vector<unsigned char> bytes;  //!< seq=1..N-1 concatenated: the solution fed to verify()
};

//! Read the block's solution: the payout (seq=0) and the assembled solution bytes
//! (seq=1..N-1) of the first solution-bearing transaction. `out.found` is false when the
//! block carries none, or when that transaction's set is malformed -- in which case
//! `why_not` explains it, for logging only. Cannot fail; see the note above.
void ExtractBlockSolution(const CBlock& block, BlockSolution& out, std::string& why_not);

//! The same over ONE transaction, for a candidate solution tx that is not in a block yet
//! (the miner's selection path, doc sec 2.1quater). Equivalent to running the above on a
//! block whose first solution-bearing tx is this one -- which is the block the miner goes
//! on to build -- so the two can never disagree about what verify() is fed.
//! `source_tx_index` is left 0 and is meaningless here.
void ExtractTxSolution(const CTransaction& tx, BlockSolution& out, std::string& why_not);

//! Cheap test for "this transaction carries at least one OP_SOLUTION output", for callers
//! that must classify every transaction they see rather than parse a solution. Matches the
//! two-byte OP_RETURN OP_SOLUTION prefix directly instead of running Solver() per output:
//! a hit is rare, and the full parse above is only worth paying for once a tx is known to
//! carry one. A tx this returns true for may still be malformed as a solution.
bool HasSolutionOutput(const CTransaction& tx);

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_SOLUTION_H
