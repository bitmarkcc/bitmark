// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/solution.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {
using valtype = std::vector<unsigned char>;

// One OP_RETURN OP_SOLUTION <seq> <chunk> output (TxoutType::SOLUTION).
CTxOut SolOut(int seq, const valtype& chunk)
{
    CScript s;
    s << OP_RETURN << OP_SOLUTION << CScriptNum(seq) << chunk;
    return CTxOut(0, s);
}

CTransactionRef TxWith(std::vector<CTxOut> vout)
{
    CMutableTransaction mtx;
    mtx.vout = std::move(vout);
    return MakeTransactionRef(std::move(mtx));
}

// A block whose coinbase (vtx[0]) is a dummy and whose remaining txs are as given.
CBlock BlockWith(std::vector<CTransactionRef> non_coinbase)
{
    CBlock b;
    b.vtx.push_back(TxWith({CTxOut(50, CScript() << OP_TRUE)})); // dummy coinbase
    for (auto& t : non_coinbase) b.vtx.push_back(std::move(t));
    return b;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(dynamicalgo_solution_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(no_solution)
{
    CBlock b = BlockWith({TxWith({CTxOut(1, CScript() << OP_TRUE)})});
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(!sol.found);
    BOOST_CHECK(why_not.empty()); // nothing there is not a malformation
}

BOOST_AUTO_TEST_CASE(payout_and_solution_split)
{
    const valtype payout{0x76, 0xa9, 0x14, 0xde, 0xad}; // stand-in scriptPubKey
    const valtype c1{0x11, 0x22};
    const valtype c2{0x33};
    // seq=0 payout, seq=1..2 the solution, in a single non-coinbase tx.
    CBlock b = BlockWith({TxWith({SolOut(0, payout), SolOut(1, c1), SolOut(2, c2)})});
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(sol.found);
    BOOST_CHECK_EQUAL(sol.source_tx_index, 1u); // the solution tx
    BOOST_CHECK(sol.payout == payout);
    const valtype expect{0x11, 0x22, 0x33}; // c1 || c2 in seq order
    BOOST_CHECK(sol.bytes == expect);
}

BOOST_AUTO_TEST_CASE(out_of_order_seq_ok)
{
    // Chunks need not appear in seq order; assembly reorders by seq.
    const valtype payout{0xaa};
    CBlock b = BlockWith({TxWith({SolOut(2, {0x03}), SolOut(0, payout), SolOut(1, {0x02})})});
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(sol.found);
    BOOST_CHECK(sol.payout == payout);
    const valtype expect{0x02, 0x03};
    BOOST_CHECK(sol.bytes == expect);
}

BOOST_AUTO_TEST_CASE(coinbase_source)
{
    // Solution carried in the coinbase itself (source_tx_index == 0).
    CBlock b;
    b.vtx.push_back(TxWith({CTxOut(50, CScript() << OP_TRUE), SolOut(0, {0xbb}), SolOut(1, {0x01})}));
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(sol.found);
    BOOST_CHECK_EQUAL(sol.source_tx_index, 0u);
}

// ---- malformed data means "no solution", never an error (doc sec 7 step 3) ----------

BOOST_AUTO_TEST_CASE(duplicate_seq_yields_no_solution)
{
    CBlock b = BlockWith({TxWith({SolOut(0, {0xaa}), SolOut(1, {0x01}), SolOut(1, {0x02})})});
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(!sol.found);
    BOOST_CHECK(!why_not.empty()); // explained, but only for the log
}

BOOST_AUTO_TEST_CASE(noncontiguous_seq_yields_no_solution)
{
    // seq {0, 2}: two chunks but a gap -> seq 2 is out of range [0,2).
    CBlock b = BlockWith({TxWith({SolOut(0, {0xaa}), SolOut(2, {0x02})})});
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(!sol.found);
    BOOST_CHECK(!why_not.empty());
}

// ---- the first solution-bearing tx is the source, full stop (doc sec 2.1quater) -----

BOOST_AUTO_TEST_CASE(first_solution_tx_wins_later_ignored)
{
    // Two complete, individually well-formed solutions. The earlier tx is the block's,
    // and the later one is not consulted at all -- it is a rival, not a continuation.
    const valtype mine{0xaa};
    const valtype theirs{0xbb};
    CBlock b = BlockWith({TxWith({SolOut(0, mine), SolOut(1, {0x01})}),
                          TxWith({SolOut(0, theirs), SolOut(1, {0x02})})});
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(sol.found);
    BOOST_CHECK_EQUAL(sol.source_tx_index, 1u);
    BOOST_CHECK(sol.payout == mine);
    const valtype expect{0x01};
    BOOST_CHECK(sol.bytes == expect);
    BOOST_CHECK(why_not.empty());
}

BOOST_AUTO_TEST_CASE(chunks_are_not_gathered_across_txs)
{
    // Half a solution in each of two txs. Under the old whole-block scan these assembled
    // into seq 0..1; now the first tx alone is the source, so its lone seq=0 chunk IS the
    // solution -- payout with zero solution bytes -- and the second tx is ignored.
    CBlock b = BlockWith({TxWith({SolOut(0, {0xaa})}), TxWith({SolOut(1, {0x01})})});
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(sol.found);
    BOOST_CHECK_EQUAL(sol.source_tx_index, 1u);
    BOOST_CHECK(sol.payout == valtype{0xaa});
    BOOST_CHECK(sol.bytes.empty());
}

BOOST_AUTO_TEST_CASE(malformed_first_tx_does_not_fall_through_to_the_next)
{
    // THE case a rival would exploit if the scan continued: a malformed set in the first
    // solution-bearing tx must leave the block with no solution, NOT promote the next tx.
    // Otherwise placing a broken tx first would be a way to pick which solution counts.
    CBlock b = BlockWith({TxWith({SolOut(0, {0xaa}), SolOut(2, {0x02})}),       // gap
                          TxWith({SolOut(0, {0xbb}), SolOut(1, {0x01})})});     // fine
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(!sol.found);
    BOOST_CHECK(!why_not.empty());
}

BOOST_AUTO_TEST_CASE(prefix_lookalike_is_skipped_not_treated_as_the_source)
{
    // HasSolutionOutput only matches the two-byte OP_RETURN OP_SOLUTION prefix, so a tx
    // can pass it while holding no output Solver() accepts (here: no seq/chunk pushes).
    // That tx carries no solution data, so the scan must continue past it rather than
    // conclude the block has none -- otherwise anyone could null a block's solution with
    // a 2-byte output.
    CBlock b = BlockWith({TxWith({CTxOut(0, CScript() << OP_RETURN << OP_SOLUTION)}),
                          TxWith({SolOut(0, {0xbb}), SolOut(1, {0x01})})});
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractBlockSolution(b, sol, why_not);
    BOOST_CHECK(sol.found);
    BOOST_CHECK_EQUAL(sol.source_tx_index, 2u);
    BOOST_CHECK(sol.payout == valtype{0xbb});
}

// ---- the per-tx form the miner uses on a mempool candidate --------------------------

BOOST_AUTO_TEST_CASE(tx_form_matches_the_block_form)
{
    const valtype payout{0xaa};
    CTransactionRef tx = TxWith({SolOut(0, payout), SolOut(1, {0x01}), SolOut(2, {0x02})});

    dynamicalgo::BlockSolution from_tx;
    std::string why_not;
    dynamicalgo::ExtractTxSolution(*tx, from_tx, why_not);
    BOOST_CHECK(from_tx.found);
    BOOST_CHECK(why_not.empty());

    // Identical to what the block containing it yields -- the property the miner relies
    // on when it prices a candidate before assembling the block.
    CBlock b = BlockWith({tx});
    dynamicalgo::BlockSolution from_block;
    dynamicalgo::ExtractBlockSolution(b, from_block, why_not);
    BOOST_CHECK(from_block.found);
    BOOST_CHECK(from_block.payout == from_tx.payout);
    BOOST_CHECK(from_block.bytes == from_tx.bytes);
}

BOOST_AUTO_TEST_CASE(tx_form_reports_malformed_without_failing)
{
    CTransactionRef tx = TxWith({SolOut(0, {0xaa}), SolOut(1, {0x01}), SolOut(1, {0x02})});
    dynamicalgo::BlockSolution sol;
    std::string why_not;
    dynamicalgo::ExtractTxSolution(*tx, sol, why_not);
    BOOST_CHECK(!sol.found);
    BOOST_CHECK(!why_not.empty());
}

BOOST_AUTO_TEST_SUITE_END()
