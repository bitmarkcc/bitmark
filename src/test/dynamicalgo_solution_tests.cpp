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
    std::string err;
    BOOST_CHECK(dynamicalgo::ExtractBlockSolution(b, sol, err));
    BOOST_CHECK(!sol.found);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(payout_and_solution_split)
{
    const valtype payout{0x76, 0xa9, 0x14, 0xde, 0xad}; // stand-in scriptPubKey
    const valtype c1{0x11, 0x22};
    const valtype c2{0x33};
    // seq=0 payout, seq=1..2 the solution, in a single non-coinbase tx.
    CBlock b = BlockWith({TxWith({SolOut(0, payout), SolOut(1, c1), SolOut(2, c2)})});
    dynamicalgo::BlockSolution sol;
    std::string err;
    BOOST_CHECK(dynamicalgo::ExtractBlockSolution(b, sol, err));
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
    std::string err;
    BOOST_CHECK(dynamicalgo::ExtractBlockSolution(b, sol, err));
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
    std::string err;
    BOOST_CHECK(dynamicalgo::ExtractBlockSolution(b, sol, err));
    BOOST_CHECK(sol.found);
    BOOST_CHECK_EQUAL(sol.source_tx_index, 0u);
}

BOOST_AUTO_TEST_CASE(duplicate_seq_rejected)
{
    CBlock b = BlockWith({TxWith({SolOut(0, {0xaa}), SolOut(1, {0x01}), SolOut(1, {0x02})})});
    dynamicalgo::BlockSolution sol;
    std::string err;
    BOOST_CHECK(!dynamicalgo::ExtractBlockSolution(b, sol, err));
    BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_CASE(noncontiguous_seq_rejected)
{
    // seq {0, 2}: two chunks but a gap -> seq 2 is out of range [0,2).
    CBlock b = BlockWith({TxWith({SolOut(0, {0xaa}), SolOut(2, {0x02})})});
    dynamicalgo::BlockSolution sol;
    std::string err;
    BOOST_CHECK(!dynamicalgo::ExtractBlockSolution(b, sol, err));
    BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_CASE(split_across_txs_rejected)
{
    // Solution outputs in two different txs -> invalid (must be single-source).
    CBlock b = BlockWith({TxWith({SolOut(0, {0xaa})}), TxWith({SolOut(1, {0x01})})});
    dynamicalgo::BlockSolution sol;
    std::string err;
    BOOST_CHECK(!dynamicalgo::ExtractBlockSolution(b, sol, err));
    BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
