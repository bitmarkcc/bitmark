// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pushcodedb.h>

#include <dbwrapper.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pushcodedb_tests, BasicTestingSetup)

// Content identity: deterministic and content-sensitive.
BOOST_AUTO_TEST_CASE(content_hash)
{
    const CScript a = CScript() << std::vector<unsigned char>{1, 2, 3} << OP_PUSHCODE;
    const CScript b = CScript() << std::vector<unsigned char>{1, 2, 4} << OP_PUSHCODE;
    BOOST_CHECK(PushCodeHash(a) == PushCodeHash(a));
    BOOST_CHECK(PushCodeHash(a) != PushCodeHash(b));
}

// Entry round-trip, content dedup / refcount, and best-block tracking.
BOOST_AUTO_TEST_CASE(entry_refcount_bestblock)
{
    CCodeDB db{DBParams{.path = m_args.GetDataDirBase() / "codedb",
                        .cache_bytes = 1 << 20,
                        .memory_only = true}};

    const uint256 H = uint256::ONE;
    const uint256 blk1 = uint256S("0x01");
    const uint256 blk2 = uint256S("0x02");

    CCodeEntry e;
    e.op = PUSHCODE_OP_INSERT;
    e.has_parent = false;
    e.height = 730;
    e.refcount = 1;

    BOOST_CHECK(!db.HaveEntry(H));

    // apply a block with one entry -> exists, readable, best block set
    BOOST_CHECK(db.ApplyBlock({{H, e}}, blk1));
    BOOST_CHECK(db.HaveEntry(H));
    CCodeEntry got;
    BOOST_CHECK(db.ReadEntry(H, got));
    BOOST_CHECK_EQUAL(got.height, 730);
    BOOST_CHECK_EQUAL(got.refcount, 1U);
    uint256 best;
    BOOST_CHECK(db.ReadBestBlock(best));
    BOOST_CHECK(best == blk1);

    // dedup across blocks: same H again -> refcount 2, best block advances
    BOOST_CHECK(db.ApplyBlock({{H, e}}, blk2));
    BOOST_CHECK(db.ReadEntry(H, got));
    BOOST_CHECK_EQUAL(got.refcount, 2U);
    BOOST_CHECK(db.ReadBestBlock(best));
    BOOST_CHECK(best == blk2);

    // undo once -> refcount 1, still present
    BOOST_CHECK(db.UndoBlock({H}, blk1));
    BOOST_CHECK(db.HaveEntry(H));
    BOOST_CHECK(db.ReadEntry(H, got));
    BOOST_CHECK_EQUAL(got.refcount, 1U);

    // undo again -> erased
    BOOST_CHECK(db.UndoBlock({H}, uint256S("0x00")));
    BOOST_CHECK(!db.HaveEntry(H));
    BOOST_CHECK(!db.ReadEntry(H, got));

    // intra-block dedup: one block adding the same H twice -> refcount 2
    BOOST_CHECK(db.ApplyBlock({{H, e}, {H, e}}, blk1));
    BOOST_CHECK(db.ReadEntry(H, got));
    BOOST_CHECK_EQUAL(got.refcount, 2U);
    BOOST_CHECK(db.UndoBlock({H, H}, uint256S("0x00")));
    BOOST_CHECK(!db.HaveEntry(H));
}

BOOST_AUTO_TEST_SUITE_END()
