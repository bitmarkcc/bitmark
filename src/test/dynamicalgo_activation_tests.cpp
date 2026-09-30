// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/activation.h>

#include <arith_uint256.h>
#include <dynamicalgo/activationdb.h>
#include <dynamicalgo/algovote.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <set>
#include <vector>

using namespace dynamicalgo;

namespace {

//! Drives the incremental activation algorithm over a synthetic chain: each "block" is
//! just a height, a fee total and a set of vote entries, fed through ComputeConnect and
//! applied to an in-memory store. This is a plain object (not a testing-setup subclass)
//! so one test can run two independent chains side by side.
//!
//! The parameters are scaled down to keep the windows short:
//!
//!   VP = 10, delay = 5  =>  a window [f, f+9] activates at f + 15
//!   year_blocks = 20    =>  the fee sum spans at most 20 blocks
//!
//! At height t the algorithm looks at the window [t-15, t-6] anchored at f = t-15, and
//! the fee sum covers [max(1, t-36), t-16]. Starting the store at height 1, year_blocks
//! therefore reaches VP (10) first at t = 26 -- exactly the activation height of the
//! window anchored at f = 11. The fixtures below build on that alignment.
struct VoteChain {
    ActivationParams params;
    CActivationDB db;
    int32_t height{0};
    std::set<uint256> assemblable;

    explicit VoteChain(const fs::path& path)
        : db{DBParams{.path = path,
                      .cache_bytes = 1 << 16,
                      .memory_only = true, // no directory is created; the path is a label
                      .wipe_data = false}}
    {
        params.voting_period = 10;
        params.activation_delay = 5;
        params.year_blocks = 20;
        params.num_slots = 8;
        params.reorg_margin = 4;
    }

    static uint256 Branch(uint32_t n) { return ArithToUint256(arith_uint256{n + 1000}); }
    static uint256 BlockHash(uint32_t n) { return ArithToUint256(arith_uint256{n}); }

    static CVoteEntry Vote(int slot, const uint256& branch, CAmount fee, CAmount stake)
    {
        return CVoteEntry{static_cast<uint8_t>(slot), branch, VoteTally{fee, stake}};
    }

    //! Connect one block. False means the algorithm refused the state (a desync).
    bool Connect(CAmount fees, const std::vector<CVoteEntry>& votes = {})
    {
        ++height;
        CBlockVotes bv;
        bv.entries = votes;
        CConnectWrite w;
        const auto assembles = [&](const uint256& b) { return assemblable.count(b) > 0; };
        if (!ComputeConnect(db, params, height, fees, bv, BlockHash(height), assembles, w)) return false;
        return db.ApplyConnect(w);
    }

    //! Connect `n` blocks that carry fees but no votes.
    bool ConnectPlain(int n, CAmount fees = 1000)
    {
        for (int i = 0; i < n; ++i) {
            if (!Connect(fees)) return false;
        }
        return true;
    }

    //! Connect `n` blocks each voting `fee`/`stake` for `branch` in `slot`.
    bool ConnectVoting(int n, int slot, const uint256& branch, CAmount fee, CAmount stake)
    {
        for (int i = 0; i < n; ++i) {
            if (!Connect(1000, {Vote(slot, branch, fee, stake)})) return false;
        }
        return true;
    }

    bool Disconnect()
    {
        CDisconnectWrite w;
        if (!ComputeDisconnect(db, params, height, BlockHash(height - 1), w)) return false;
        if (!db.ApplyDisconnect(w)) return false;
        --height;
        return true;
    }

    std::optional<uint256> Active(int slot) const
    {
        CSlotActivation a;
        if (db.ReadSlot(slot, a) && a.IsActive()) return a.branch;
        return std::nullopt;
    }

    int32_t ActivationHeight(int slot) const
    {
        CSlotActivation a;
        return db.ReadSlot(slot, a) ? a.activation_height : 0;
    }

    int32_t StateHeight() const
    {
        CActivationState s;
        return db.ReadState(s) ? s.height : -1;
    }

    //! Heights 1..10 carry fee history only, 11..20 vote for `branch` in slot 0, 21..25 are
    //! plain. Ends at height 25, one short of that window's activation height (26).
    bool RunUpToActivation(const uint256& branch, CAmount fee, CAmount stake)
    {
        return ConnectPlain(10) && ConnectVoting(10, 0, branch, fee, stake) && ConnectPlain(5);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(dynamicalgo_activation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(activates_after_window_and_delay)
{
    VoteChain c{m_args.GetDataDirBase() / "algoact"};
    const uint256 b{VoteChain::Branch(1)};
    c.assemblable.insert(b);
    BOOST_REQUIRE(c.RunUpToActivation(b, /*fee=*/100, /*stake=*/50));

    // The window is complete, but its activation height has not arrived yet.
    BOOST_CHECK_EQUAL(c.height, 25);
    BOOST_CHECK(!c.Active(0));

    // f + VP + delay == 11 + 10 + 5 == 26.
    BOOST_REQUIRE(c.Connect(1000));
    BOOST_CHECK_EQUAL(c.height, 26);
    BOOST_CHECK(c.Active(0) == b);
    BOOST_CHECK_EQUAL(c.ActivationHeight(0), 26);
    BOOST_CHECK_EQUAL(c.StateHeight(), 26);

    // Only the voted slot moved.
    BOOST_CHECK(!c.Active(1));

    // And it stays active as the window slides past it.
    BOOST_REQUIRE(c.ConnectPlain(10));
    BOOST_CHECK(c.Active(0) == b);
    BOOST_CHECK_EQUAL(c.ActivationHeight(0), 26);
}

BOOST_AUTO_TEST_CASE(fee_floor_blocks_weak_turnout)
{
    // Per-block fees of 1000 over the 10 recorded blocks give an average of 1000, so the
    // floor is 0.0625 * 1000 * VP(10) == 625.
    const uint256 b{VoteChain::Branch(2)};

    // A fee-weight total of 10 * 50 == 500 is below the floor.
    VoteChain weak{m_args.GetDataDirBase() / "algoact-weak"};
    weak.assemblable.insert(b);
    BOOST_REQUIRE(weak.RunUpToActivation(b, /*fee=*/50, /*stake=*/50));
    BOOST_REQUIRE(weak.Connect(1000));
    BOOST_CHECK_EQUAL(weak.height, 26);
    BOOST_CHECK(!weak.Active(0));

    // 10 * 100 == 1000 clears it, and the same window then activates.
    VoteChain ok{m_args.GetDataDirBase() / "algoact-ok"};
    ok.assemblable.insert(b);
    BOOST_REQUIRE(ok.RunUpToActivation(b, /*fee=*/100, /*stake=*/50));
    BOOST_REQUIRE(ok.Connect(1000));
    BOOST_CHECK(ok.Active(0) == b);
}

BOOST_AUTO_TEST_CASE(stake_is_required)
{
    // Fee votes only: the window's stake total is zero, so no branch can hold 75% of it.
    VoteChain c{m_args.GetDataDirBase() / "algoact"};
    const uint256 b{VoteChain::Branch(3)};
    c.assemblable.insert(b);
    BOOST_REQUIRE(c.RunUpToActivation(b, /*fee=*/100, /*stake=*/0));
    BOOST_REQUIRE(c.Connect(1000));
    BOOST_CHECK(!c.Active(0));
}

BOOST_AUTO_TEST_CASE(anchor_must_vote_for_the_winner)
{
    // Blocks 12..20 carry the winning branch; the window's FIRST block (11 == f, the
    // anchor) votes for a different one. The window has a 75% winner, but it is not
    // anchored to that winner, so nothing activates.
    VoteChain c{m_args.GetDataDirBase() / "algoact"};
    const uint256 winner{VoteChain::Branch(4)}, other{VoteChain::Branch(5)};
    c.assemblable.insert(winner);
    c.assemblable.insert(other);
    BOOST_REQUIRE(c.ConnectPlain(10));                                    // 1..10
    BOOST_REQUIRE(c.Connect(1000, {VoteChain::Vote(0, other, 10, 5)}));   // 11 == f
    BOOST_REQUIRE(c.ConnectVoting(9, 0, winner, 100, 50));                // 12..20
    BOOST_REQUIRE(c.ConnectPlain(5));                                     // 21..25
    BOOST_REQUIRE(c.Connect(1000));                                       // 26
    BOOST_CHECK(!c.Active(0));
}

BOOST_AUTO_TEST_CASE(unassemblable_winner_voids_activation)
{
    const uint256 b{VoteChain::Branch(6)};

    // A winning, anchored window whose branch cannot be assembled: the activation is void
    // and the slot keeps its previous algo (here: none).
    VoteChain voided{m_args.GetDataDirBase() / "algoact-void"};
    // `b` deliberately NOT added to `assemblable`
    BOOST_REQUIRE(voided.RunUpToActivation(b, /*fee=*/100, /*stake=*/50));
    BOOST_REQUIRE(voided.Connect(1000));
    BOOST_CHECK(!voided.Active(0));

    // The identical chain activates once the branch does assemble.
    VoteChain ok{m_args.GetDataDirBase() / "algoact-ok"};
    ok.assemblable.insert(b);
    BOOST_REQUIRE(ok.RunUpToActivation(b, /*fee=*/100, /*stake=*/50));
    BOOST_REQUIRE(ok.Connect(1000));
    BOOST_CHECK(ok.Active(0) == b);
}

BOOST_AUTO_TEST_CASE(min_fee_history_guard)
{
    // A window anchored at f = 1 would otherwise activate at height 16, but by then no fee
    // history has entered the sum at all (year_blocks == 0 < VP), so the guard defers it
    // rather than judge the floor against a block or two of fees.
    VoteChain c{m_args.GetDataDirBase() / "algoact"};
    const uint256 b{VoteChain::Branch(7)};
    c.assemblable.insert(b);
    BOOST_REQUIRE(c.ConnectVoting(10, 0, b, 100, 50)); // 1..10 == the window [1,10]
    BOOST_REQUIRE(c.ConnectPlain(6));                  // 11..16 (16 == 1 + VP + delay)
    BOOST_CHECK_EQUAL(c.height, 16);
    BOOST_CHECK(!c.Active(0));
}

BOOST_AUTO_TEST_CASE(later_window_supersedes)
{
    // Slot 0 activates B from the window [11,20], then C from [21,30]. In between, the
    // sliding window is a mix of the two and no branch holds 75%, so nothing changes; the
    // windows anchored at 12..20 do re-elect B, which is already active and so is a no-op.
    VoteChain c{m_args.GetDataDirBase() / "algoact"};
    const uint256 b{VoteChain::Branch(8)}, d{VoteChain::Branch(9)};
    c.assemblable.insert(b);
    c.assemblable.insert(d);
    BOOST_REQUIRE(c.ConnectPlain(10));                    // 1..10
    BOOST_REQUIRE(c.ConnectVoting(10, 0, b, 100, 50));    // 11..20
    BOOST_REQUIRE(c.ConnectVoting(10, 0, d, 100, 50));    // 21..30
    BOOST_REQUIRE(c.ConnectPlain(5));                     // 31..35
    BOOST_CHECK(c.Active(0) == b);                        // B landed at 26
    BOOST_CHECK_EQUAL(c.ActivationHeight(0), 26);

    BOOST_REQUIRE(c.Connect(1000));                       // 36 == 21 + VP + delay
    BOOST_CHECK(c.Active(0) == d);
    BOOST_CHECK_EQUAL(c.ActivationHeight(0), 36);
}

BOOST_AUTO_TEST_CASE(disconnect_restores_prior_activation)
{
    VoteChain c{m_args.GetDataDirBase() / "algoact"};
    const uint256 b{VoteChain::Branch(10)};
    c.assemblable.insert(b);
    BOOST_REQUIRE(c.RunUpToActivation(b, /*fee=*/100, /*stake=*/50));
    BOOST_REQUIRE(c.Connect(1000)); // 26 activates
    BOOST_CHECK(c.Active(0) == b);

    // Disconnecting the activating block returns the slot to primitive-only and retreats
    // the bookkeeping one height.
    BOOST_REQUIRE(c.Disconnect());
    BOOST_CHECK_EQUAL(c.height, 25);
    BOOST_CHECK_EQUAL(c.StateHeight(), 25);
    BOOST_CHECK(!c.Active(0));

    // Reconnecting reaches the same activation again: the slide is symmetric.
    BOOST_REQUIRE(c.Connect(1000));
    BOOST_CHECK_EQUAL(c.StateHeight(), 26);
    BOOST_CHECK(c.Active(0) == b);
    BOOST_CHECK_EQUAL(c.ActivationHeight(0), 26);
}

BOOST_AUTO_TEST_CASE(disconnect_rewinds_a_whole_window)
{
    // Unwind past the window's first block and replay it, to exercise the window slide in
    // both directions rather than only the activating block.
    VoteChain c{m_args.GetDataDirBase() / "algoact"};
    const uint256 b{VoteChain::Branch(11)};
    c.assemblable.insert(b);
    BOOST_REQUIRE(c.RunUpToActivation(b, /*fee=*/100, /*stake=*/50));
    BOOST_REQUIRE(c.Connect(1000)); // 26 activates
    BOOST_CHECK(c.Active(0) == b);

    for (int i = 0; i < 16; ++i) BOOST_REQUIRE(c.Disconnect()); // back to height 10
    BOOST_CHECK_EQUAL(c.height, 10);
    BOOST_CHECK_EQUAL(c.StateHeight(), 10);
    BOOST_CHECK(!c.Active(0));

    BOOST_REQUIRE(c.ConnectVoting(10, 0, b, 100, 50)); // 11..20
    BOOST_REQUIRE(c.ConnectPlain(6));                  // 21..26
    BOOST_CHECK_EQUAL(c.StateHeight(), 26);
    BOOST_CHECK(c.Active(0) == b);
    BOOST_CHECK_EQUAL(c.ActivationHeight(0), 26);
}

BOOST_AUTO_TEST_CASE(compute_rejects_a_desynced_store)
{
    VoteChain c{m_args.GetDataDirBase() / "algoact"};
    BOOST_REQUIRE(c.ConnectPlain(3));

    // A connect that is not the store's height + 1 must be refused rather than silently
    // corrupting the running sums, and likewise a disconnect of a height the store does
    // not currently reflect.
    const auto assembles = [](const uint256&) { return true; };
    CConnectWrite cw;
    BOOST_CHECK(!ComputeConnect(c.db, c.params, /*height=*/99, 1000, CBlockVotes{},
                                VoteChain::BlockHash(99), assembles, cw));
    BOOST_CHECK(!ComputeConnect(c.db, c.params, /*height=*/3, 1000, CBlockVotes{},
                                VoteChain::BlockHash(3), assembles, cw));
    CDisconnectWrite dw;
    BOOST_CHECK(!ComputeDisconnect(c.db, c.params, /*height=*/2, VoteChain::BlockHash(1), dw));
}

BOOST_AUTO_TEST_SUITE_END()
