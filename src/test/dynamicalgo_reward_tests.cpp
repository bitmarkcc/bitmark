// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/reward.h>

#include <consensus/amount.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

using namespace dynamicalgo;

namespace {
constexpr uint64_t Q = uint64_t{1} << 32; // Q32 one
constexpr uint32_t HALF = uint32_t{1} << 31; // 0.5 in Q32
} // namespace

BOOST_FIXTURE_TEST_SUITE(dynamicalgo_reward_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fp_mul_basics)
{
    // Exact halves and identities.
    BOOST_CHECK_EQUAL(fp_mul(100, HALF), 50);
    BOOST_CHECK_EQUAL(fp_mul(100, Q), 100);      // q == 2^32 acts as *1
    BOOST_CHECK_EQUAL(fp_mul(100, 0), 0);
    BOOST_CHECK_EQUAL(fp_mul(0, HALF), 0);

    // Floors downward: 3 * 0.5 = 1.5 -> 1.
    BOOST_CHECK_EQUAL(fp_mul(3, HALF), 1);

    // Never exceeds x for q <= 2^32; q just below 2^32 stays < x by the floor.
    BOOST_CHECK_EQUAL(fp_mul(40, Q - 1), 39);    // floor(40 * (2^32-1)/2^32)

    // Wide intermediate: no overflow near the money ceiling.
    const CAmount big = 21000000LL * COIN; // > 2^50
    BOOST_CHECK_EQUAL(fp_mul(big, HALF), big / 2);
    BOOST_CHECK_EQUAL(fp_mul(big, Q), big);
}

BOOST_AUTO_TEST_CASE(split_valid_solution)
{
    // r = 40 + 10 = 50; alpha = 0.5 -> dyn = 25, prim = 25, full subsidy emitted.
    RewardSplit s = ComputeRewardSplit(/*subsidy=*/40, /*fees=*/10, /*alpha=*/HALF, /*beta=*/HALF, /*valid=*/true);
    BOOST_CHECK_EQUAL(s.required_payout, 25);
    BOOST_CHECK_EQUAL(s.emitted_subsidy, 40);
    BOOST_CHECK_EQUAL(s.max_coinbase_value, 50);
    // dyn + prim == r exactly (prim = max - dyn).
    BOOST_CHECK_EQUAL(s.max_coinbase_value - s.required_payout, 25);

    // alpha = 0: nothing owed to the dynamic miner, but a valid solution still emits S
    // and the coinbase may claim all of r.
    s = ComputeRewardSplit(40, 10, /*alpha=*/0, HALF, true);
    BOOST_CHECK_EQUAL(s.required_payout, 0);
    BOOST_CHECK_EQUAL(s.emitted_subsidy, 40);
    BOOST_CHECK_EQUAL(s.max_coinbase_value, 50);
}

BOOST_AUTO_TEST_CASE(split_no_solution)
{
    // emitted = floor(beta * (1-alpha) * S). alpha=0.5, beta=0.5, S=40 -> 0.25*40 = 10.
    RewardSplit s = ComputeRewardSplit(/*subsidy=*/40, /*fees=*/10, HALF, HALF, /*valid=*/false);
    BOOST_CHECK_EQUAL(s.required_payout, 0);
    BOOST_CHECK_EQUAL(s.emitted_subsidy, 10);
    BOOST_CHECK_EQUAL(s.max_coinbase_value, 20); // emitted + fees

    // Reference whirlpool no-solution split: alpha=0, beta=0.5 -> emit S/2.
    s = ComputeRewardSplit(40, 10, /*alpha=*/0, HALF, false);
    BOOST_CHECK_EQUAL(s.emitted_subsidy, 20);
    BOOST_CHECK_EQUAL(s.max_coinbase_value, 30);

    // Soft-fork safety: emitted subsidy can never exceed S, even at beta ~ 1, alpha = 0.
    s = ComputeRewardSplit(40, 10, /*alpha=*/0, /*beta=*/uint32_t(Q - 1), false);
    BOOST_CHECK(s.emitted_subsidy <= 40);
    BOOST_CHECK_EQUAL(s.emitted_subsidy, 39);
    BOOST_CHECK(s.max_coinbase_value <= 40 + 10);
}

BOOST_AUTO_TEST_CASE(split_negative_subsidy)
{
    // SSF near-peak region: S < 0. A valid solution still splits the fee-funded reward
    // r = S + F, so the dynamic miner gets alpha*r. S=-10, F=50, alpha=0.5 -> r=40, dyn=20.
    RewardSplit s = ComputeRewardSplit(/*subsidy=*/-10, /*fees=*/50, HALF, HALF, /*valid=*/true);
    BOOST_CHECK_EQUAL(s.required_payout, 20);
    BOOST_CHECK_EQUAL(s.max_coinbase_value, 40); // == S + F, the old-node ceiling
    BOOST_CHECK_EQUAL(s.emitted_subsidy, -10);

    // Valid but fees don't cover the shortfall: r = S + F <= 0 -> nothing owed, and the
    // ceiling is negative so ConnectBlock rejects the block (coinbase value >= 0 > r).
    s = ComputeRewardSplit(/*subsidy=*/-40, /*fees=*/10, HALF, HALF, /*valid=*/true);
    BOOST_CHECK_EQUAL(s.required_payout, 0);
    BOOST_CHECK_EQUAL(s.max_coinbase_value, -30);

    // No solution AND S < 0: the subsidy is NOT scaled up toward zero; emit primitive S,
    // so the ceiling is exactly S + F (identical to old nodes) -- soft-fork-safe.
    s = ComputeRewardSplit(/*subsidy=*/-10, /*fees=*/50, HALF, HALF, /*valid=*/false);
    BOOST_CHECK_EQUAL(s.emitted_subsidy, -10);
    BOOST_CHECK_EQUAL(s.max_coinbase_value, 40); // == S + F, not beta*(1-alpha)*S + F > S+F

    // Ceiling never exceeds the old-node ceiling S + F, across a sweep of alpha/beta.
    for (uint64_t a = 0; a <= Q; a += (Q / 8)) {
        for (uint64_t b = 0; b <= Q; b += (Q / 8)) {
            const uint32_t aq = (uint32_t)std::min<uint64_t>(a, Q - 1);
            const uint32_t bq = (uint32_t)std::min<uint64_t>(b, Q - 1);
            for (bool valid : {true, false}) {
                RewardSplit t = ComputeRewardSplit(-10, 50, aq, bq, valid);
                BOOST_CHECK(t.max_coinbase_value <= -10 + 50);
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
