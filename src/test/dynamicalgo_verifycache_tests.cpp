// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/verifycache.h>

#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <set>
#include <vector>

using namespace dynamicalgo;

namespace {

//! A distinguishable 32-byte value.
uint256 H(uint8_t b)
{
    uint256 h;
    h.begin()[0] = b;
    return h;
}

std::vector<unsigned char> B(const std::string& s) { return {s.begin(), s.end()}; }

//! The reference arguments every key test perturbs exactly one field of.
struct Args {
    uint256 branch{H(1)};
    uint8_t algo{3};
    uint256 anchor{H(2)};
    uint32_t nbits{0x1d00ffff};
    std::vector<unsigned char> payout{B("payout")};
    std::vector<unsigned char> solution{B("solution")};

    uint256 Key() const
    {
        return VerifyCache::Key(branch, algo, anchor, nbits, payout, solution);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(dynamicalgo_verifycache_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_covers_every_input)
{
    // Perturbing ANY input must move the key. A field left out of the key would let a hit
    // return the verdict of a different computation -- the one way this cache could
    // change consensus rather than merely speed it up (doc sec 8.9).
    const Args base;
    std::set<uint256> keys{base.Key()};

    Args a;
    a.branch = H(9);
    BOOST_CHECK(keys.insert(a.Key()).second);
    a = base; a.algo = 4;
    BOOST_CHECK(keys.insert(a.Key()).second);
    a = base; a.anchor = H(9);
    BOOST_CHECK(keys.insert(a.Key()).second);
    a = base; a.nbits = 0x1d00fffe;
    BOOST_CHECK(keys.insert(a.Key()).second);
    a = base; a.payout = B("payouu");
    BOOST_CHECK(keys.insert(a.Key()).second);
    a = base; a.solution = B("solutioo");
    BOOST_CHECK(keys.insert(a.Key()).second);

    // Same inputs, same key -- the whole point.
    Args again;
    BOOST_CHECK_EQUAL(again.Key().ToString(), base.Key().ToString());
}

BOOST_AUTO_TEST_CASE(key_frames_variable_length_inputs)
{
    // The two variable-length arguments are adjacent, so without explicit lengths these
    // would hash alike and a solution could be verified against the wrong payout.
    Args x; x.payout = B("ab"); x.solution = B("c");
    Args y; y.payout = B("a");  y.solution = B("bc");
    BOOST_CHECK(x.Key() != y.Key());

    // Including the empty/non-empty boundary, which is the no-solution case's key.
    Args p; p.payout = B("");   p.solution = B("ab");
    Args q; q.payout = B("a");  q.solution = B("b");
    Args r; r.payout = B("ab"); r.solution = B("");
    BOOST_CHECK(p.Key() != q.Key());
    BOOST_CHECK(q.Key() != r.Key());
    BOOST_CHECK(p.Key() != r.Key());
}

BOOST_AUTO_TEST_CASE(get_put_roundtrip)
{
    VerifyCache c{16};
    const uint256 k{H(7)};
    VerifyVerdict v;
    BOOST_CHECK(!c.Get(k, v)); // cold

    c.Put(k, VerifyVerdict{.ok = true, .solution_valid = true, .out_of_gas = false,
                           .alpha_q32 = 123, .beta_q32 = 456});
    BOOST_CHECK(c.Get(k, v));
    BOOST_CHECK(v.ok);
    BOOST_CHECK(v.solution_valid);
    BOOST_CHECK(!v.out_of_gas);
    BOOST_CHECK_EQUAL(v.alpha_q32, 123U);
    BOOST_CHECK_EQUAL(v.beta_q32, 456U);

    // A rejection is cached too: it is as much a function of the inputs as an acceptance,
    // and it is the answer an attacker would most like us to recompute (doc sec 2.1quater).
    const uint256 bad{H(8)};
    c.Put(bad, VerifyVerdict{.ok = false, .out_of_gas = true});
    BOOST_CHECK(c.Get(bad, v));
    BOOST_CHECK(!v.ok);
    BOOST_CHECK(v.out_of_gas);
}

BOOST_AUTO_TEST_CASE(bounded_and_evicts_in_insertion_order)
{
    VerifyCache c{4};
    for (uint8_t i = 0; i < 4; ++i) c.Put(H(i), VerifyVerdict{.alpha_q32 = i});
    BOOST_CHECK_EQUAL(c.Size(), 4U);

    // Overflowing drops the oldest, never grows past the cap.
    c.Put(H(4), VerifyVerdict{.alpha_q32 = 4});
    BOOST_CHECK_EQUAL(c.Size(), 4U);
    VerifyVerdict v;
    BOOST_CHECK(!c.Get(H(0), v));      // evicted
    BOOST_CHECK(c.Get(H(4), v));       // newest kept
    BOOST_CHECK_EQUAL(v.alpha_q32, 4U);
    for (uint8_t i = 1; i < 4; ++i) BOOST_CHECK(c.Get(H(i), v));

    // Re-Put of a live key must not queue a second eviction token for it, or the cap
    // would be enforced by throwing away entries that are still present in the map.
    for (int i = 0; i < 100; ++i) c.Put(H(4), VerifyVerdict{.alpha_q32 = 4});
    BOOST_CHECK_EQUAL(c.Size(), 4U);
    BOOST_CHECK(c.Get(H(4), v));
    for (uint8_t i = 1; i < 4; ++i) BOOST_CHECK(c.Get(H(i), v));
}

BOOST_AUTO_TEST_CASE(cap_of_one_is_usable)
{
    // A degenerate size must still behave (and never divide-by-zero or underflow).
    VerifyCache c{1};
    VerifyVerdict v;
    c.Put(H(1), VerifyVerdict{.ok = true});
    BOOST_CHECK(c.Get(H(1), v));
    c.Put(H(2), VerifyVerdict{.ok = true});
    BOOST_CHECK_EQUAL(c.Size(), 1U);
    BOOST_CHECK(!c.Get(H(1), v));
    BOOST_CHECK(c.Get(H(2), v));
}

BOOST_AUTO_TEST_SUITE_END()
