// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for OP_PUSHCODE soft-fork activation: the base-version
// supermajority mechanism (CBlockIndex::IsSuperMajority) and, critically, that
// the mPoW algo / auxpow / variant / chainid bits in nVersion are masked out of
// the version count (GetBlockVersion = nVersion & 255). Without that mask a
// version-4 block carrying algo bits (raw nVersion e.g. 516) would be miscounted
// as "version >= 5" and could falsely activate the fork.

#include <chain.h>
#include <primitives/pureheader.h>
#include <script/pushcode.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(pushcode_tests, BasicTestingSetup)

namespace {
// Build a linked chain of `n` CBlockIndex with the given nVersion values
// (versions[i] is the nVersion of block i; block n-1 is the tip).
std::vector<CBlockIndex> MakeChain(const std::vector<int>& versions)
{
    std::vector<CBlockIndex> blocks(versions.size());
    for (size_t i = 0; i < versions.size(); i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = (int)i;
        blocks[i].nVersion = versions[i];
    }
    return blocks;
}
} // namespace

// Base version threshold: 75 of the last 100 blocks at base version >= 5.
BOOST_AUTO_TEST_CASE(supermajority_threshold)
{
    // exactly 75 version-5 blocks in a window of 100 -> active
    {
        std::vector<int> v(100, 4);
        for (int i = 25; i < 100; i++) v[i] = 5; // 75 blocks at version 5
        auto blocks = MakeChain(v);
        BOOST_CHECK(blocks.back().IsSuperMajority(5, 75, 100));
    }
    // only 74 version-5 blocks -> not active
    {
        std::vector<int> v(100, 4);
        for (int i = 26; i < 100; i++) v[i] = 5; // 74 blocks at version 5
        auto blocks = MakeChain(v);
        BOOST_CHECK(!blocks.back().IsSuperMajority(5, 75, 100));
    }
}

// The critical test: algo/auxpow/variant bits must not perturb the count.
BOOST_AUTO_TEST_CASE(algo_bits_are_masked)
{
    // 100 blocks all at BASE version 4 but carrying algo bits, so each raw
    // nVersion is well above 5. Correct masking (& 255) keeps them at 4, so the
    // supermajority is NOT reached. A broken (raw) comparison would see them all
    // as >= 5 and wrongly activate.
    {
        std::vector<int> v(100, 4 | BLOCK_VERSION_SHA256D); // raw 516
        auto blocks = MakeChain(v);
        BOOST_CHECK_EQUAL(blocks.back().nVersion, 516);
        BOOST_CHECK(!blocks.back().IsSuperMajority(5, 75, 100));
    }

    // 75 genuine version-5 blocks, each carrying a different algo (and some with
    // auxpow/variant bits): masking keeps them at base version 5, so they DO
    // count and the fork activates.
    {
        std::vector<int> v(100, 4); // 25 non-signalling version-4 blocks
        const int algos[] = {BLOCK_VERSION_SHA256D, BLOCK_VERSION_SCRYPT,
                             BLOCK_VERSION_ARGON2, BLOCK_VERSION_X17,
                             BLOCK_VERSION_YESCRYPT};
        for (int i = 25; i < 100; i++) {
            int nv = 5 | algos[i % 5];
            if (i % 2) nv |= BLOCK_VERSION_AUXPOW;
            if (i % 3) nv |= BLOCK_VERSION_VARIANT;
            v[i] = nv;
        }
        auto blocks = MakeChain(v);
        BOOST_CHECK(blocks.back().IsSuperMajority(5, 75, 100));
    }

    // A version-4 block whose raw nVersion happens to exceed 5 via a chain id in
    // the high bits must still not count (chainid occupies bits 16+).
    {
        std::vector<int> v(100, 4 | (7 << 16)); // chainid 7, base version 4
        auto blocks = MakeChain(v);
        BOOST_CHECK(!blocks.back().IsSuperMajority(5, 75, 100));
    }
}

namespace {
using valtype = std::vector<unsigned char>;
// a numeric PUSHCODE param, encoded as it lives on the stack (CScriptNum)
valtype pnum(int64_t v) { return CScriptNum(v).getvch(); }
valtype pbytes(size_t n, unsigned char fill = 0xab) { return valtype(n, fill); }
} // namespace

// Phase 3a grammar validation (CheckPushCodeGrammar): structure/sizes/consistency.
BOOST_AUTO_TEST_CASE(pushcode_grammar)
{
    std::string reason;
    auto ok = [&](std::vector<valtype> sol) { reason.clear(); return CheckPushCodeGrammar(sol, reason); };

    const valtype H = pbytes(32);          // valid 32-byte content hash
    const valtype code = pbytes(4, 0x11);
    const valtype empty;

    // valid forms
    BOOST_CHECK(ok({code}));                                // NEW
    BOOST_CHECK(ok({H, code}));                             // INSERT at end
    BOOST_CHECK(ok({pnum(0), H, code}));                    // pushtype INSERT, at end
    BOOST_CHECK(ok({pnum(1), H, code}));                    // pushtype REPLACE, at end
    BOOST_CHECK(ok({pnum(0), H, pnum(3), code}));           // INSERT at part 3
    BOOST_CHECK(ok({pnum(1), H, pnum(2), pnum(5), code}));  // REPLACE range [2,5]
    BOOST_CHECK(ok({pnum(1), H, pnum(4), pnum(4), code}));  // single-element range
    BOOST_CHECK(ok({pnum(3), H, pnum(2)}));                 // DELETE single part 2 (pushtype 3, no code)
    BOOST_CHECK(ok({pnum(3), H, pnum(2), pnum(5)}));        // DELETE range [2,5] (no code)

    // invalid forms
    BOOST_CHECK(!ok({}));                                   // 0 params
    BOOST_CHECK(!ok({pnum(0), H, pnum(1), pnum(2), pnum(3), code})); // 6 params
    BOOST_CHECK(!ok({empty}));                              // NEW with empty code
    BOOST_CHECK(!ok({H, empty}));                           // INSERT with empty code
    BOOST_CHECK(!ok({pnum(0), H, empty}));                  // explicit INSERT, empty code
    BOOST_CHECK(!ok({pnum(1), H, pnum(2), pnum(5), empty})); // REPLACE (non-delete) empty code: removal is delete-only now
    BOOST_CHECK(!ok({pbytes(31), code}));                   // ref hash not 32 bytes
    BOOST_CHECK(!ok({pbytes(33), code}));                   // ref hash not 32 bytes
    BOOST_CHECK(!ok({pnum(0), H, pnum(2), pnum(5), code})); // part range with INSERT
    BOOST_CHECK(!ok({pnum(1), H, pnum(5), pnum(2), code})); // nPart2 < nPart
    BOOST_CHECK(!ok({pnum(-1), H, code}));                  // negative pushtype
    BOOST_CHECK(!ok({pbytes(5), H, code}));                 // pushtype param > 4 bytes
    BOOST_CHECK(!ok({pnum(2), H, pnum(2)}));                // delete bit without replace bit (pushtype 2)
    BOOST_CHECK(!ok({pnum(3), H, pnum(2), pnum(5), code})); // delete takes no code (5 params)
    BOOST_CHECK(!ok({pnum(3), H, pnum(5), pnum(2)}));       // delete range nPart2 < nPart
    BOOST_CHECK(!reason.empty());                           // a reason was set on the last failure
}

BOOST_AUTO_TEST_SUITE_END()
