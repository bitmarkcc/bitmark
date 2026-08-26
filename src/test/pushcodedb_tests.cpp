// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pushcodedb.h>

#include <arith_uint256.h>
#include <dbwrapper.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <set>
#include <string>

BOOST_FIXTURE_TEST_SUITE(pushcodedb_tests, BasicTestingSetup)

// Content identity: deterministic and content-sensitive.
BOOST_AUTO_TEST_CASE(content_hash)
{
    const CScript a = CScript() << OP_RETURN << OP_PUSHCODE << std::vector<unsigned char>{1, 2, 3};
    const CScript b = CScript() << OP_RETURN << OP_PUSHCODE << std::vector<unsigned char>{1, 2, 4};
    BOOST_CHECK(PushCodeHash(a) == PushCodeHash(a));
    BOOST_CHECK(PushCodeHash(a) != PushCodeHash(b));
}

namespace {
// A one-location entry at a given height/vout (content fields don't matter here).
CCodeEntry EntryAt(int32_t height, uint32_t vout)
{
    CCodeEntry e;
    e.op = PUSHCODE_OP_INSERT;
    e.has_parent = false;
    CCodeLocation loc;
    loc.height = height;
    loc.vout = vout;
    e.locations.assign(1, loc);
    return e;
}
} // namespace

// Entry round-trip, content dedup (multiple copies at distinct heights), height-
// based undo, canonical Height(), and best-block tracking.
BOOST_AUTO_TEST_CASE(entry_refcount_bestblock)
{
    CCodeDB db{DBParams{.path = m_args.GetDataDirBase() / "codedb",
                        .cache_bytes = 1 << 20,
                        .memory_only = true}};

    const uint256 H = uint256::ONE;
    const uint256 blk1 = uint256S("0x01");
    const uint256 blk2 = uint256S("0x02");

    BOOST_CHECK(!db.HaveEntry(H));

    // apply a block (height 730) with one copy -> exists, readable, best block set
    BOOST_CHECK(db.ApplyBlock({{H, EntryAt(730, 0)}}, blk1));
    BOOST_CHECK(db.HaveEntry(H));
    CCodeEntry got;
    BOOST_CHECK(db.ReadEntry(H, got));
    BOOST_CHECK_EQUAL(got.Height(), 730);
    BOOST_CHECK_EQUAL(got.refcount(), 1U);
    uint256 best;
    BOOST_CHECK(db.ReadBestBlock(best));
    BOOST_CHECK(best == blk1);

    // re-push at a LATER height (731) -> 2 copies, canonical Height() stays 730
    BOOST_CHECK(db.ApplyBlock({{H, EntryAt(731, 1)}}, blk2));
    BOOST_CHECK(db.ReadEntry(H, got));
    BOOST_CHECK_EQUAL(got.refcount(), 2U);
    BOOST_CHECK_EQUAL(got.Height(), 730); // first appearance, not the re-push
    BOOST_CHECK(db.ReadBestBlock(best));
    BOOST_CHECK(best == blk2);

    // undo the height-731 block -> only that copy drops; entry (and 730) remain
    BOOST_CHECK(db.UndoBlock({H}, 731, blk1));
    BOOST_CHECK(db.HaveEntry(H));
    BOOST_CHECK(db.ReadEntry(H, got));
    BOOST_CHECK_EQUAL(got.refcount(), 1U);
    BOOST_CHECK_EQUAL(got.Height(), 730);

    // undo the height-730 block -> erased
    BOOST_CHECK(db.UndoBlock({H}, 730, uint256S("0x00")));
    BOOST_CHECK(!db.HaveEntry(H));
    BOOST_CHECK(!db.ReadEntry(H, got));

    // intra-block dedup: one block (height 730) adds the same H twice -> 2 copies,
    // both at height 730, so undoing that height removes both.
    BOOST_CHECK(db.ApplyBlock({{H, EntryAt(730, 0)}, {H, EntryAt(730, 1)}}, blk1));
    BOOST_CHECK(db.ReadEntry(H, got));
    BOOST_CHECK_EQUAL(got.refcount(), 2U);
    BOOST_CHECK(db.UndoBlock({H, H}, 730, uint256S("0x00")));
    BOOST_CHECK(!db.HaveEntry(H));
}

// ---- Assembly (phase 3c) ----------------------------------------------------
//
// A small harness: build code entries in an in-memory DB and materialize each
// entry's chunk from a vout->bytes map (standing in for the block files), so the
// pure AssemblePushCode replay/limit logic is exercised without any chain state.
namespace {
struct AssemblyFixture : public BasicTestingSetup {
    CCodeDB db{DBParams{.path = m_args.GetDataDirBase() / "codedb-asm",
                        .cache_bytes = 1 << 20,
                        .memory_only = true}};
    std::map<uint32_t, std::vector<unsigned char>> chunks; // vout -> chunk bytes
    std::set<uint32_t> unavailable;                        // vout with no chunk (pruned)
    uint32_t next_vout{0};
    uint32_t last_vout{0}; // vout assigned by the most recent Add()

    static uint256 MkHash(unsigned v) { return ArithToUint256(arith_uint256{v}); }

    // Add an entry keyed by H with a single location at `height`; its chunk is
    // stored under a fresh vout (standing in for the block-file read). Returns H.
    uint256 Add(unsigned id, CCodeEntry e, const std::vector<unsigned char>& chunk,
                int32_t height = 0)
    {
        CCodeLocation loc;
        loc.height = height;
        loc.vout = last_vout = next_vout++;
        e.locations.assign(1, loc);
        chunks[loc.vout] = chunk;
        const uint256 H = MkHash(id);
        BOOST_REQUIRE(db.ApplyBlock({{H, e}}, uint256::ONE));
        return H;
    }

    PushCodeChunkFetcher fetcher()
    {
        return [this](const CCodeEntry& e, std::vector<unsigned char>& out) {
            // Try each copy (highest height first, as the real fetcher does).
            for (auto it = e.locations.rbegin(); it != e.locations.rend(); ++it) {
                if (unavailable.count(it->vout)) continue;
                auto c = chunks.find(it->vout);
                if (c == chunks.end()) continue;
                out = c->second;
                return true;
            }
            return false;
        };
    }

    PushCodeStatus Assemble(const uint256& tip, std::vector<unsigned char>& out)
    {
        std::string reason;
        return AssemblePushCode(db, tip, fetcher(), out, reason);
    }
};

CCodeEntry NewRoot() { CCodeEntry e; e.has_parent = false; e.op = PUSHCODE_OP_INSERT; return e; }

CCodeEntry Child(const uint256& parent, uint8_t op)
{
    CCodeEntry e; e.has_parent = true; e.parent_hash = parent; e.op = op; return e;
}

const std::vector<unsigned char> A{0xAA}, B{0xBB}, C{0xCC};
} // namespace

BOOST_FIXTURE_TEST_CASE(assemble_new_and_append, AssemblyFixture)
{
    // NEW root seeds [A]; a plain reference (no part index) appends at the end.
    uint256 h0 = Add(0, NewRoot(), A);
    std::vector<unsigned char> out;
    BOOST_CHECK(Assemble(h0, out) == PushCodeStatus::COMPLETE);
    BOOST_CHECK(out == A);

    uint256 h1 = Add(1, Child(h0, PUSHCODE_OP_INSERT), B); // no has_part => append
    BOOST_CHECK(Assemble(h1, out) == PushCodeStatus::COMPLETE);
    BOOST_CHECK((out == std::vector<unsigned char>{0xAA, 0xBB}));
}

BOOST_FIXTURE_TEST_CASE(assemble_insert_at_index, AssemblyFixture)
{
    uint256 h0 = Add(0, NewRoot(), A);
    uint256 h1 = Add(1, Child(h0, PUSHCODE_OP_INSERT), B); // append => [A,B]
    CCodeEntry ins = Child(h1, PUSHCODE_OP_INSERT);
    ins.has_part = true; ins.nPart = 1;                    // insert C before index 1
    uint256 h2 = Add(2, ins, C);
    std::vector<unsigned char> out;
    BOOST_CHECK(Assemble(h2, out) == PushCodeStatus::COMPLETE);
    BOOST_CHECK((out == std::vector<unsigned char>{0xAA, 0xCC, 0xBB}));
}

BOOST_FIXTURE_TEST_CASE(assemble_replace_and_delete, AssemblyFixture)
{
    uint256 h0 = Add(0, NewRoot(), A);
    uint256 h1 = Add(1, Child(h0, PUSHCODE_OP_INSERT), B); // [A,B]
    uint256 h2 = Add(2, Child(h1, PUSHCODE_OP_INSERT), C); // append => [A,B,C]

    // REPLACE index 1 with A => [A,A,C]
    CCodeEntry rep = Child(h2, PUSHCODE_OP_REPLACE);
    rep.has_part = true; rep.nPart = 1;
    uint256 h3 = Add(3, rep, A);
    std::vector<unsigned char> out;
    BOOST_CHECK(Assemble(h3, out) == PushCodeStatus::COMPLETE);
    BOOST_CHECK((out == std::vector<unsigned char>{0xAA, 0xAA, 0xCC}));

    // DELETE range [0,1] (op=replace, is_delete, no chunk fetched) => [C]
    CCodeEntry del = Child(h2, PUSHCODE_OP_REPLACE);
    del.is_delete = true;
    del.has_part = true; del.nPart = 0; del.has_part2 = true; del.nPart2 = 1;
    uint256 h4 = Add(4, del, {});
    unavailable.insert(last_vout); // prove the assembler does NOT fetch a delete's chunk
    BOOST_CHECK(Assemble(h4, out) == PushCodeStatus::COMPLETE);
    BOOST_CHECK((out == std::vector<unsigned char>{0xCC}));
}

BOOST_FIXTURE_TEST_CASE(assemble_incomplete, AssemblyFixture)
{
    // Dangling reference: tip's parent is not in the DB (forward ref / never).
    uint256 h1 = Add(1, Child(MkHash(999), PUSHCODE_OP_INSERT), B);
    std::vector<unsigned char> out;
    BOOST_CHECK(Assemble(h1, out) == PushCodeStatus::INCOMPLETE);

    // Chunk unavailable (e.g. pruned block file) is also INCOMPLETE, not invalid.
    uint256 h0 = Add(0, NewRoot(), A);
    unavailable.insert(last_vout); // h0's chunk
    BOOST_CHECK(Assemble(h0, out) == PushCodeStatus::INCOMPLETE);
}

BOOST_FIXTURE_TEST_CASE(assemble_repush_survives_prune, AssemblyFixture)
{
    // Root pushed at height 10, then RE-PUSHED (same content H) at height 1000.
    uint256 h0 = Add(0, NewRoot(), A, /*height=*/10);
    const uint32_t old_vout = last_vout;
    // Re-push: same H (MkHash(0)) with a fresh, recent copy (its own vout/chunk).
    CCodeLocation recent;
    recent.height = 1000;
    recent.vout = next_vout++;
    chunks[recent.vout] = A; // byte-identical copy
    CCodeEntry re = NewRoot();
    re.locations.assign(1, recent);
    BOOST_REQUIRE(db.ApplyBlock({{h0, re}}, uint256::ONE));

    std::vector<unsigned char> out;
    // Prune the ORIGINAL copy: assembly must fall back to the recent copy.
    unavailable.insert(old_vout);
    BOOST_CHECK(Assemble(h0, out) == PushCodeStatus::COMPLETE);
    BOOST_CHECK(out == A);

    // Both copies gone -> INCOMPLETE (nothing on disk).
    unavailable.insert(recent.vout);
    BOOST_CHECK(Assemble(h0, out) == PushCodeStatus::INCOMPLETE);
}

BOOST_FIXTURE_TEST_CASE(assemble_out_of_range, AssemblyFixture)
{
    uint256 h0 = Add(0, NewRoot(), A); // parts == [A], size 1
    std::vector<unsigned char> out;

    CCodeEntry ins = Child(h0, PUSHCODE_OP_INSERT);
    ins.has_part = true; ins.nPart = 2; // > size (1) => out of range (size is ok)
    uint256 hi = Add(1, ins, B);
    BOOST_CHECK(Assemble(hi, out) == PushCodeStatus::INVALID);

    CCodeEntry rep = Child(h0, PUSHCODE_OP_REPLACE);
    rep.has_part = true; rep.nPart = 1; // == size => no such index to replace
    uint256 hr = Add(2, rep, C);
    BOOST_CHECK(Assemble(hr, out) == PushCodeStatus::INVALID);
}

BOOST_FIXTURE_TEST_CASE(assemble_depth_and_length_limits, AssemblyFixture)
{
    std::vector<unsigned char> out;

    // Forward reference within DEPTH: parent confirmed in a LATER block than the
    // child (negative raw distance, bounded by |.|) is fine.
    uint256 fh0 = Add(0, NewRoot(), A, /*height=*/1000);
    uint256 fh1 = Add(1, Child(fh0, PUSHCODE_OP_INSERT), B, /*height=*/10); // 990 blocks < DEPTH
    BOOST_CHECK(Assemble(fh1, out) == PushCodeStatus::COMPLETE);

    // DEPTH: a single reference edge farther than MAX_PUSHCODE_DEPTH blocks.
    uint256 dh0 = Add(2, NewRoot(), A, /*height=*/0);
    uint256 dh1 = Add(3, Child(dh0, PUSHCODE_OP_INSERT), B, /*height=*/MAX_PUSHCODE_DEPTH + 1);
    BOOST_CHECK(Assemble(dh1, out) == PushCodeStatus::INVALID);

    // LENGTH: edges within DEPTH but the tip-to-root block span exceeds LENGTH.
    const int32_t mid = MAX_PUSHCODE_LENGTH / 2 + 1;
    uint256 lh0 = Add(4, NewRoot(), A, /*height=*/0);
    uint256 lh1 = Add(5, Child(lh0, PUSHCODE_OP_INSERT), B, /*height=*/mid);
    uint256 lh2 = Add(6, Child(lh1, PUSHCODE_OP_INSERT), C, /*height=*/2 * mid); // span 2*mid > LENGTH
    BOOST_CHECK(Assemble(lh2, out) == PushCodeStatus::INVALID);
}

BOOST_AUTO_TEST_SUITE_END()
