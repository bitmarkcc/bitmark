// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PUSHCODEDB_H
#define BITCOIN_PUSHCODEDB_H

#include <dbwrapper.h>
#include <index/disktxpos.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

class CScript;

// OP_PUSHCODE code-entry consensus store (Bitmark, phase 3b).
//
// Each confirmed PUSHCODE output is an immutable, content-addressed code entry.
// Its identity is H = PushCodeHash(scriptPubKey) = Hash() (double-SHA256) of the
// whole output script -- which embeds the parent reference and the code chunk,
// so the entry DAG is acyclic by construction (git-like). A later PUSHCODE
// output references an entry by putting this H in its 32-byte codehash param.
//
// This is a CONSENSUS database (unlike the optional src/index BaseIndex ones):
// it is updated synchronously as blocks connect/disconnect and read during
// ConnectBlock to resolve references, so it must always reflect the active
// chain's entries. Storage follows dev2024: only the code POSITION
// (CDiskTxPos) is kept, not the code bytes; assembly seeks into the block files.

/** Op field of a code entry (low bit of the output's pushtype). */
enum PushCodeOp : uint8_t {
    PUSHCODE_OP_INSERT = 0, // NEW (root) and INSERT both append parts
    PUSHCODE_OP_REPLACE = 1, // REPLACE/DELETE a part range
};

/** One on-disk copy of a code entry: a confirmed PUSHCODE output backing H. The
 *  same content hash H can be pushed more than once (content dedup) -- e.g. an
 *  active algo re-pushed to keep a recent copy inside the pruned-node keep window.
 *  Each copy records where to read its (byte-identical) code chunk from disk. */
struct CCodeLocation {
    int32_t height{0};          // block height of this copy
    CDiskTxPos code_pos;        // position of the containing transaction in the block file
    uint32_t vout{0};           // index of the PUSHCODE output within that transaction

    SERIALIZE_METHODS(CCodeLocation, obj)
    {
        READWRITE(obj.height, obj.code_pos, VARINT(obj.vout));
    }
};

/** A confirmed code entry, keyed by its content hash H in the store. The content-
 *  derived fields (op/parent/parts) are identical for every copy of H, since H is
 *  the hash of the whole output script that encodes them; only the on-disk
 *  location differs per copy, so those are held in a per-copy list. */
struct CCodeEntry {
    uint8_t op{PUSHCODE_OP_INSERT};
    bool is_delete{false};      // REPLACE with no replacement: erase the part range
    bool has_parent{false};     // false for a NEW root entry
    uint256 parent_hash;        // content hash of the referenced entry (if has_parent)
    uint32_t nPart{0};          // part index (INSERT) or range start (REPLACE/DELETE)
    uint32_t nPart2{0};         // range end (REPLACE/DELETE); == nPart when single
    bool has_part{false};       // whether nPart was specified
    bool has_part2{false};      // whether nPart2 was specified (range)
    std::vector<CCodeLocation> locations; // one per confirmed output backing H

    SERIALIZE_METHODS(CCodeEntry, obj)
    {
        READWRITE(obj.op, obj.is_delete, obj.has_parent, obj.parent_hash, VARINT(obj.nPart),
                  VARINT(obj.nPart2), obj.has_part, obj.has_part2, obj.locations);
    }

    /** Number of confirmed outputs backing H (the old "refcount"). */
    uint32_t refcount() const { return static_cast<uint32_t>(locations.size()); }

    /** Canonical (logical) height for the DEPTH/LENGTH limits = the entry's first
     *  appearance = the lowest copy height. Re-pushing a recent copy adds
     *  availability without changing the entry's position in the DAG. */
    int32_t Height() const
    {
        int32_t h{0};
        bool first{true};
        for (const CCodeLocation& l : locations) {
            if (first || l.height < h) { h = l.height; first = false; }
        }
        return h;
    }
};

/** Content hash H of a PUSHCODE output's scriptPubKey (double-SHA256). */
uint256 PushCodeHash(const CScript& scriptPubKey);

/** LevelDB-backed store for code entries plus a best-block marker so the store
 *  can be reconciled with the active chain on startup. All access is expected
 *  under cs_main (the consensus caller holds it). */
class CCodeDB
{
private:
    CDBWrapper m_db;

public:
    explicit CCodeDB(DBParams db_params);

    bool ReadEntry(const uint256& hash, CCodeEntry& entry) const;
    bool HaveEntry(const uint256& hash) const;

    /** Connect a block's PUSHCODE outputs: for each (H, entry) append the copy's
     *  location to H's entry (creating it if new; content dedup, including
     *  duplicates within this same block). Each incoming entry carries exactly one
     *  location. Written with the new best block in a single atomic batch. */
    bool ApplyBlock(const std::vector<std::pair<uint256, CCodeEntry>>& entries,
                    const uint256& best_block);
    /** Disconnect the block at `height`: for each H, drop the copy locations
     *  confirmed at that height (one active-chain block per height), and erase the
     *  entry when no locations remain. Written with the new best block (the block's
     *  parent) in a single atomic batch. */
    bool UndoBlock(const std::vector<uint256>& hashes, int32_t height,
                   const uint256& best_block);

    bool ReadBestBlock(uint256& best_block) const;
    bool WriteBestBlock(const uint256& best_block);
};

// ---- Code assembly (phase 3c) ------------------------------------------------
//
// The materialized code of a branch tip H is a pure function of the entry DAG:
// walk parent_hash from H back to the NEW root, then replay the ops root->tip to
// build an ordered list of parts, and concatenate them. Nothing mutable is
// stored -- assembly is recomputable from the code DB (op/parent/part fields)
// plus the code chunks fetched from the block files (code_pos).

// MAX_PUSHCODE_* consensus limits (from dev2024 main.h). Both are BLOCK-HEIGHT
// distances -- they bound the branch's own shape, not byte sizes:
//   DEPTH  -- per parent edge: |E.height - parent.height| blocks (how far a single
//             reference reaches, either direction now that forward refs exist).
//   LENGTH -- per entry vs. the tip: |tip.height - E.height| blocks (the branch's
//             internal block span). (Later, dynamic-algo activation will add its
//             own "how far back was this defined" bounds, relative to the invoking
//             block; those are NOT these.)
// dev2024's MAX_PUSHCODE_PART_DEPTH was defined but never used (dropped), and
// MAX_PUSHCODE_SIZE was int64max (no effective byte bound; omitted).
// Max block span of a branch (tip -> oldest part). Also the pruned-node keep
// window: a node with pruning enabled keeps at least this many blocks below the
// tip (via a "pushcode" prune lock) so code assembly, which reads chunks from the
// block files, works. 525600 ~= 2 years at 720 blocks/day.
static constexpr int64_t MAX_PUSHCODE_LENGTH = 525600;
// Max blocks per single reference edge (|child.height - parent.height|). Set
// equal to LENGTH for now: a single hop may span the whole allowed branch length.
// (Lower it below LENGTH to make individual references reach less far than the
// branch total.)
static constexpr int64_t MAX_PUSHCODE_DEPTH = MAX_PUSHCODE_LENGTH;

// Per-slot pruned-node keep floor: keep at least this many of EACH mPoW slot's
// OWN blocks on disk. A dynamic algo's input is the last n blocks of its slot, so
// n must stay >= the DGW retarget window (25) and >= ~1 year (subsidy-scaling
// peak-hashrate), even for a sluggishly-mined slot where n-within-
// MAX_PUSHCODE_LENGTH could otherwise fall below 25. 90*365 = 32850 ~= 1 year of
// one slot at 90 blocks/day (720 blocks/day / 8 slots). Normally MAX_PUSHCODE_
// LENGTH keeps more than this; it only extends the window for sluggish slots.
static constexpr int MIN_SLOT_BLOCKS_ON_DISK = 90 * 365;

/** Outcome of assembling a branch tip's code. */
enum class PushCodeStatus {
    COMPLETE,    // `out` holds the fully-assembled code
    INCOMPLETE,  // a referenced ancestor entry (or its chunk) is not available yet
    INVALID,     // a consensus limit was exceeded or an op index was out of range
};

/** Fetch the raw code chunk of an entry (the code param of one of the PUSHCODE
 *  outputs in entry.locations). The chunk is byte-identical across copies, so the
 *  fetcher may read any location on disk -- it should prefer a recent copy for
 *  availability under pruning. Returns false if no copy is available (all pruned). */
using PushCodeChunkFetcher =
    std::function<bool(const CCodeEntry& entry, std::vector<unsigned char>& chunk)>;

/** Assemble the code of branch tip `hash`: walk parent_hash back to the NEW root,
 *  then replay insert/replace/delete ops root->tip, concatenating the parts.
 *  A missing ancestor or unavailable chunk yields INCOMPLETE (references are
 *  commitments -- a part may arrive in a later block, or never); an out-of-range
 *  op index or a blown MAX_PUSHCODE_DEPTH/LENGTH limit yields INVALID. Pure
 *  w.r.t. (db, fetch); holds no lock of its own. */
PushCodeStatus AssemblePushCode(const CCodeDB& db, const uint256& hash,
                                const PushCodeChunkFetcher& fetch,
                                std::vector<unsigned char>& out, std::string& reason);

#endif // BITCOIN_PUSHCODEDB_H
