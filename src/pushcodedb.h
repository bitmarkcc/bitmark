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

/** A confirmed code entry, keyed by its content hash H in the store. */
struct CCodeEntry {
    uint8_t op{PUSHCODE_OP_INSERT};
    bool has_parent{false};     // false for a NEW root entry
    uint256 parent_hash;        // content hash of the referenced entry (if has_parent)
    uint32_t nPart{0};          // part index (INSERT) or range start (REPLACE)
    uint32_t nPart2{0};         // range end (REPLACE); == nPart when single
    bool has_part{false};       // whether nPart was specified
    bool has_part2{false};      // whether nPart2 was specified (REPLACE range)
    int32_t height{0};          // block height the entry was confirmed at
    CDiskTxPos code_pos;        // position of the containing transaction in the block file
    uint32_t vout{0};           // index of the PUSHCODE output within that transaction
    uint32_t refcount{1};       // number of confirmed outputs backing this H

    SERIALIZE_METHODS(CCodeEntry, obj)
    {
        READWRITE(obj.op, obj.has_parent, obj.parent_hash, VARINT(obj.nPart),
                  VARINT(obj.nPart2), obj.has_part, obj.has_part2,
                  obj.height, obj.code_pos, VARINT(obj.vout), VARINT(obj.refcount));
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

    /** Connect a block's PUSHCODE outputs: for each (H, entry), create the entry
     *  or bump its refcount if H already exists (content dedup, including
     *  duplicates within this same block). Written with the new best block in a
     *  single atomic batch. */
    bool ApplyBlock(const std::vector<std::pair<uint256, CCodeEntry>>& entries,
                    const uint256& best_block);
    /** Disconnect a block's PUSHCODE outputs: for each H, decrement its refcount
     *  and erase when it reaches zero. Written with the new best block (the
     *  block's parent) in a single atomic batch. */
    bool UndoBlock(const std::vector<uint256>& hashes, const uint256& best_block);

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
static constexpr int64_t MAX_PUSHCODE_DEPTH = 33638400;  // max blocks per reference edge
static constexpr int64_t MAX_PUSHCODE_LENGTH = 33638400; // max block span of a branch

/** Outcome of assembling a branch tip's code. */
enum class PushCodeStatus {
    COMPLETE,    // `out` holds the fully-assembled code
    INCOMPLETE,  // a referenced ancestor entry (or its chunk) is not available yet
    INVALID,     // a consensus limit was exceeded or an op index was out of range
};

/** Fetch the raw code chunk of an entry (the code param of the PUSHCODE output at
 *  entry.code_pos / entry.vout). Returns false if unavailable (e.g. pruned). */
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
