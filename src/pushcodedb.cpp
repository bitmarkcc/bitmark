// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pushcodedb.h>

#include <hash.h>
#include <script/script.h>

#include <cstdlib>
#include <map>

namespace {
// key prefixes in the code DB
constexpr uint8_t DB_CODE_ENTRY{'e'};
constexpr uint8_t DB_CODE_BESTBLOCK{'B'};
} // namespace

uint256 PushCodeHash(const CScript& scriptPubKey)
{
    // Content identity is the double-SHA256 of the whole output script (which
    // embeds the parent reference and code chunk), consistent with the 32-byte
    // reference param a child output carries.
    return Hash(scriptPubKey);
}

CCodeDB::CCodeDB(DBParams db_params) : m_db{std::move(db_params)} {}

bool CCodeDB::ReadEntry(const uint256& hash, CCodeEntry& entry) const
{
    return m_db.Read(std::make_pair(DB_CODE_ENTRY, hash), entry);
}

bool CCodeDB::HaveEntry(const uint256& hash) const
{
    return m_db.Exists(std::make_pair(DB_CODE_ENTRY, hash));
}

bool CCodeDB::ApplyBlock(const std::vector<std::pair<uint256, CCodeEntry>>& entries,
                         const uint256& best_block)
{
    // Aggregate by H so byte-identical outputs (even within this one block) bump
    // one entry's refcount rather than clobbering it. Keep the first-seen entry
    // fields as canonical (lowest height / earliest position).
    std::map<uint256, std::pair<CCodeEntry, uint32_t>> agg;
    for (const auto& [h, e] : entries) {
        auto it = agg.find(h);
        if (it == agg.end()) agg.emplace(h, std::make_pair(e, uint32_t{1}));
        else it->second.second += 1;
    }
    CDBBatch batch{m_db};
    for (const auto& [h, ec] : agg) {
        const uint32_t added = ec.second;
        CCodeEntry existing;
        CCodeEntry stored;
        if (m_db.Read(std::make_pair(DB_CODE_ENTRY, h), existing)) {
            stored = existing;
            stored.refcount = existing.refcount + added;
        } else {
            stored = ec.first;
            stored.refcount = added;
        }
        batch.Write(std::make_pair(DB_CODE_ENTRY, h), stored);
    }
    batch.Write(DB_CODE_BESTBLOCK, best_block);
    return m_db.WriteBatch(batch);
}

bool CCodeDB::UndoBlock(const std::vector<uint256>& hashes, const uint256& best_block)
{
    std::map<uint256, uint32_t> agg;
    for (const auto& h : hashes) agg[h] += 1;
    CDBBatch batch{m_db};
    for (const auto& [h, removed] : agg) {
        CCodeEntry existing;
        if (m_db.Read(std::make_pair(DB_CODE_ENTRY, h), existing)) {
            if (existing.refcount > removed) {
                existing.refcount -= removed;
                batch.Write(std::make_pair(DB_CODE_ENTRY, h), existing);
            } else {
                batch.Erase(std::make_pair(DB_CODE_ENTRY, h));
            }
        }
    }
    batch.Write(DB_CODE_BESTBLOCK, best_block);
    return m_db.WriteBatch(batch);
}

bool CCodeDB::ReadBestBlock(uint256& best_block) const
{
    return m_db.Read(DB_CODE_BESTBLOCK, best_block);
}

bool CCodeDB::WriteBestBlock(const uint256& best_block)
{
    return m_db.Write(DB_CODE_BESTBLOCK, best_block);
}

PushCodeStatus AssemblePushCode(const CCodeDB& db, const uint256& hash,
                                const PushCodeChunkFetcher& fetch,
                                std::vector<unsigned char>& out, std::string& reason)
{
    // 1. Walk parent_hash from the tip back to the NEW root, collecting entries
    //    tip-first. A missing ancestor => the branch is unassemblable (INCOMPLETE),
    //    not invalid: references are commitments, so a part may appear in a later
    //    block or never. Acyclicity is guaranteed by content addressing (H depends
    //    on parent_hash), so a simple walk terminates at the root; the DEPTH cap
    //    below also bounds any corrupt/looping DB.
    std::vector<CCodeEntry> chain; // tip-first
    uint256 cur = hash;
    while (true) {
        CCodeEntry e;
        if (!db.ReadEntry(cur, e)) {
            reason = "pushcode-incomplete";
            return PushCodeStatus::INCOMPLETE;
        }
        // DEPTH: each reference edge (child -> parent) spans a bounded number of
        // blocks, in either direction (forward references are allowed).
        if (!chain.empty()) {
            const int64_t edge = std::abs(int64_t{chain.back().height} - int64_t{e.height});
            if (edge > MAX_PUSHCODE_DEPTH) { reason = "pushcode-depth"; return PushCodeStatus::INVALID; }
        }
        chain.push_back(e);
        if (!e.has_parent) break; // reached the NEW root
        cur = e.parent_hash;
    }

    // LENGTH: every entry lies within a bounded block span of the tip (the
    // branch's internal length in blocks).
    const int64_t tip_height = chain.front().height;
    for (const CCodeEntry& e : chain) {
        if (std::abs(tip_height - int64_t{e.height}) > MAX_PUSHCODE_LENGTH) {
            reason = "pushcode-length"; return PushCodeStatus::INVALID;
        }
    }

    // 2. Replay ops root -> tip to build the ordered part list. Op semantics
    //    (matching dev2024): NEW seeds [chunk]; no part index appends at the end
    //    (whatever the op); INSERT+nPart inserts before index nPart; REPLACE with
    //    a [nPart,nPart2] range overwrites it (an empty chunk deletes the range).
    std::vector<std::vector<unsigned char>> parts;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        const CCodeEntry& e = *it;
        std::vector<unsigned char> chunk;
        if (!fetch(e, chunk)) {
            reason = "pushcode-chunk-unavailable";
            return PushCodeStatus::INCOMPLETE;
        }
        if (!e.has_parent) {
            parts.assign(1, std::move(chunk)); // NEW root
        } else if (!e.has_part) {
            parts.push_back(std::move(chunk));  // append at end
        } else if (e.op == PUSHCODE_OP_INSERT) {
            if (e.nPart > parts.size()) { reason = "pushcode-insert-oob"; return PushCodeStatus::INVALID; }
            parts.insert(parts.begin() + e.nPart, std::move(chunk));
        } else { // PUSHCODE_OP_REPLACE over [nPart, nPart2]
            const uint32_t start = e.nPart;
            const uint32_t end = e.has_part2 ? e.nPart2 : e.nPart;
            if (end < start || start >= parts.size() || end >= parts.size()) {
                reason = "pushcode-replace-oob"; return PushCodeStatus::INVALID;
            }
            parts.erase(parts.begin() + start, parts.begin() + end + 1);
            if (!chunk.empty()) parts.insert(parts.begin() + start, std::move(chunk)); // empty => delete
        }
    }

    // 3. Concatenate the parts into the assembled code.
    size_t total = 0;
    for (const auto& p : parts) total += p.size();
    out.clear();
    out.reserve(total);
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return PushCodeStatus::COMPLETE;
}
