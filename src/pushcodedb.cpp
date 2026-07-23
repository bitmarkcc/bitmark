// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pushcodedb.h>

#include <hash.h>
#include <script/script.h>

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
