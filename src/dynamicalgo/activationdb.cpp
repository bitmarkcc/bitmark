// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/activationdb.h>

#include <algorithm>
#include <utility>

namespace dynamicalgo {

namespace {
constexpr uint8_t DB_SLOT{'s'};      // (DB_SLOT, uint8 slot)    -> CSlotActivation
constexpr uint8_t DB_WINDOW{'w'};    // (DB_WINDOW, uint8 slot)  -> CWindowTally
constexpr uint8_t DB_FEES{'f'};      // (DB_FEES, int32 height)  -> CAmount
constexpr uint8_t DB_VOTES{'v'};     // (DB_VOTES, int32 height) -> CBlockVotes (sparse)
constexpr uint8_t DB_UNDO{'u'};      // (DB_UNDO, int32 height)  -> vector<CSlotEntry> (sparse)
constexpr uint8_t DB_STATE{'S'};     // -> CActivationState
constexpr uint8_t DB_BESTBLOCK{'B'}; // -> uint256

//! Key helpers, so the prefixes are written in exactly one place.
auto SlotKey(int slot) { return std::make_pair(DB_SLOT, static_cast<uint8_t>(slot)); }
auto WindowKey(int slot) { return std::make_pair(DB_WINDOW, static_cast<uint8_t>(slot)); }
auto FeesKey(int32_t height) { return std::make_pair(DB_FEES, height); }
auto VotesKey(int32_t height) { return std::make_pair(DB_VOTES, height); }
auto UndoKey(int32_t height) { return std::make_pair(DB_UNDO, height); }
} // namespace

// ---- CWindowTally ---------------------------------------------------------------

void CWindowTally::Add(const uint256& branch, const VoteTally& t)
{
    if (t.IsEmpty()) return;
    const auto it = std::lower_bound(branches.begin(), branches.end(), branch,
                                     [](const CBranchTally& a, const uint256& b) { return a.branch < b; });
    if (it != branches.end() && it->branch == branch) {
        it->tally += t;
        if (it->tally.IsEmpty()) branches.erase(it);
        return;
    }
    branches.insert(it, CBranchTally{branch, t}); // kept sorted by branch (canonical)
}

void CWindowTally::Sub(const uint256& branch, const VoteTally& t)
{
    if (t.IsEmpty()) return;
    const auto it = std::lower_bound(branches.begin(), branches.end(), branch,
                                     [](const CBranchTally& a, const uint256& b) { return a.branch < b; });
    // Only ever called to remove weight that was previously added (the block leaving the
    // window), so a missing branch would mean the bookkeeping drifted; ignore rather than
    // create a negative entry.
    if (it == branches.end() || it->branch != branch) return;
    it->tally -= t;
    if (it->tally.IsEmpty()) branches.erase(it);
}

std::map<uint256, VoteTally> CWindowTally::ToMap() const
{
    std::map<uint256, VoteTally> m;
    for (const CBranchTally& b : branches) m.emplace(b.branch, b.tally);
    return m;
}

// ---- CActivationDB -------------------------------------------------------------

CActivationDB::CActivationDB(DBParams db_params) : m_db{std::move(db_params)} {}

bool CActivationDB::ReadSlot(int slot, CSlotActivation& out) const
{
    return m_db.Read(SlotKey(slot), out);
}

bool CActivationDB::ReadBlockFees(int32_t height, CAmount& out) const
{
    return m_db.Read(FeesKey(height), out);
}

bool CActivationDB::ReadBlockVotes(int32_t height, CBlockVotes& out) const
{
    return m_db.Read(VotesKey(height), out);
}

bool CActivationDB::ReadSlotUndo(int32_t height, std::vector<CSlotEntry>& out) const
{
    return m_db.Read(UndoKey(height), out);
}

bool CActivationDB::ReadWindow(int slot, CWindowTally& out) const
{
    return m_db.Read(WindowKey(slot), out);
}

bool CActivationDB::ReadState(CActivationState& out) const
{
    return m_db.Read(DB_STATE, out);
}

bool CActivationDB::ReadBestBlock(uint256& best_block) const
{
    return m_db.Read(DB_BESTBLOCK, best_block);
}

bool CActivationDB::ApplyConnect(const CConnectWrite& w)
{
    CDBBatch batch{m_db};
    batch.Write(FeesKey(w.height), w.block_fees);
    if (!w.votes.IsEmpty()) batch.Write(VotesKey(w.height), w.votes);
    for (const auto& [slot, tally] : w.windows) batch.Write(WindowKey(slot), tally);
    for (const CSlotEntry& e : w.slot_updates) batch.Write(SlotKey(e.slot), e.act);
    if (!w.slot_undo.empty()) batch.Write(UndoKey(w.height), w.slot_undo);
    // Per-block records that have fallen out of the retention window (the sliding window
    // and the year-fees sum no longer reach them).
    for (const int32_t h : w.prune_heights) {
        batch.Erase(FeesKey(h));
        batch.Erase(VotesKey(h));
        batch.Erase(UndoKey(h));
    }
    batch.Write(DB_STATE, w.state);
    batch.Write(DB_BESTBLOCK, w.best_block);
    return m_db.WriteBatch(batch);
}

bool CActivationDB::ApplyDisconnect(const CDisconnectWrite& w)
{
    CDBBatch batch{m_db};
    for (const auto& [slot, tally] : w.windows) batch.Write(WindowKey(slot), tally);
    for (const CSlotEntry& e : w.slot_restores) batch.Write(SlotKey(e.slot), e.act);
    // The block is gone, so its per-block records go with it.
    batch.Erase(FeesKey(w.height));
    batch.Erase(VotesKey(w.height));
    batch.Erase(UndoKey(w.height));
    batch.Write(DB_STATE, w.state);
    batch.Write(DB_BESTBLOCK, w.best_block);
    return m_db.WriteBatch(batch);
}

bool CActivationDB::WriteBestBlock(const uint256& best_block)
{
    return m_db.Write(DB_BESTBLOCK, best_block);
}

} // namespace dynamicalgo
