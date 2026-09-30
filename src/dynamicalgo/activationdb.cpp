// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/activationdb.h>

#include <utility>

namespace dynamicalgo {

namespace {
constexpr uint8_t DB_SLOT{'s'};      // (DB_SLOT, uint8 slot) -> CSlotActivation
constexpr uint8_t DB_BESTBLOCK{'B'}; // best-block marker for reconciliation
} // namespace

CActivationDB::CActivationDB(DBParams db_params) : m_db{std::move(db_params)} {}

bool CActivationDB::ReadSlot(int slot, CSlotActivation& out) const
{
    return m_db.Read(std::make_pair(DB_SLOT, static_cast<uint8_t>(slot)), out);
}

bool CActivationDB::ApplyBlock(const std::vector<std::pair<int, CSlotActivation>>& slot_updates,
                               const uint256& best_block)
{
    CDBBatch batch{m_db};
    for (const auto& [slot, act] : slot_updates) {
        batch.Write(std::make_pair(DB_SLOT, static_cast<uint8_t>(slot)), act);
    }
    batch.Write(DB_BESTBLOCK, best_block);
    return m_db.WriteBatch(batch);
}

bool CActivationDB::UndoBlock(const std::vector<std::pair<int, CSlotActivation>>& slot_restores,
                              const uint256& best_block)
{
    CDBBatch batch{m_db};
    for (const auto& [slot, act] : slot_restores) {
        batch.Write(std::make_pair(DB_SLOT, static_cast<uint8_t>(slot)), act);
    }
    batch.Write(DB_BESTBLOCK, best_block);
    return m_db.WriteBatch(batch);
}

bool CActivationDB::ReadBestBlock(uint256& best_block) const
{
    return m_db.Read(DB_BESTBLOCK, best_block);
}

bool CActivationDB::WriteBestBlock(const uint256& best_block)
{
    return m_db.Write(DB_BESTBLOCK, best_block);
}

} // namespace dynamicalgo
