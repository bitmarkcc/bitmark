// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_ACTIVATIONDB_H
#define BITCOIN_DYNAMICALGO_ACTIVATIONDB_H

#include <dbwrapper.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <utility>
#include <vector>

// Dynamic-algo per-slot ACTIVATION consensus store (Bitmark, phase 6.5b).
//
// The active dynamic algo for an mPoW slot is a pure function of the confirmed chain
// (the OP_VOTE anchored-window tally + the 720-block activation delay -- see
// doc/dynamic-algo-voting.md sec "Activation"). Rather than rescan thousands of blocks
// on every ConnectBlock (as the informational getalgovote RPC does), consensus tracks
// it INCREMENTALLY in this store: as blocks connect it records, per slot, the currently
// active branch and the height it activated, so the reward path's GetActiveAlgoBranch is
// an O(1) lookup.
//
// Like the OP_PUSHCODE code DB (src/pushcodedb.h), this is a CONSENSUS database: updated
// synchronously in ConnectBlock/DisconnectBlock and reconciled with the active tip at
// startup via a best-block marker. All access is under cs_main.
//
// NOTE (phase 6.5b step 2): this is the storage layer only. The incremental
// window-tally / year-fees state and the ConnectBlock computation that produces the
// per-block slot updates are added in the following step; here the store just holds the
// per-slot active branch, the best block, and atomic apply/undo.

namespace dynamicalgo {

//! The active dynamic algo for one slot. A null branch means the slot is primitive-only
//! (no algo activated yet). `activation_height` is the height at which `branch` became
//! the slot's algo (0 when primitive-only).
struct CSlotActivation {
    uint256 branch;               //!< OP_PUSHCODE branch tip of the active algo (null == primitive-only)
    int32_t activation_height{0}; //!< height `branch` became active (0 == none)

    SERIALIZE_METHODS(CSlotActivation, obj)
    {
        READWRITE(obj.branch, obj.activation_height);
    }

    bool IsActive() const { return !branch.IsNull(); }
};

//! LevelDB-backed per-slot activation store plus a best-block marker for startup
//! reconciliation. All access is expected under cs_main (the consensus caller holds it).
class CActivationDB
{
private:
    CDBWrapper m_db;

public:
    explicit CActivationDB(DBParams db_params);

    //! The active algo for `slot` as last written. Returns false and leaves `out` at its
    //! default (primitive-only) when the slot has no record.
    bool ReadSlot(int slot, CSlotActivation& out) const;

    //! Atomically apply a block's per-slot activation changes and advance the best block.
    //! `slot_updates` lists only the slots whose activation changed at this block (usually
    //! none); each writes that slot's new CSlotActivation.
    bool ApplyBlock(const std::vector<std::pair<int, CSlotActivation>>& slot_updates,
                    const uint256& best_block);

    //! Atomically revert a block: restore each listed slot to the PRIOR CSlotActivation
    //! the caller supplies (its pre-block state) and set the best block to the block's
    //! parent.
    bool UndoBlock(const std::vector<std::pair<int, CSlotActivation>>& slot_restores,
                   const uint256& best_block);

    bool ReadBestBlock(uint256& best_block) const;
    bool WriteBestBlock(const uint256& best_block);
};

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_ACTIVATIONDB_H
