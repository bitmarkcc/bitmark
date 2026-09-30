// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_ACTIVATIONDB_H
#define BITCOIN_DYNAMICALGO_ACTIVATIONDB_H

#include <consensus/amount.h>
#include <dbwrapper.h>
#include <dynamicalgo/algovote.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

// Dynamic-algo per-slot ACTIVATION consensus store (Bitmark, phase 6.5b).
//
// The active dynamic algo for an mPoW slot is a pure function of the confirmed chain
// (the OP_VOTE anchored-window tally + the 720-block activation delay -- see
// doc/dynamic-algo-voting.md sec "Activation"). Rescanning the window on every block
// (as the informational getalgovote RPC does) would be O(VOTING_PERIOD) per block, so
// consensus tracks it INCREMENTALLY here and the reward path's GetActiveAlgoBranch is
// an O(1) lookup.
//
// The window that would activate at height t is [f, f+VP-1] with f = t - VP - 720 (its
// last block is t-721), so it slides by exactly one block per height. The store keeps:
//   * per-block FEES (dense, tiny) -- for the year_fees running sum the fee floor uses;
//   * per-block VOTES (sparse: only blocks that carry votes) -- the units the sliding
//     window adds and subtracts;
//   * a per-slot running WINDOW tally -- so evaluating a window is O(branches);
//   * the running STATE (year_fees and the height it reflects);
//   * the per-slot ACTIVATION output, plus a per-block UNDO record of the prior values.
//
// Like the OP_PUSHCODE code DB (src/pushcodedb.h) this is a CONSENSUS database, backed
// by LevelDB, updated synchronously in ConnectBlock/DisconnectBlock and reconciled with
// the active tip at startup via a best-block marker. All access is under cs_main.

namespace dynamicalgo {

//! The active dynamic algo for one slot. A null branch means the slot is primitive-only
//! (no algo activated yet). `activation_height` is the height at which `branch` became
//! the slot's algo (0 when primitive-only).
struct CSlotActivation {
    uint256 branch;               //!< OP_PUSHCODE branch tip of the active algo (null == primitive-only)
    int32_t activation_height{0}; //!< height `branch` became active (0 == none)

    SERIALIZE_METHODS(CSlotActivation, obj) { READWRITE(obj.branch, obj.activation_height); }

    bool IsActive() const { return !branch.IsNull(); }
};

//! A (slot, activation) pair -- used for the per-slot updates a block makes, and for the
//! prior values recorded so the block can be undone.
struct CSlotEntry {
    uint8_t slot{0};
    CSlotActivation act;

    SERIALIZE_METHODS(CSlotEntry, obj) { READWRITE(obj.slot, obj.act); }
};

//! One (slot, branch) vote contribution from a single block.
struct CVoteEntry {
    uint8_t slot{0};
    uint256 branch;
    VoteTally tally;

    SERIALIZE_METHODS(CVoteEntry, obj) { READWRITE(obj.slot, obj.branch, obj.tally); }
};

//! A block's vote contributions across all slots. Stored only for blocks that actually
//! carry votes, so this record is sparse.
struct CBlockVotes {
    std::vector<CVoteEntry> entries;

    SERIALIZE_METHODS(CBlockVotes, obj) { READWRITE(obj.entries); }

    bool IsEmpty() const { return entries.empty(); }
};

//! One branch's running tally within a window.
struct CBranchTally {
    uint256 branch;
    VoteTally tally;

    SERIALIZE_METHODS(CBranchTally, obj) { READWRITE(obj.branch, obj.tally); }
};

//! A slot's running per-branch tally over the anchored window currently under
//! evaluation. Maintained by adding the block that enters the window and subtracting the
//! one that leaves, so the window never has to be rescanned.
struct CWindowTally {
    std::vector<CBranchTally> branches;

    SERIALIZE_METHODS(CWindowTally, obj) { READWRITE(obj.branches); }

    //! Add/subtract a branch's weight. Entries that reach zero are dropped, so a window
    //! with no live votes serializes empty (and the representation stays canonical).
    void Add(const uint256& branch, const VoteTally& t);
    void Sub(const uint256& branch, const VoteTally& t);

    //! The tally in the form VoteWindowWinner() consumes.
    std::map<uint256, VoteTally> ToMap() const;
};

//! The store's incremental bookkeeping, valid as of `height`.
struct CActivationState {
    int32_t height{0};       //!< height of the block this state reflects (== best block)
    CAmount year_fees{0};    //!< running sum of block fees over the year ending at the
                             //!< evaluated window's f-1 (the fee floor's basis)
    int32_t year_blocks{0};  //!< how many blocks are summed into year_fees; the fee floor
                             //!< normalizes by this, so a partially recorded year (the
                             //!< store only starts at fork activation) still yields a
                             //!< meaningful floor

    SERIALIZE_METHODS(CActivationState, obj)
    {
        READWRITE(obj.height, obj.year_fees, obj.year_blocks);
    }
};

//! Everything block `height` changes in the store, written in one atomic batch.
struct CConnectWrite {
    int32_t height{0};
    CAmount block_fees{0};                 //!< this block's total tx fees
    CBlockVotes votes;                     //!< this block's votes (not written when empty)
    std::vector<std::pair<int, CWindowTally>> windows; //!< slots whose window tally moved
    CActivationState state;
    std::vector<CSlotEntry> slot_updates;  //!< slots activating at this height (usually none)
    std::vector<CSlotEntry> slot_undo;     //!< their prior values, for DisconnectBlock
    std::vector<int32_t> prune_heights;    //!< per-block records that fell out of retention
    uint256 best_block;
};

//! Everything needed to reverse a connect, written in one atomic batch.
struct CDisconnectWrite {
    int32_t height{0};                     //!< the block being disconnected
    std::vector<std::pair<int, CWindowTally>> windows; //!< reverted window tallies
    CActivationState state;                //!< reverted state
    std::vector<CSlotEntry> slot_restores; //!< per-slot prior values to restore
    uint256 best_block;                    //!< the disconnected block's parent
};

//! LevelDB-backed activation store. All access is expected under cs_main (the consensus
//! caller holds it).
class CActivationDB
{
private:
    CDBWrapper m_db;

public:
    explicit CActivationDB(DBParams db_params);

    // ---- reads -------------------------------------------------------------------
    //! The active algo for `slot`. Returns false and leaves `out` at its default
    //! (primitive-only) when the slot has no record.
    bool ReadSlot(int slot, CSlotActivation& out) const;
    //! This block's total fees / votes / the prior-activation undo record. Each returns
    //! false when absent (no votes, pruned, or nothing changed at that height).
    bool ReadBlockFees(int32_t height, CAmount& out) const;
    bool ReadBlockVotes(int32_t height, CBlockVotes& out) const;
    bool ReadSlotUndo(int32_t height, std::vector<CSlotEntry>& out) const;
    //! A slot's running window tally (false when the slot has no live votes).
    bool ReadWindow(int slot, CWindowTally& out) const;
    //! The running bookkeeping (false before the first block is applied).
    bool ReadState(CActivationState& out) const;
    bool ReadBestBlock(uint256& best_block) const;

    // ---- atomic writes -----------------------------------------------------------
    bool ApplyConnect(const CConnectWrite& w);
    bool ApplyDisconnect(const CDisconnectWrite& w);
    bool WriteBestBlock(const uint256& best_block);
};

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_ACTIVATIONDB_H
