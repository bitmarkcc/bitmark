// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/activation.h>

#include <dynamicalgo/algovote.h>

#include <map>
#include <set>
#include <utility>
#include <vector>

namespace dynamicalgo {

namespace {

//! Loads each touched slot's window tally once, so the slide and the activation check
//! share one copy, and collects the edited tallies for the atomic write.
class WindowCache
{
    const CActivationDB& m_db;
    std::map<int, CWindowTally> m_tallies;

public:
    explicit WindowCache(const CActivationDB& db) : m_db{db} {}

    CWindowTally& Get(int slot)
    {
        const auto it = m_tallies.find(slot);
        if (it != m_tallies.end()) return it->second;
        CWindowTally t;
        m_db.ReadWindow(slot, t); // absent -> empty window
        return m_tallies.emplace(slot, std::move(t)).first->second;
    }

    std::vector<std::pair<int, CWindowTally>> Take() const
    {
        std::vector<std::pair<int, CWindowTally>> v;
        v.reserve(m_tallies.size());
        for (const auto& [slot, t] : m_tallies) v.emplace_back(slot, t);
        return v;
    }
};

} // namespace

bool ComputeConnect(const CActivationDB& db, const ActivationParams& params,
                    int32_t height, CAmount block_fees, const CBlockVotes& votes,
                    const uint256& block_hash, const BranchAssembler& assembles,
                    CConnectWrite& out)
{
    const int32_t VP{params.voting_period};
    const int32_t D{params.activation_delay};
    const int32_t Y{params.year_blocks};

    // The store must sit exactly one block behind; anything else means it diverged and
    // the caller has to reconcile (or reindex). An absent state is the first recorded
    // block -- the store legitimately starts empty at fork activation.
    CActivationState prev;
    if (db.ReadState(prev)) {
        if (prev.height != height - 1) return false;
    } else {
        prev = CActivationState{height - 1, 0, 0};
    }

    out = CConnectWrite{};
    out.height = height;
    out.block_fees = block_fees;
    out.votes = votes;
    out.best_block = block_hash;

    // ---- slide the fee sum -------------------------------------------------------
    // The floor for the window starting at f = height - VP - D is measured over the fees
    // ending at f-1, so the block entering that sum is f-1 and the one leaving is f-1-Y.
    // Heights the store never recorded (pre-fork) or has pruned simply do not contribute,
    // and year_blocks tracks how many did -- the floor normalizes by it.
    CAmount year_fees{prev.year_fees};
    int32_t year_blocks{prev.year_blocks};
    const int32_t fee_add{height - VP - D - 1}; // == f - 1
    const int32_t fee_sub{fee_add - Y};
    CAmount fees{0};
    if (fee_add >= 1 && db.ReadBlockFees(fee_add, fees)) { year_fees += fees; ++year_blocks; }
    if (fee_sub >= 1 && db.ReadBlockFees(fee_sub, fees)) { year_fees -= fees; --year_blocks; }

    // ---- slide the per-slot window tallies ---------------------------------------
    // W(height) = [height-VP-D, height-D-1]. W(height-1) both began and ended one block
    // earlier, so add the window's new last block and drop its old first block.
    WindowCache windows{db};
    const int32_t win_add{height - D - 1}; // the window's new last block
    const int32_t win_sub{fee_add};        // its old first block (== f - 1)
    CBlockVotes entering, leaving;
    if (win_add >= 1 && db.ReadBlockVotes(win_add, entering)) {
        for (const CVoteEntry& e : entering.entries) windows.Get(e.slot).Add(e.branch, e.tally);
    }
    if (win_sub >= 1 && db.ReadBlockVotes(win_sub, leaving)) {
        for (const CVoteEntry& e : leaving.entries) windows.Get(e.slot).Sub(e.branch, e.tally);
    }

    // ---- decide the activations landing at this height ---------------------------
    // At least one voting period's worth of recorded fee history is required before any
    // activation can land. The store only starts recording at fork activation, so without
    // this the earliest eligible window (which needs just VP+D+1 blocks after the fork)
    // would be judged against a floor averaged over a single block's fees. The guard
    // defers the first possible activation to fork + 2*VP + D.
    const int32_t f{height - VP - D};
    CBlockVotes anchor;
    if (year_blocks >= VP && f >= 1 && db.ReadBlockVotes(f, anchor)) {
        const CAmount fee_floor{VoteFeeFloor(year_fees, year_blocks, VP)};
        std::set<int> anchored_slots;
        for (const CVoteEntry& e : anchor.entries) anchored_slots.insert(e.slot);
        for (const int slot : anchored_slots) {
            const std::optional<uint256> winner{VoteWindowWinner(windows.Get(slot).ToMap(), fee_floor)};
            if (!winner) continue;
            // The window is only anchored if its FIRST block votes for the winner itself.
            bool anchored{false};
            for (const CVoteEntry& e : anchor.entries) {
                if (e.slot == slot && e.branch == *winner) { anchored = true; break; }
            }
            if (!anchored) continue;
            CSlotActivation prior;
            db.ReadSlot(slot, prior);
            if (prior.IsActive() && prior.branch == *winner) continue; // already this algo
            // A winner that cannot be assembled voids the activation; the slot keeps its
            // previous algo (assembly is a pure function of the chain, so this is
            // identical on every node).
            if (!assembles(*winner)) continue;
            out.slot_updates.push_back(CSlotEntry{static_cast<uint8_t>(slot),
                                                  CSlotActivation{*winner, height}});
            out.slot_undo.push_back(CSlotEntry{static_cast<uint8_t>(slot), prior});
        }
    }

    out.windows = windows.Take();
    out.state = CActivationState{height, year_fees, year_blocks};

    // ---- retention ---------------------------------------------------------------
    // Disconnecting this block has to re-add fee_sub, so keep records down to it plus a
    // reorg margin and drop what falls below.
    const int32_t prune{fee_sub - params.reorg_margin};
    if (prune >= 1) out.prune_heights.push_back(prune);
    return true;
}

bool ComputeDisconnect(const CActivationDB& db, const ActivationParams& params,
                       int32_t height, const uint256& parent_hash,
                       CDisconnectWrite& out)
{
    const int32_t VP{params.voting_period};
    const int32_t D{params.activation_delay};
    const int32_t Y{params.year_blocks};

    CActivationState prev;
    if (!db.ReadState(prev) || prev.height != height) return false;

    out = CDisconnectWrite{};
    out.height = height;
    out.best_block = parent_hash;

    // Reverse the fee-sum slide. (Every height read here is below `height`, so none of
    // them is the record this disconnect erases.)
    CAmount year_fees{prev.year_fees};
    int32_t year_blocks{prev.year_blocks};
    const int32_t fee_add{height - VP - D - 1};
    const int32_t fee_sub{fee_add - Y};
    CAmount fees{0};
    if (fee_add >= 1 && db.ReadBlockFees(fee_add, fees)) { year_fees -= fees; --year_blocks; }
    if (fee_sub >= 1 && db.ReadBlockFees(fee_sub, fees)) { year_fees += fees; ++year_blocks; }

    // Reverse the window slide.
    WindowCache windows{db};
    const int32_t win_add{height - D - 1};
    const int32_t win_sub{fee_add};
    CBlockVotes entering, leaving;
    if (win_add >= 1 && db.ReadBlockVotes(win_add, entering)) {
        for (const CVoteEntry& e : entering.entries) windows.Get(e.slot).Sub(e.branch, e.tally);
    }
    if (win_sub >= 1 && db.ReadBlockVotes(win_sub, leaving)) {
        for (const CVoteEntry& e : leaving.entries) windows.Get(e.slot).Add(e.branch, e.tally);
    }

    // Restore whatever per-slot activations this block made (absent record == none).
    db.ReadSlotUndo(height, out.slot_restores);
    out.windows = windows.Take();
    out.state = CActivationState{height - 1, year_fees, year_blocks};
    return true;
}

} // namespace dynamicalgo
