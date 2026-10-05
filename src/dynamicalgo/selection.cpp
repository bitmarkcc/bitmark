// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/selection.h>

namespace dynamicalgo {

bool CandidateBudget::TrySpend(int slot, const uint256& anchor, int budget)
{
    if (budget <= 0) return false;
    if (slot < 0 || static_cast<size_t>(slot) >= MAX_SLOTS) return false;
    LOCK(m_mutex);
    Slot& s{m_slots[static_cast<size_t>(slot)]};
    if (s.anchor != anchor) {
        // A new epoch for this slot: the seed changed, so every candidate is new work and
        // the previous epoch's spending is irrelevant.
        s.anchor = anchor;
        s.spent = 0;
    }
    if (s.spent >= budget) return false;
    ++s.spent;
    return true;
}

int CandidateBudget::Spent(int slot, const uint256& anchor) const
{
    if (slot < 0 || static_cast<size_t>(slot) >= MAX_SLOTS) return 0;
    LOCK(m_mutex);
    const Slot& s{m_slots[static_cast<size_t>(slot)]};
    return s.anchor == anchor ? s.spent : 0;
}

} // namespace dynamicalgo
