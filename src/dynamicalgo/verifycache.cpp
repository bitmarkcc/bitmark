// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/verifycache.h>

#include <hash.h>

#include <algorithm>

namespace dynamicalgo {

VerifyCache::VerifyCache(size_t max_entries)
    : m_max_entries{std::max<size_t>(max_entries, 1)}
{
}

uint256 VerifyCache::Key(const uint256& branch, uint8_t algo, const uint256& anchor,
                         uint32_t nbits, Span<const unsigned char> payout,
                         Span<const unsigned char> solution)
{
    HashWriter w{};
    w << branch << algo << anchor << nbits;
    // Explicit lengths ahead of the variable-length arguments: without them
    // (payout="ab", solution="c") and (payout="a", solution="bc") would hash alike.
    w << static_cast<uint64_t>(payout.size());
    w.write(AsBytes(payout));
    w << static_cast<uint64_t>(solution.size());
    w.write(AsBytes(solution));
    return w.GetHash();
}

bool VerifyCache::Get(const uint256& key, VerifyVerdict& out) const
{
    LOCK(m_mutex);
    const auto it{m_map.find(key)};
    if (it == m_map.end()) return false;
    out = it->second;
    return true;
}

void VerifyCache::Put(const uint256& key, const VerifyVerdict& verdict)
{
    LOCK(m_mutex);
    if (!m_map.emplace(key, verdict).second) return; // already known; nothing to reorder
    m_order.push_back(key);
    while (m_order.size() > m_max_entries) {
        m_map.erase(m_order.front());
        m_order.pop_front();
    }
}

size_t VerifyCache::Size() const
{
    LOCK(m_mutex);
    return m_map.size();
}

} // namespace dynamicalgo
