// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/reward.h>

#include <arith_uint256.h>
#include <util/check.h>

#include <algorithm>
#include <cassert>

namespace dynamicalgo {

CAmount fp_mul(CAmount x, uint64_t q_q32)
{
    assert(x >= 0);
    // (x * q) >> 32, with the product held in 256 bits so it cannot overflow: x is a
    // money amount (< 2^63) and q_q32 <= 2^32, so x*q < 2^95.
    arith_uint256 acc{static_cast<uint64_t>(x)};
    acc *= arith_uint256{q_q32};
    acc >>= 32;
    return static_cast<CAmount>(acc.GetLow64());
}

RewardSplit ComputeRewardSplit(CAmount subsidy, CAmount fees,
                               uint32_t alpha_q32, uint32_t beta_q32,
                               bool solution_valid)
{
    assert(fees >= 0);
    // NOTE: `subsidy` (S) MAY BE NEGATIVE. Bitmark's SSF can drive the scaled subsidy
    // below zero in a narrow near-peak hashrate region -- a pre-existing property of
    // GetBlockSubsidy that consensus must preserve (fixing it would be a hard fork). The
    // reward `r = S + F` can still be positive (fee-funded), so the split keys off `r`,
    // and fp_mul is only ever fed non-negative values.
    RewardSplit s;
    if (solution_valid) {
        const CAmount r = subsidy + fees;
        // dyn = floor(alpha*r) of the (possibly fee-funded) reward; primitive gets the
        // remainder r - dyn, so dyn + prim = r exactly. Full subsidy is emitted. If r <= 0
        // (fees don't cover a negative S) there is nothing to pay and the block will fail
        // the coinbase-value ceiling anyway; guard fp_mul off the non-positive case.
        s.required_payout = (r > 0) ? fp_mul(r, alpha_q32) : 0;
        s.emitted_subsidy = subsidy;
        s.max_coinbase_value = r;
    } else {
        // No solution. T = beta*(1-alpha) scales the WHOLE reward r (sec 4, 4.2), not the
        // subsidy alone. Each fp_mul factor is <= 2^32 so every result floors downward and
        // can never over-claim vs old nodes; the 1-alpha factor uses the full [0, 2^32]
        // range (alpha_q32 == 0 -> factor exactly 2^32).
        const uint64_t one_minus_alpha = (uint64_t{1} << 32) - alpha_q32;
        const auto T = [&](CAmount x) { return fp_mul(fp_mul(x, one_minus_alpha), beta_q32); };
        const CAmount r = subsidy + fees;

        // Only TWO things make this soft-fork safe, and they constrain different terms:
        //   1. emitted_subsidy <= S -- so a NEGATIVE S must not be scaled. T(-100) is -25,
        //      i.e. greater than -100, which would push the ceiling above S+F. Emit a
        //      negative S unchanged instead.
        //   2. total coinbase <= S + F.
        // Withholding FEES violates neither, in either sign of S, so it happens in both
        // cases: the negative-S region is a high-hashrate region, exactly where the
        // inclusion incentive should stay intact rather than switch off.
        s.emitted_subsidy = (subsidy >= 0) ? T(subsidy) : subsidy;
        s.max_coinbase_value = s.emitted_subsidy + fees;

        // The primitive miner keeps floor(T*r); the rest of what the coinbase may claim is
        // the withheld fee value and must appear in a pot output. Taking it as a
        // REMAINDER rather than an independently floored (1-T)*F is what keeps
        // keep + required_pot == max_coinbase_value EXACTLY, losing no satoshi between two
        // separate floor operations (sec 4.4). For S >= 0 this works out to ~(1-T)*F, and
        // for S < 0 to ~(1-T)*r.
        // The clamp is on `keep`, not on the pot, because as a statement about `keep` it
        // is independently true and worth enforcing: the miner cannot keep more than the
        // coinbase is allowed to claim. That makes required_pot >= 0 hold BY
        // CONSTRUCTION, so a release build (where Assume compiles away) can never feed a
        // negative amount to the "coinbase must contain a pot output of exactly
        // required_pot" rule. Clamping the pot directly would instead silently mask such
        // a bug, which on the money path is worse than failing loudly.
        //
        // The Assume documents that the clamp is NOT expected to bite: fp_mul is
        // Lipschitz-<=1 in x (adding d raises the floor by at most d) and composing two
        // such maps preserves that, so T(S+F) - T(S) <= F.
        const CAmount keep = std::min((r > 0) ? T(r) : s.max_coinbase_value,
                                      s.max_coinbase_value);
        Assume(keep == ((r > 0) ? T(r) : s.max_coinbase_value));
        s.required_pot = s.max_coinbase_value - keep;
        s.required_payout = 0;
    }
    return s;
}

} // namespace dynamicalgo
