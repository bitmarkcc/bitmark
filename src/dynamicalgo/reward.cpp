// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/reward.h>

#include <arith_uint256.h>

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
    } else if (subsidy >= 0) {
        // emitted = floor(beta * (1 - alpha) * S). Each fp_mul factor is <= 2^32, so the
        // result is <= S -- can never over-claim vs old nodes (soft-fork-safe). The
        // 1-alpha factor uses the full [0, 2^32] range (alpha_q32 == 0 -> factor 2^32).
        const uint64_t one_minus_alpha = (uint64_t{1} << 32) - alpha_q32;
        s.emitted_subsidy = fp_mul(fp_mul(subsidy, one_minus_alpha), beta_q32);
        s.required_payout = 0;
        s.max_coinbase_value = s.emitted_subsidy + fees;
    } else {
        // No solution AND S < 0: a negative subsidy cannot be meaningfully "scaled down"
        // (beta*(1-alpha)*S would move it TOWARD zero, i.e. UP, exceeding the primitive
        // ceiling S + F and breaking soft-fork safety). Emit the primitive S unchanged, so
        // the ceiling is exactly S + F -- identical to old nodes.
        s.emitted_subsidy = subsidy;
        s.required_payout = 0;
        s.max_coinbase_value = subsidy + fees;
    }
    return s;
}

} // namespace dynamicalgo
