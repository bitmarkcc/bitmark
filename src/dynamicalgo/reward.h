// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_REWARD_H
#define BITCOIN_DYNAMICALGO_REWARD_H

#include <consensus/amount.h>

#include <cstdint>

// Dynamic-algo reward split (doc/dynamic-algo-mining.md sec 4). The algo's verifier
// emits two Q32 fixed-point fractions -- alpha (the dynamic miner's cut) and beta
// (the subsidy scale applied when no valid solution is present) -- as u32 values
// where the stored integer is value * 2^32, so alpha = alpha_q32 / 2^32 and the whole
// u32 range maps to [0, 1). No float ever enters this money path: all arithmetic is
// integer with a single fixed-point multiply-floor (fp_mul).

namespace dynamicalgo {

//! floor(x * q / 2^32), computed with a wide (256-bit) intermediate so x*q (up to
//! ~2^95) never overflows. `x` is a non-negative money amount; `q_q32` is a Q32
//! factor in [0, 2^32] (2^32 is permitted so a "1 - alpha" factor with alpha_q32 = 0
//! is exact). Every reward figure floors downward, so totals can never over-claim.
CAmount fp_mul(CAmount x, uint64_t q_q32);

//! The consensus reward constraints for one block, derived from the split (sec 4.4).
//! With r = subsidy + fees and T = beta*(1-alpha):
//!   * valid solution: the coinbase must pay >= required_payout to the payout
//!     scriptPubKey (the floor of sec 4.3), its total value <= max_coinbase_value = r,
//!     and it emits the full subsidy. required_pot = 0.
//!   * no solution: required_payout = 0; the primitive miner keeps floor(T*r) and the
//!     coinbase must ALSO carry a <algo+1> OP_SOLUTIONPOT output of exactly required_pot
//!     (sec 4.5), so its total value is max_coinbase_value = emitted_subsidy + fees.
//!     Only emitted_subsidy = floor(T*S) of the subsidy is emitted; the rest is
//!     milestone-deferred, and the withheld fees go to the pot rather than being burned.
//!
//! T scales the WHOLE reward r, not the subsidy alone. Scaling only the subsidy would
//! invert the inclusion incentive as the subsidy decays -- a pool would compare
//! (1-alpha)*r against beta*(1-alpha)*S + F and, once fees exceeded ~S/2, always prefer
//! to skip the solution (sec 4, 4.2).
struct RewardSplit {
    CAmount required_payout{0};    //!< dyn = floor(alpha*r) to the payout spk (0 if no solution)
    CAmount required_pot{0};       //!< exact value the coinbase's pot output must carry (0 if a solution)
    CAmount emitted_subsidy{0};    //!< subsidy actually emitted this block (for money-supply accounting)
    CAmount max_coinbase_value{0}; //!< coinbase GetValueOut() must be <= this (INCLUDING the pot output)
};

//! Compute the split. `subsidy` is S (post-mPoW-SSF-scaling), `fees` is F (the fees the
//! coinbase may claim), and alpha_q32/beta_q32 are the verifier's Q32 outputs.
//! `solution_valid` is whether verify() accepted a solution this block. Pure integer,
//! deterministic, identical on every node.
//!
//! S MAY BE NEGATIVE: the SSF can drive the scaled subsidy below zero near an algo's
//! hashrate peak (a pre-existing GetBlockSubsidy property we must preserve -- fixing it
//! would hard-fork). Handled soft-fork-safely: a valid solution still splits the reward
//! r = S + F (positive when fees cover the shortfall) so the dynamic miner gets alpha*r;
//! the no-solution branch, which would otherwise scale S UP toward zero, instead emits
//! the primitive S unchanged when S < 0. In every case max_coinbase_value <= S + F (the
//! old-node ceiling), and fp_mul is only ever given non-negative inputs.
RewardSplit ComputeRewardSplit(CAmount subsidy, CAmount fees,
                               uint32_t alpha_q32, uint32_t beta_q32,
                               bool solution_valid);

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_REWARD_H
