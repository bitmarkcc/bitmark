// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <uint256.h>
#include <logging.h>
#include <streams.h>
#include <crypto/equihash/equihash.h>
#include <node/protocol_version.h>
#include <serialize.h>
#include <util/bignum.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params, Algo algo)
{

    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
       	    {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 1 day worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);
    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);

    // Post 8mPoW fork // todo
    //return DarkGravityWave(pindexLast, algo);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    LogDebug(BCLog::VALIDATION, "GetNextWorkRequired RETARGET\n");
    LogDebug(BCLog::VALIDATION,"nTargetTimespan = %d    nActualTimespan = %d\n", params.nPowTargetTimespan, nActualTimespan);
    LogDebug(BCLog::VALIDATION,"Before: %08x  %s\n", pindexLast->nBits, arith_uint256().SetCompact(pindexLast->nBits).ToString());
    LogDebug(BCLog::VALIDATION,"After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    // asume true after for since lack of CBlockIndex at this function, we can't calculate if diff transition is permitted.
    /*    if (height > 450866) {
        return true;
	}*/ // todo: check

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());

        if (maximum_new_target < observed_new_target) {
	    return false;
	}

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) {
	    return false;
	}
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

bool CheckEquihashSolution(const CPureBlockHeader* pblock)
{
    Consensus::Params params = Params().GetConsensus();

    if (pblock->nSolution.size() > 1) {
        // LogPrintf("check equihash solution hashprevblock=%s solution size = %d part = %x %x\n",pblock->hashPrevBlock.GetHex().c_str(),pblock->nSolution.size(),pblock->nSolution[0],pblock->nSolution[1]);
    } else {
        // LogPrintf("check equihash solution with solution size = %d\n",pblock->nSolution.size());
    }

    unsigned int n = params.EquihashN();
    unsigned int k = params.EquihashK();

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    DataStream ss;
    ss << I;
    ss << pblock->nNonce256;

    /*LogPrintf("checkES ss (%lu) = ",ss.size());
    for (int i=0; i<ss.size(); i++) {
      LogPrintf("%02x",*((unsigned char *)&ss[0]+i));
    }

    LogPrintf("\n");
    LogPrintf("checkES nSolution (%lu) = ",(pblock->nSolution).size());
    for (int i=0; i<(pblock->nSolution).size(); i++) {
      LogPrintf("%02x",*((unsigned char *)&(pblock->nSolution)[0]+i));
    }
    LogPrintf("\n");*/

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);
    if (!isValid)
        return error("CheckEquihashSolution(): invalid solution");

    return true;
}

bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params)
{
    /*if (block.IsAuxpow()) {
        return CheckAuxPowProofOfWork(block);
    }

    if (block.GetAlgo() == Algo::EQUIHASH && !CheckEquihashSolution(&block)) {
        return false;
	}*/ // tmp: put it back

    return CheckProofOfWork(block.GetPoWHash(), block.nBits, params, block.GetAlgo());
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params, Algo algo)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range (todo: multiply by algo weight)
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget) {
        return false;
    }

    return true;
}


bool CheckAuxPowProofOfWork(const CBlockHeader& block, const Consensus::Params& params)
{
    Algo algo = block.GetAlgo();
    /*if (block.auxpow || block.IsAuxpow()) {
      LogPrintf("checking auxpowproofofwork for algo %d\n",algo);
      LogPrintf("chain id : %d\n",block.GetChainId());
      }*/

    if (block.nVersion > 3 && block.IsAuxpow() && params.fStrictChainId && block.GetChainId() != params.nAuxpowChainId) {
        LogPrintf("auxpow err 1\n");
        return error("%s : block does not have our chain ID"
                     " (got %d, expected %d, full nVersion %d)",
                     __func__,
                     block.GetChainId(),
                     params.nAuxpowChainId,
                     block.nVersion);
    }

    if (!block.auxpow) {
        if (block.IsAuxpow()) {
            LogPrintf("auxpow err 2\n");
            return error("%s : no auxpow on block with auxpow version",
                         __func__);
        }

        if (!CheckProofOfWork(block.GetPoWHash(algo), block.nBits, params, block.GetAlgo())) {
            LogPrintf("auxpow err 3\n");
            return error("%s : non-AUX proof of work failed", __func__);
        }

        return true;
    }

    if (!block.IsAuxpow()) {
        LogPrintf("auxpow err 4\n");
        return error("%s : auxpow on block with non-auxpow version", __func__);
    }

    if (!block.auxpow->check(block.GetHash(), block.GetChainId())) {
        LogPrintf("auxpow err 5\n");
        return error("%s : AUX POW is not valid", __func__);
    }

    if (false) {  // TODO: fDebug
        arith_uint256 bnTarget;
        bnTarget.SetCompact(block.nBits);
        uint256 target = ArithToUint256(bnTarget);

        LogPrintf("DEBUG: proof-of-work submitted  \n  parent-PoWhash: %s\n  target: %s  bits: %08x \n",
                  block.auxpow->getParentBlockPoWHash(algo).ToString().c_str(),
                  target.GetHex().c_str(),
                  bnTarget.GetCompact());
    }

    if (block.GetAlgo() == Algo::EQUIHASH && !CheckEquihashSolution(&(block.auxpow->parentBlock))) {
        return error("%s : AUX equihash solution failed", __func__);
    }

    if (!CheckProofOfWork(block.auxpow->getParentBlockPoWHash(algo), block.nBits, params, block.GetAlgo())) {
        return error("%s : AUX proof of work failed", __func__);
    }

    return true;
}
