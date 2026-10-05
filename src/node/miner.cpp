// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <logging.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/solver.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <utility>

namespace node {
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(pindexPrev->GetMedianTimePast() + 1, TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams, pblock->GetAlgo());
    }

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

static BlockAssembler::Options ClampOptions(BlockAssembler::Options options)
{
    // Limit weight to between 4K and DEFAULT_BLOCK_MAX_WEIGHT for sanity:
    options.nBlockMaxWeight = std::clamp<size_t>(options.nBlockMaxWeight, 4000, DEFAULT_BLOCK_MAX_WEIGHT);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{mempool},
      m_chainstate{chainstate},
      m_options{ClampOptions(options)}
{
}

void ApplyArgsManOptions(const ArgsManager& args, BlockAssembler::Options& options)
{
    // Block resource limits
    options.nBlockMaxWeight = args.GetIntArg("-blockmaxweight", options.nBlockMaxWeight);
    if (const auto blockmintxfee{args.GetArg("-blockmintxfee")}) {
        if (const auto parsed{ParseMoney(*blockmintxfee)}) options.blockMinFeeRate = CFeeRate{*parsed};
    }
    options.signal_algo_readiness = args.GetBoolArg("-signalalgoreadiness",
                                                    options.signal_algo_readiness);
    options.max_solution_verify = static_cast<int>(
        args.GetIntArg("-maxsolutionverify", options.max_solution_verify));
}
static BlockAssembler::Options ConfiguredOptions()
{
    BlockAssembler::Options options;
    ApplyArgsManOptions(gArgs, options);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool)
    : BlockAssembler(chainstate, mempool, ConfiguredOptions()) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();
    // Bitmark: solution exclusions are decided per template from per-epoch state, so a
    // reused assembler must not inherit the last one's (see m_exclude).
    m_exclude.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

    std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, int32_t nVersionTx, Algo algo, bool mpowValue)
{
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if (!pblocktemplate.get()) {
        return nullptr;
    }
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK(::cs_main);
    CBlockIndex* pindexPrev = m_chainstate.m_chain.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    if (algo == Algo::UNKNOWN)
	algo = miningAlgo;

    //pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    pblock->nVersion = CPureBlockHeader::CURRENT_VERSION;
    bool onMultiPoWFork = nHeight >= 450947;
    // Testnet-only version schedule (NOT regtest -- IsTestChain() would also match
    // regtest and mine version-3 blocks that consensus rejects): v3 for the first
    // 300 blocks, v4 for 301-1000, v5 from 1001 so the PUSHCODE fork can activate.
    if (chainparams.GetChainType() == ChainType::TESTNET) {
	if (nHeight >= 1001) {
	    pblock->nVersion = 5;
	}
	else if (nHeight >= 301) {
	    pblock->nVersion = 4;
	}
	else {
	    pblock->nVersion = 3;
	}
	onMultiPoWFork = nHeight >= 376;
    }
    else if (chainparams.GetChainType() == ChainType::REGTEST) {
	// Regtest activates the Multi-PoW fork at fixed height 750, matching OnFork() for the
	// block being built (nHeight = pindexPrev->nHeight + 1 here). 750 > COINBASE_MATURITY
	// (720) keeps the default test fixtures pre-fork; once functional tests mine past 750
	// the miner sets the algo so multi-algo mining (per-algo v5) works. A fixed height
	// keeps OnFork() O(1) -- see the note in chain.cpp OnFork().
	onMultiPoWFork = nHeight >= 750;
    }

    if (onMultiPoWFork)
	pblock->SetAlgo(algo);

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    if (onMultiPoWFork) {
	CBlockIndex* pprevAlgo = pindexPrev;
	if (pprevAlgo->GetAlgo()!=algo) {
	    pprevAlgo = CBlockIndex::GetPrevAlgoBlockIndex(pindexPrev,algo);
	}
	if (!pprevAlgo) pblock->SetUpdateSSF();
	else {
	    bool update = true;
	    for (int i=0; i<nSSF; i++) {
		if (update_ssf(pprevAlgo->nVersion)) {
		    if (i!=nSSF-1) {
			update = false;
		    }
		    break;
		}
		pprevAlgo = CBlockIndex::GetPrevAlgoBlockIndex(pprevAlgo,Algo::UNKNOWN);
		if (!pprevAlgo) break;
	    }
	    if (update) pblock->SetUpdateSSF();
	}
    }
    
    // Fill in the header BEFORE the coinbase. Both the SSF-scaled subsidy (via the
    // CBlockIndex built from *pblock) and the dynamic-algo reward (which needs nBits to
    // run verify() against the same target consensus will use) read header fields, so
    // computing them against a half-filled header would price the template wrongly.
    // Nothing here depends on vtx[0]; GenerateCoinbaseCommitment, which does, stays
    // below.
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus(), algo);
    pblock->nNonce         = 0;

    if (algo == Algo::EQUIHASH) {
	pblock->nNonce256.SetNull();
	pblock->nSolution.clear();
    }

    // Bitmark: which algo, if any, this slot runs. Needed before transaction selection,
    // because a solution transaction is not an ordinary one: it must be chosen on its
    // alpha rather than its feerate, and must end up FIRST among the block's
    // solution-bearing txs to be the one consensus reads (doc sec 7 step 3, 2.1quater).
    const std::optional<uint256> active_branch{
        m_chainstate.GetActiveAlgoBranch(static_cast<int>(algo))};

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    SolutionChoice solution;
    if (m_mempool) {
        LOCK(m_mempool->cs);
        if (active_branch) {
            SelectSolution(*m_mempool, pindexPrev, algo, pblock->nBits, *active_branch, solution);
            // Added before the fee-driven pass so it leads the block and gets first claim
            // on the weight limit. If it cannot be placed, fall back to no solution rather
            // than price a block for one it is not presenting.
            if (solution.have && !AddSolutionPackage(*m_mempool, solution.iter)) {
                LogPrintf("CreateNewBlock(): chosen solution tx %s could not be placed; "
                          "building the no-solution branch\n",
                          solution.iter->GetSharedTx()->GetHash().ToString());
                solution.have = false;
            }
        }
        addPackageTxs(*m_mempool, nPackagesSelected, nDescendantsUpdated);
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.nVersion = nVersionTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    CAmount coinbase_subsidy;
    if (mpowValue) {
	CBlockIndex indexDummy(*pblock);
	indexDummy.pprev = pindexPrev;
	indexDummy.nHeight = pindexPrev->nHeight+1;
	coinbase_subsidy = GetBlockSubsidy(&indexDummy, chainparams.GetConsensus());
    }
    else
	coinbase_subsidy = GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vout[0].nValue = nFees + coinbase_subsidy;
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;

    // Bitmark: once this slot has an active dynamic algo, S + F is NOT what the coinbase
    // may claim (doc sec 4). With no solution the ceiling is T*S + F and the withheld
    // fees must appear in an OP_SOLUTIONPOT output (sec 4.5); with one, part of the
    // reward is owed to the solution's committed payout. Building S + F regardless would
    // produce blocks this very node rejects -- bad-cb-amount, or
    // solutionpot-coinbase-amount.
    //
    // Either way the split comes from dynamicalgo::ComputeRewardSplit, the SAME pure
    // function ConnectBlock reaches through ResolveAlgoReward, fed the same alpha and beta,
    // so the template cannot be priced against different rules than the ones that will
    // judge it.
    //
    // The voluntary readiness signal (doc sec 4.5), advertising that this miner's
    // software can append the coinbase outputs an activated algo will require.
    //
    // Only once the dynamic-algo FORK is active and while this slot has NO active algo.
    // Before the fork no slot can be activated at all, so there is nothing to be ready
    // for and the marker would be noise in every block ever mined -- including every
    // block the test fixtures build, whose hashes it would change. After the slot is
    // activated the obligation is live, so blocks are simply valid or invalid and the
    // signal says nothing; there is no de-activation path, so it would be permanently
    // pointless block space.
    //
    // Added to the coinbase BY DEFAULT, because a node mining its own template is
    // running the very code that appends those outputs -- its readiness is a property of
    // its version, which it can assert on its own authority. Leaving it opt-in would make
    // coverage systematically under-report and push voters to defer activation
    // needlessly. This does NOT let the node signal on a pool's behalf: a pool driving
    // getblocktemplate builds its own coinbase and discards this one, so the marker only
    // ever rides on blocks the node itself assembles. -signalalgoreadiness=0 opts out,
    // for an operator who takes the node's template but rewrites the coinbase with their
    // own tooling and so cannot honestly make the claim.
    if (!active_branch && DynamicForkActive(pindexPrev, chainparams.GetConsensus())) {
        pblocktemplate->readiness_signal.nValue = 0;
        pblocktemplate->readiness_signal.scriptPubKey = CScript() << OP_RETURN << OP_SOLUTIONPOT;
        if (m_options.signal_algo_readiness) {
            // Costs nothing: 0-value and OP_RETURN-prefixed, so it never enters the UTXO set.
            coinbaseTx.vout.push_back(pblocktemplate->readiness_signal);
        }
    }
    if (active_branch) {
        // ConnectBlock always prices the reward off the SSF-scaled subsidy, so the plan
        // must be fed the same one or the template is priced against a different S.
        // Every real mining caller passes mpowValue=true; the false default is used only
        // by unit tests, which never have an active branch. Asserted rather than assumed
        // silently, since the consequence is an invalid block.
        Assume(mpowValue);
        dynamicalgo::RewardSplit split;
        if (solution.have) {
            // SelectSolution already ran verify() on this candidate, so its alpha and beta
            // are in hand and the split needs no further run -- which matters, because a
            // run can cost ~38 s (doc sec 8.6, 8.9).
            split = dynamicalgo::ComputeRewardSplit(coinbase_subsidy, nFees,
                                                    solution.alpha_q32, solution.beta_q32,
                                                    /*solution_valid=*/true);
        } else {
            // No solution to present. Priced through the shared resolver, which runs the
            // empty solution to read alpha and beta exactly as consensus will (doc sec 7
            // step 4) -- normally a memoized hit, since SelectSolution asked the same
            // question moments ago.
            const dynamicalgo::BlockSolution no_solution{};
            AlgoRewardPlan plan;
            if (!m_chainstate.ResolveAlgoReward(pindexPrev, algo, pblock->nBits, no_solution,
                                                coinbase_subsidy, nFees, active_branch, plan)) {
                // A template we cannot price is one we must not hand out: mining it would
                // either forfeit value or produce an invalid block.
                throw std::runtime_error(strprintf(
                    "CreateNewBlock: cannot resolve the dynamic-algo reward (%s%s)",
                    plan.fail.fatal ? "local fault: " : plan.fail.reject_reason + ": ",
                    plan.fail.err));
            }
            split = plan.split;
        }

        // vout[0] keeps what is left after the obligations below, so a pool reading
        // `coinbasevalue` sees only its OWN share and cannot over-claim by appending them.
        coinbaseTx.vout[0].nValue =
            split.max_coinbase_value - split.required_pot - split.required_payout;
        if (split.required_pot > 0) {
            // The withheld fees, in a pot for this block's own slot. Deferred rather than
            // burned, and claimable by a later solution-bearing block of this slot.
            CTxOut pot;
            pot.nValue = split.required_pot;
            pot.scriptPubKey = SolutionPotScript(static_cast<int>(algo));
            coinbaseTx.vout.push_back(pot);
            // Also recorded for GBT: a pool builds its own coinbase, so the obligation
            // has to be handed over explicitly (doc sec 6bis).
            pblocktemplate->vRequiredCoinbaseOutputs.push_back(pot);
        }
        if (split.required_payout > 0) {
            // alpha*r to the scriptPubKey the solution committed to (doc sec 2.3). The
            // target is the solution's own seq=0 chunk, and the seed binds to it, so this
            // cannot be redirected without invalidating the solution being paid for.
            CTxOut payout;
            payout.nValue = split.required_payout;
            payout.scriptPubKey = CScript(solution.sol.payout.begin(), solution.sol.payout.end());
            coinbaseTx.vout.push_back(payout);
            pblocktemplate->vRequiredCoinbaseOutputs.push_back(payout);
        }
    }

    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);

    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    BlockValidationState state;
    if (m_options.test_block_validity && !TestBlockValidity(state, chainparams, m_chainstate, *pblock, pindexPrev,
                                                            /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
    }
    const auto time_2{SteadyClock::now()};

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start), nPackagesSelected, nDescendantsUpdated,
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count((*iit)->GetSharedTx()->GetHash())) {
            testSet.erase(iit++);
        } else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= m_options.nBlockMaxWeight) {
        return false;
    }
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package) const
{
    for (CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
        // Bitmark: an unjudged solution tx must not reach the block (see m_exclude).
        // Rejecting the whole package rather than the one tx also keeps its in-block
        // descendants out, which a per-tx skip would not.
        if (!m_exclude.empty() && m_exclude.count(it->GetSharedTx()->GetHash())) {
            return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblocktemplate->block.vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter->GetSharedTx()->GetHash());

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee rate %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

/** Add descendants of given transactions to mapModifiedTx with ancestor
 * state updated assuming given transactions are inBlock. Returns number
 * of updated descendants. */
static int UpdatePackagesForAdded(const CTxMemPool& mempool,
                                  const CTxMemPool::setEntries& alreadyAdded,
                                  indexed_modified_transaction_set& mapModifiedTx) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs)
{
    AssertLockHeld(mempool.cs);

    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc)) {
                continue;
            }
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                mit = mapModifiedTx.insert(modEntry).first;
            }
            mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
        }
    }
    return nDescendantsUpdated;
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::SelectSolution(const CTxMemPool& mempool, const CBlockIndex* prev,
                                    Algo algo, uint32_t nbits, const uint256& branch,
                                    SolutionChoice& out)
{
    AssertLockHeld(mempool.cs);
    // Not `out = SolutionChoice{}`: a default-constructed mempool iterator has no
    // defined value, and copying one is undefined even though nobody reads it while
    // `have` is false.
    out.have = false;
    const int slot{static_cast<int>(algo)};

    // The no-solution reference point. Needed to price the coinbase if nothing is chosen
    // (doc sec 7 step 4), and needed here to decide whether a candidate is worth taking at
    // all, so it is not an extra cost. Memoized per epoch, so this is one run per anchor.
    const dynamicalgo::BlockSolution empty{};
    AlgoVerifyResult vr0;
    AlgoFailure fail0;
    if (!m_chainstate.RunAlgoVerifyForBlock(prev, algo, nbits, empty, branch, vr0, fail0)) {
        throw std::runtime_error(strprintf(
            "CreateNewBlock: cannot read the dynamic algo's reward fractions (%s%s)",
            fail0.fatal ? "local fault: " : fail0.reject_reason + ": ", fail0.err));
    }
    // A module that faults on an empty solution states no alpha/beta; consensus prices
    // that as zero (doc sec 7 step 4), and so must we, or the template would not match.
    static constexpr uint64_t Q{uint64_t{1} << 32}; // Q32 one
    const uint64_t a0{vr0.ok ? vr0.alpha_q32 : 0};
    const uint64_t b0{vr0.ok ? vr0.beta_q32 : 0};
    // What this block keeps per unit of r with no solution: T = beta * (1 - alpha).
    const uint64_t keep_without{((Q - a0) * b0) >> 32};

    struct Cand {
        CTxMemPool::txiter iter;
        dynamicalgo::BlockSolution sol;
        CAmount fee;
        int64_t size;
    };
    std::vector<Cand> cands;
    for (auto it{mempool.mapTx.begin()}; it != mempool.mapTx.end(); ++it) {
        if (!dynamicalgo::HasSolutionOutput(it->GetTx())) continue;
        dynamicalgo::BlockSolution sol;
        std::string why_not;
        dynamicalgo::ExtractTxSolution(it->GetTx(), sol, why_not);
        // Malformed, or merely prefix-shaped: consensus would read no solution from it
        // (doc sec 7 step 3), which is exactly how this template prices a block without
        // one. So it is not a candidate and needs no exclusion -- it can be mined for its
        // fee like any other transaction.
        if (!sol.found) continue;
        cands.push_back({mempool.mapTx.iterator_to(*it), std::move(sol),
                         it->GetModFeesWithAncestors(), it->GetSizeWithAncestors()});
    }
    if (cands.empty()) return;

    // Highest declared feerate first (see the header note on why that is a real bid).
    std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
        // a.fee/a.size vs b.fee/b.size, cross-multiplied in double as
        // CompareTxMemPoolEntryByAncestorFee does: the integer product can reach ~8e20
        // and overflow int64. Ties broken by txid so the order is total and deterministic.
        const double lhs{static_cast<double>(a.fee) * static_cast<double>(b.size)};
        const double rhs{static_cast<double>(b.fee) * static_cast<double>(a.size)};
        if (lhs != rhs) return lhs > rhs;
        return a.iter->GetSharedTx()->GetHash() < b.iter->GetSharedTx()->GetHash();
    });

    const CBlockIndex* const anchor_idx{AlgoSeedAnchor(prev, algo)};
    if (!anchor_idx) return; // cannot happen where an algo is active; nothing to spend on
    const uint256 anchor{anchor_idx->GetBlockHash()};

    std::vector<CTxMemPool::txiter> verified_valid;
    uint64_t best_keep{0};
    for (const Cand& c : cands) {
        dynamicalgo::VerifyVerdict v;
        if (!m_chainstate.PeekAlgoVerify(prev, algo, nbits, c.sol, branch, v)) {
            if (!m_chainstate.m_blockman.m_candidate_budget.TrySpend(
                    slot, anchor, m_options.max_solution_verify)) {
                // Out of budget for this epoch: this candidate stays unjudged, so it must
                // not be mined (it might verify, which would oblige an alpha*r payment
                // this template is not making). A later template will judge it.
                m_exclude.insert(c.iter->GetSharedTx()->GetHash());
                continue;
            }
            AlgoVerifyResult vr;
            AlgoFailure fail;
            if (!m_chainstate.RunAlgoVerifyForBlock(prev, algo, nbits, c.sol, branch, vr, fail)) {
                throw std::runtime_error(strprintf(
                    "CreateNewBlock: cannot verify a solution candidate (%s%s)",
                    fail.fatal ? "local fault: " : fail.reject_reason + ": ", fail.err));
            }
            v = dynamicalgo::VerifyVerdict{.ok = vr.ok, .solution_valid = vr.solution_valid,
                                           .out_of_gas = vr.out_of_gas,
                                           .alpha_q32 = vr.alpha_q32, .beta_q32 = vr.beta_q32};
        }
        if (!v.ok || !v.solution_valid) continue; // judged and no good: mine it for its fee
        verified_valid.push_back(c.iter);

        // Taking it leaves (1 - alpha) of r; leaving it leaves T of r. Both are fractions
        // of the same r, so comparing the fractions needs no estimate of the block's
        // fees -- which is useful, since they are not known until selection has run.
        const uint64_t keep_with{Q - v.alpha_q32};
        if (keep_with <= keep_without) continue;
        if (!out.have || keep_with > best_keep) {
            best_keep = keep_with;
            out.have = true;
            out.iter = c.iter;
            out.sol = c.sol;
            out.alpha_q32 = v.alpha_q32;
            out.beta_q32 = v.beta_q32;
        }
    }

    if (!out.have) {
        // Nothing chosen, so no verified-valid candidate may be mined either: whichever
        // landed first would present consensus with a valid solution and oblige the
        // alpha*r payment. (With a winner they are harmless -- it goes in first, so they
        // are never the tx consensus reads, and they still pay their fees.)
        for (const CTxMemPool::txiter& it : verified_valid) {
            m_exclude.insert(it->GetSharedTx()->GetHash());
        }
    }
}

bool BlockAssembler::AddSolutionPackage(const CTxMemPool& mempool, CTxMemPool::txiter winner)
{
    AssertLockHeld(mempool.cs);
    auto ancestors{mempool.AssumeCalculateMemPoolAncestors(
        __func__, *winner, CTxMemPool::Limits::NoLimits(), /*fSearchForParents=*/false)};
    onlyUnconfirmed(ancestors);
    ancestors.insert(winner);

    if (!TestPackage(winner->GetSizeWithAncestors(), winner->GetSigOpCostWithAncestors())) {
        return false;
    }
    if (!TestPackageTransactions(ancestors)) return false;

    std::vector<CTxMemPool::txiter> sorted;
    SortForBlock(ancestors, sorted);
    // An ancestor must precede the winner, so an ancestor carrying solution outputs would
    // be the tx consensus reads instead of it. Checked across the whole package before
    // anything is added, so declining leaves the block untouched.
    for (const CTxMemPool::txiter& it : sorted) {
        if (it != winner && dynamicalgo::HasSolutionOutput(it->GetTx())) return false;
    }
    for (const CTxMemPool::txiter& it : sorted) AddToBlock(it);
    return true;
}

void BlockAssembler::addPackageTxs(const CTxMemPool& mempool, int& nPackagesSelected, int& nDescendantsUpdated)
{
    AssertLockHeld(mempool.cs);

    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    std::set<Txid> failedTx;

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty()) {
        // First try to find a new transaction in mapTx to evaluate.
        //
        // Skip entries in mapTx that are already in a block or are present
        // in mapModifiedTx (which implies that the mapTx ancestor state is
        // stale due to ancestor inclusion in the block)
        // Also skip transactions that we've already failed to add. This can happen if
        // we consider a transaction in mapModifiedTx and it fails: we can then
        // potentially consider it again while walking mapTx.  It's currently
        // guaranteed to fail again, but as a belt-and-suspenders check we put it in
        // failedTx and avoid re-evaluation, since the re-evaluation would be using
        // cached size/sigops/fee values that are not actually correct.
        /** Return true if given transaction from mapTx has already been evaluated,
         * or if the transaction's cached data in mapTx is incorrect. */
        if (mi != mempool.mapTx.get<ancestor_score>().end()) {
            auto it = mempool.mapTx.project<0>(mi);
            assert(it != mempool.mapTx.end());
            if (mapModifiedTx.count(it) || inBlock.count(it->GetSharedTx()->GetHash()) || failedTx.count(it->GetSharedTx()->GetHash())) {
                ++mi;
                continue;
            }
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter->GetSharedTx()->GetHash()));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < m_options.blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter->GetSharedTx()->GetHash());
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    m_options.nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        auto ancestors{mempool.AssumeCalculateMemPoolAncestors(__func__, *iter, CTxMemPool::Limits::NoLimits(), /*fSearchForParents=*/false)};

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter->GetSharedTx()->GetHash());
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

        for (size_t i = 0; i < sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(mempool, ancestors, mapModifiedTx);
    }
}
} // namespace node
