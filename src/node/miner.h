// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MINER_H
#define BITCOIN_NODE_MINER_H

#include <dynamicalgo/solution.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <txmempool.h>

#include <memory>
#include <optional>
#include <stdint.h>

#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/indexed_by.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/tag.hpp>
#include <boost/multi_index_container.hpp>

class ArgsManager;
class CBlockIndex;
class CChainParams;
class CScript;
class Chainstate;
class ChainstateManager;

extern Algo miningAlgo;

namespace Consensus { struct Params; };

namespace node {
static const bool DEFAULT_PRINTPRIORITY = false;
/** Bitmark: default for -signalalgoreadiness (doc/dynamic-algo-mining.md sec 4.5). On,
 *  because a node mining its own template runs the code that appends the coinbase
 *  outputs an activated algo requires, so its readiness is a property of its version. */
static constexpr bool DEFAULT_SIGNAL_ALGO_READINESS{true};

/** Bitmark: default for -maxsolutionverify, the number of mempool solution candidates a
 *  template may run verify() on per slot per ANCHOR EPOCH (~16 min, doc sec 2.1quater
 *  rule 1). One run costs up to ~38 s (doc sec 8.6) and anyone may publish candidates, so
 *  this is the node's exposure to judging them. One is enough for the honest case -- a
 *  dynamic miner broadcasts one solution per epoch -- and a pool with CPU to spare can
 *  raise it to work through rivals faster. Zero disables candidate verification, which
 *  means never mining a solution and always taking the no-solution branch. */
static constexpr int DEFAULT_MAX_SOLUTION_VERIFY{1};

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOpsCost;
    std::vector<unsigned char> vchCoinbaseCommitment;

    /** Bitmark: coinbase outputs a pool MUST append for this template to be valid --
     *  the withheld-fee OP_SOLUTIONPOT output, and (once solutions are selected) the
     *  alpha*r payment to the solution's committed payout. Recorded explicitly rather
     *  than re-derived from the assembled coinbase, because the payout output is an
     *  arbitrary scriptPubKey and so cannot be identified by type.
     *
     *  The assembled template already contains them, so a node mining its own template
     *  needs nothing extra; this list exists to hand the obligation to a pool over GBT,
     *  the same way default_witness_commitment does (doc sec 6bis). `coinbasevalue`
     *  reports only the pool's OWN share, so appending these cannot over-claim. */
    std::vector<CTxOut> vRequiredCoinbaseOutputs;

    /** Bitmark: the VOLUNTARY readiness signal a miner may append to advertise that its
     *  software can add the outputs above (doc sec 4.5). 0-value and unspendable, so it
     *  costs nothing and never enters the UTXO set. Not required, and not included in
     *  the assembled template -- a pool opts in. */
    CTxOut readiness_signal;
};

// Container for tracking updates to ancestor feerate as we include (parent)
// transactions in a block
struct CTxMemPoolModifiedEntry {
    explicit CTxMemPoolModifiedEntry(CTxMemPool::txiter entry)
    {
        iter = entry;
        nSizeWithAncestors = entry->GetSizeWithAncestors();
        nModFeesWithAncestors = entry->GetModFeesWithAncestors();
        nSigOpCostWithAncestors = entry->GetSigOpCostWithAncestors();
    }

    CAmount GetModifiedFee() const { return iter->GetModifiedFee(); }
    uint64_t GetSizeWithAncestors() const { return nSizeWithAncestors; }
    CAmount GetModFeesWithAncestors() const { return nModFeesWithAncestors; }
    size_t GetTxSize() const { return iter->GetTxSize(); }
    const CTransaction& GetTx() const { return iter->GetTx(); }

    CTxMemPool::txiter iter;
    uint64_t nSizeWithAncestors;
    CAmount nModFeesWithAncestors;
    int64_t nSigOpCostWithAncestors;
};

/** Comparator for CTxMemPool::txiter objects.
 *  It simply compares the internal memory address of the CTxMemPoolEntry object
 *  pointed to. This means it has no meaning, and is only useful for using them
 *  as key in other indexes.
 */
struct CompareCTxMemPoolIter {
    bool operator()(const CTxMemPool::txiter& a, const CTxMemPool::txiter& b) const
    {
        return &(*a) < &(*b);
    }
};

struct modifiedentry_iter {
    typedef CTxMemPool::txiter result_type;
    result_type operator() (const CTxMemPoolModifiedEntry &entry) const
    {
        return entry.iter;
    }
};

// A comparator that sorts transactions based on number of ancestors.
// This is sufficient to sort an ancestor package in an order that is valid
// to appear in a block.
struct CompareTxIterByAncestorCount {
    bool operator()(const CTxMemPool::txiter& a, const CTxMemPool::txiter& b) const
    {
        if (a->GetCountWithAncestors() != b->GetCountWithAncestors()) {
            return a->GetCountWithAncestors() < b->GetCountWithAncestors();
        }
        return CompareIteratorByHash()(a, b);
    }
};

typedef boost::multi_index_container<
    CTxMemPoolModifiedEntry,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<
            modifiedentry_iter,
            CompareCTxMemPoolIter
        >,
        // sorted by modified ancestor fee rate
        boost::multi_index::ordered_non_unique<
            // Reuse same tag from CTxMemPool's similar index
            boost::multi_index::tag<ancestor_score>,
            boost::multi_index::identity<CTxMemPoolModifiedEntry>,
            CompareTxMemPoolEntryByAncestorFee
        >
    >
> indexed_modified_transaction_set;

typedef indexed_modified_transaction_set::nth_index<0>::type::iterator modtxiter;
typedef indexed_modified_transaction_set::index<ancestor_score>::type::iterator modtxscoreiter;

struct update_for_parent_inclusion
{
    explicit update_for_parent_inclusion(CTxMemPool::txiter it) : iter(it) {}

    void operator() (CTxMemPoolModifiedEntry &e)
    {
        e.nModFeesWithAncestors -= iter->GetModifiedFee();
        e.nSizeWithAncestors -= iter->GetTxSize();
        e.nSigOpCostWithAncestors -= iter->GetSigOpCost();
    }

    CTxMemPool::txiter iter;
};

/** Generate a new block, without valid proof-of-work */
class BlockAssembler
{
private:
    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    // Information on the current status of the block
    uint64_t nBlockWeight;
    uint64_t nBlockTx;
    uint64_t nBlockSigOpsCost;
    CAmount nFees;
    std::unordered_set<Txid, SaltedTxidHasher> inBlock;

    // Chain context for the block
    int nHeight;
    int64_t m_lock_time_cutoff;

    /** Bitmark: mempool transactions this template must NOT contain. Two kinds:
     *  solution-pot CLAIMS when this block has no valid solution (see ExcludePotClaims),
     *  and solution-bearing txs whose solution is UNJUDGED (doc sec 2.1quater) -- either the per-epoch
     *  verification budget ran out, or a verified-valid candidate was not the one chosen
     *  and no other was. Both would be a hazard if they landed first among the block's
     *  solution-bearing txs: an unjudged solution might verify, and a verified-valid one
     *  certainly does, either way obliging a coinbase payment of alpha*r that this
     *  template did not price. Note what is deliberately ABSENT: a candidate verified and
     *  found NOT to verify is mined like any other tx, for its fee, which is what makes
     *  publishing garbage cost its author something.
     *  Checked in TestPackageTransactions, so a package containing one is skipped whole
     *  and the exclusion covers in-block descendants for free. */
    std::unordered_set<Txid, SaltedTxidHasher> m_exclude;

    /** Bitmark: the mempool solution this template will mine, if any (doc sec 2.1quater).
     *  `alpha_q32`/`beta_q32` come from the verifier run that judged it, so pricing the
     *  coinbase needs no further run. */
    struct SolutionChoice {
        bool have{false};
        CTxMemPool::txiter iter;
        dynamicalgo::BlockSolution sol;
        uint32_t alpha_q32{0};
        uint32_t beta_q32{0};
    };

    const CChainParams& chainparams;
    const CTxMemPool* const m_mempool;
    Chainstate& m_chainstate;

public:
    struct Options {
        // Configuration parameters for the block size
        size_t nBlockMaxWeight{DEFAULT_BLOCK_MAX_WEIGHT};
        CFeeRate blockMinFeeRate{DEFAULT_BLOCK_MIN_TX_FEE};
        // Whether to call TestBlockValidity() at the end of CreateNewBlock().
        bool test_block_validity{true};
        /** Bitmark -signalalgoreadiness: add the voluntary readiness marker to coinbases
         *  this node builds, while the mined slot has no active algo (doc sec 4.5).
         *  ON by default: a node mining its own template runs the code that appends the
         *  outputs an activated algo requires, so its readiness is a property of its
         *  version and it can assert that itself. Set false by an operator who takes the
         *  template but rewrites the coinbase with their own tooling. A pool driving GBT
         *  appends `coinbasesignal` itself and is unaffected either way. */
        bool signal_algo_readiness{DEFAULT_SIGNAL_ALGO_READINESS};
        /** Bitmark -maxsolutionverify: candidate verifier runs per slot per anchor epoch
         *  (doc sec 2.1quater). See DEFAULT_MAX_SOLUTION_VERIFY. */
        int max_solution_verify{DEFAULT_MAX_SOLUTION_VERIFY};
    };

    explicit BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool);
    explicit BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options);

    /** Construct a new block template with coinbase to scriptPubKeyIn */
    std::unique_ptr<CBlockTemplate> CreateNewBlock(const CScript& scriptPubKeyIn, const int32_t nVersionTx = CTransaction::CURRENT_VERSION, const Algo algo = Algo::UNKNOWN, bool mpowValue = false);

    inline static std::optional<int64_t> m_last_block_num_txs{};
    inline static std::optional<int64_t> m_last_block_weight{};

private:
    const Options m_options;

    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();
    /** Add a tx to the block */
    void AddToBlock(CTxMemPool::txiter iter);

    // Methods for how to add transactions to a block.
    /** Add transactions based on feerate including unconfirmed ancestors
      * Increments nPackagesSelected / nDescendantsUpdated with corresponding
      * statistics from the package selection (for logging statistics). */
    void addPackageTxs(const CTxMemPool& mempool, int& nPackagesSelected, int& nDescendantsUpdated) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs);

    // helper functions for addPackageTxs()
    /** Remove confirmed (inBlock) entries from given set */
    void onlyUnconfirmed(CTxMemPool::setEntries& testSet);
    /** Test if a new package would "fit" in the block */
    bool TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const;
    /** Perform checks on each transaction in a package:
      * locktime, premature-witness, serialized size (if necessary)
      * These checks should always succeed, and they're here
      * only as an extra check in case of suboptimal node configuration */
    bool TestPackageTransactions(const CTxMemPool::setEntries& package) const;
    /** Sort the package in an order that is valid to appear in a block */
    void SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries);

    /** Bitmark: choose which mempool solution this block will mine, and record in
     *  m_exclude the candidates that must be kept out (doc sec 2.1quater).
     *
     *  Candidates are tried in descending declared feerate. That ordering is sound only
     *  because a losing candidate is still mined for its fee, so a high declared fee is a
     *  real bid rather than a free bluff. Verdicts are memoized by CONTENT (doc sec 8.9),
     *  so a candidate already judged this epoch costs nothing and a malleated copy of it
     *  is not a new question; only genuinely new content draws on the per-epoch budget.
     *
     *  Among candidates that verify, the winner is the one leaving the miner the largest
     *  share, (1 - alpha). A candidate is taken only if that beats T = beta*(1-alpha0),
     *  what this block would keep with no solution at all -- a scale-free comparison, so
     *  it needs no estimate of the block's eventual fees. */
    void SelectSolution(const CTxMemPool& mempool, const CBlockIndex* prev, Algo algo,
                        uint32_t nbits, const uint256& branch, SolutionChoice& out)
        EXCLUSIVE_LOCKS_REQUIRED(mempool.cs, ::cs_main);

    /** Bitmark: keep solution-pot CLAIMS out of a block that has no valid solution
     *  (doc sec 4.5). A claim releases the whole pot as fee, so its feerate dwarfs
     *  everything else and ordinary selection would take it first -- but it is only valid
     *  in a block whose slot has an active algo AND a valid solution, so including one
     *  otherwise makes the block invalid (solutionpot-claim-nosolution, or
     *  solutionpot-claim-noalgo) and CreateNewBlock would throw rather than return a
     *  template. One relayed claim would otherwise stall every miner that has no solution.
     *
     *  Claims ARE relayable, deliberately: that is what lets anyone build one and have
     *  whichever miner holds a solution collect it, so no node needs to hunt for pots. The
     *  cost of that is this exclusion, which is the miner's own business rather than a
     *  network rule. Shape test first (one 0-value unspendable output, every scriptSig a
     *  lone selector-0 push), so the coin lookups that confirm it only happen for the
     *  handful of transactions that could possibly be claims. */
    void ExcludePotClaims(const CTxMemPool& mempool) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs, ::cs_main);

    /** Bitmark: add the chosen solution tx and its unconfirmed ancestors, BEFORE any
     *  fee-driven selection, so it is the first solution-bearing tx in the block and
     *  therefore the one consensus reads (doc sec 7 step 3) -- and so the block's most
     *  valuable transaction gets first claim on the weight limit. Returns false if the
     *  package does not fit, is not final, or would place another solution-bearing tx
     *  ahead of it (an ancestor carrying one), in which case the caller must fall back to
     *  the no-solution branch rather than mine a block priced for a solution it is not
     *  actually presenting. */
    bool AddSolutionPackage(const CTxMemPool& mempool, CTxMemPool::txiter winner)
        EXCLUSIVE_LOCKS_REQUIRED(mempool.cs);
};

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

/** Update an old GenerateCoinbaseCommitment from CreateNewBlock after the block txs have changed */
void RegenerateCommitments(CBlock& block, ChainstateManager& chainman);

/** Apply -blockmintxfee and -blockmaxweight options from ArgsManager to BlockAssembler options. */
void ApplyArgsManOptions(const ArgsManager& gArgs, BlockAssembler::Options& options);
} // namespace node

#endif // BITCOIN_NODE_MINER_H
