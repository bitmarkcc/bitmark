// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The Solver functions are used by policy and the wallet, but not consensus.

#ifndef BITCOIN_SCRIPT_SOLVER_H
#define BITCOIN_SCRIPT_SOLVER_H

#include <attributes.h>
#include <script/script.h>

#include <string>
#include <optional>
#include <utility>
#include <vector>

class CPubKey;
template <typename C> class Span;

enum class TxoutType {
    NONSTANDARD,
    // 'standard' transaction types:
    PUBKEY,
    PUBKEYHASH,
    SCRIPTHASH,
    MULTISIG,
    NULL_DATA, //!< unspendable OP_RETURN script that carries data
    WITNESS_V0_SCRIPTHASH,
    WITNESS_V0_KEYHASH,
    WITNESS_V1_TAPROOT,
    WITNESS_UNKNOWN, //!< Only for Witness versions not already defined above
    PUSHCODE, //!< Bitmark: OP_RETURN OP_PUSHCODE <up to 5 params>, carries dynamic-algo code (unspendable)
    FEE_VOTE, //!< Bitmark: OP_RETURN OP_VOTE <branch:32> <slot>, a fee-weighted dynamic-algo vote (unspendable)
    STAKE_VOTE, //!< Bitmark: <lock> OP_CSV OP_DROP OP_VOTE <branch:32> OP_DROP <slot> OP_DROP <payout>, a stake-weighted vote (spendable after lock)
    SOLUTION, //!< Bitmark: OP_RETURN OP_SOLUTION <seq> <chunk>, a dynamic-algo solution chunk (unspendable; coinbase or solution-tx)
    RESERVEFEE, //!< Bitmark: <algo> <s0> <refund_pkh> OP_RESERVEFEE, a spendable hashrate-contingent reserve-fee covenant output
    //! Bitmark: the per-slot pot holding fees withheld from no-solution blocks, in two forms:
    //!   <algo+1> OP_SOLUTIONPOT     the real pot -- SPENDABLE, carries value;
    //!                               vSolutions = [algo+1], i.e. 1..NUM_ALGOS
    //!   OP_RETURN OP_SOLUTIONPOT    a miner's VOLUNTARY readiness signal -- 0-value and
    //!                               unspendable, so it never enters the UTXO set;
    //!                               vSolutions = [] (empty)
    //! So a non-empty vSolutions distinguishes a real pot from a signal (equivalently,
    //! CScript::IsUnspendable() is true only for the signal).
    //!
    //! The slot is stored OFF BY ONE, and that is load-bearing rather than a quirk: the
    //! algo push is the LAST item this script leaves on the stack, and a spend only
    //! succeeds if the final stack top is true. A zero-valued push is false, so a 0-based
    //! encoding would make every slot-0 pot permanently unspendable while slots 1..7
    //! worked -- a bug that is invisible until something tries to claim one. Always go
    //! through SolutionPotScript / SolutionPotAlgo below rather than touching the byte.
    //! (OP_RESERVEFEE needs no such trick: its script ends with the 20-byte refund_pkh,
    //! which is truthy, so it stores the slot 0-based. The two differ for that reason.)
    SOLUTIONPOT,
};

/** Bitmark: the canonical scriptPubKey of a real solution pot for `algo` (see
 *  TxoutType::SOLUTIONPOT). Callers must not build this by hand -- the +1 lives here. */
CScript SolutionPotScript(int algo);

/** Bitmark: the slot a SOLUTIONPOT output names, from Solver's vSolutions. Returns false
 *  for the readiness signal (empty vSolutions) and for an out-of-range encoding, which the
 *  matcher accepts but no valid pot can carry -- callers treat that as invalid. */
bool SolutionPotAlgo(const std::vector<std::vector<unsigned char>>& sols, int& algo);

/** Get the name of a TxoutType as a string */
std::string GetTxnOutputType(TxoutType t);

constexpr bool IsPushdataOp(opcodetype opcode)
{
    return opcode > OP_FALSE && opcode <= OP_PUSHDATA4;
}

/**
 * Parse a scriptPubKey and identify script type for standard scripts. If
 * successful, returns script type and parsed pubkeys or hashes, depending on
 * the type. For example, for a P2SH script, vSolutionsRet will contain the
 * script hash, for P2PKH it will contain the key hash, etc.
 *
 * @param[in]   scriptPubKey   Script to parse
 * @param[out]  vSolutionsRet  Vector of parsed pubkeys and hashes
 * @return                     The script type. TxoutType::NONSTANDARD represents a failed solve.
 */
TxoutType Solver(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& vSolutionsRet);

/** Generate a P2PK script for the given pubkey. */
CScript GetScriptForRawPubKey(const CPubKey& pubkey);

/** Determine if script is a "multi_a" script. Returns (threshold, keyspans) if so, and nullopt otherwise.
 *  The keyspans refer to bytes in the passed script. */
std::optional<std::pair<int, std::vector<Span<const unsigned char>>>> MatchMultiA(const CScript& script LIFETIMEBOUND);

/** Generate a multisig script. */
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);

#endif // BITCOIN_SCRIPT_SOLVER_H
