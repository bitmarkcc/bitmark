// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <span.h>

#include <algorithm>
#include <cassert>
#include <string>

typedef std::vector<unsigned char> valtype;

std::string GetTxnOutputType(TxoutType t)
{
    switch (t) {
    case TxoutType::NONSTANDARD: return "nonstandard";
    case TxoutType::PUBKEY: return "pubkey";
    case TxoutType::PUBKEYHASH: return "pubkeyhash";
    case TxoutType::SCRIPTHASH: return "scripthash";
    case TxoutType::MULTISIG: return "multisig";
    case TxoutType::NULL_DATA: return "nulldata";
    case TxoutType::WITNESS_V0_KEYHASH: return "witness_v0_keyhash";
    case TxoutType::WITNESS_V0_SCRIPTHASH: return "witness_v0_scripthash";
    case TxoutType::WITNESS_V1_TAPROOT: return "witness_v1_taproot";
    case TxoutType::WITNESS_UNKNOWN: return "witness_unknown";
    case TxoutType::PUSHCODE: return "pushcode";
    case TxoutType::FEE_VOTE: return "fee_vote";
    case TxoutType::STAKE_VOTE: return "stake_vote";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

static bool MatchPayToPubkey(const CScript& script, valtype& pubkey)
{
    if (script.size() == CPubKey::SIZE + 2 && script[0] == CPubKey::SIZE && script.back() == OP_CHECKSIG) {
        pubkey = valtype(script.begin() + 1, script.begin() + CPubKey::SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    if (script.size() == CPubKey::COMPRESSED_SIZE + 2 && script[0] == CPubKey::COMPRESSED_SIZE && script.back() == OP_CHECKSIG) {
        pubkey = valtype(script.begin() + 1, script.begin() + CPubKey::COMPRESSED_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    return false;
}

static bool MatchPayToPubkeyHash(const CScript& script, valtype& pubkeyhash)
{
    if (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 20 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
        pubkeyhash = valtype(script.begin () + 3, script.begin() + 23);
        return true;
    }
    return false;
}

/** Test for "small positive integer" script opcodes - OP_1 through OP_16. */
static constexpr bool IsSmallInteger(opcodetype opcode)
{
    return opcode >= OP_1 && opcode <= OP_16;
}

/** Retrieve a minimally-encoded number in range [min,max] from an (opcode, data) pair,
 *  whether it's OP_n or through a push. */
static std::optional<int> GetScriptNumber(opcodetype opcode, valtype data, int min, int max)
{
    int count;
    if (IsSmallInteger(opcode)) {
        count = CScript::DecodeOP_N(opcode);
    } else if (IsPushdataOp(opcode)) {
        if (!CheckMinimalPush(data, opcode)) return {};
        try {
            count = CScriptNum(data, /* fRequireMinimal = */ true).getint();
        } catch (const scriptnum_error&) {
            return {};
        }
    } else {
        return {};
    }
    if (count < min || count > max) return {};
    return count;
}

static bool MatchMultisig(const CScript& script, int& required_sigs, std::vector<valtype>& pubkeys)
{
    opcodetype opcode;
    valtype data;

    CScript::const_iterator it = script.begin();
    if (script.size() < 1 || script.back() != OP_CHECKMULTISIG) return false;

    if (!script.GetOp(it, opcode, data)) return false;
    auto req_sigs = GetScriptNumber(opcode, data, 1, MAX_PUBKEYS_PER_MULTISIG);
    if (!req_sigs) return false;
    required_sigs = *req_sigs;
    while (script.GetOp(it, opcode, data) && CPubKey::ValidSize(data)) {
        pubkeys.emplace_back(std::move(data));
    }
    auto num_keys = GetScriptNumber(opcode, data, required_sigs, MAX_PUBKEYS_PER_MULTISIG);
    if (!num_keys) return false;
    if (pubkeys.size() != static_cast<unsigned long>(*num_keys)) return false;

    return (it + 1 == script.end());
}

std::optional<std::pair<int, std::vector<Span<const unsigned char>>>> MatchMultiA(const CScript& script)
{
    std::vector<Span<const unsigned char>> keyspans;

    // Redundant, but very fast and selective test.
    if (script.size() == 0 || script[0] != 32 || script.back() != OP_NUMEQUAL) return {};

    // Parse keys
    auto it = script.begin();
    while (script.end() - it >= 34) {
        if (*it != 32) return {};
        ++it;
        keyspans.emplace_back(&*it, 32);
        it += 32;
        if (*it != (keyspans.size() == 1 ? OP_CHECKSIG : OP_CHECKSIGADD)) return {};
        ++it;
    }
    if (keyspans.size() == 0 || keyspans.size() > MAX_PUBKEYS_PER_MULTI_A) return {};

    // Parse threshold.
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(it, opcode, data)) return {};
    if (it == script.end()) return {};
    if (*it != OP_NUMEQUAL) return {};
    ++it;
    if (it != script.end()) return {};
    auto threshold = GetScriptNumber(opcode, data, 1, (int)keyspans.size());
    if (!threshold) return {};

    // Construct result.
    return std::pair{*threshold, std::move(keyspans)};
}

// Bitmark: match a PUSHCODE output. The script is a provably-unspendable
// OP_RETURN carrying a 2-byte protocol-magic prefix (OP_RETURN OP_PUSHCODE)
// followed by 1..5 push params. Data pushes become their bytes; small integers
// (OP_0, OP_1..OP_16) become a single byte holding 0..16, matching the dev2024
// param decoding. Maximal form:
//   OP_RETURN OP_PUSHCODE <pushtype> <codehash(32B)> <nPart> <nPart2> <code>
// This is 5 params, down from dev2024's 6, because a referenced entry is now
// identified by a single 32-byte content hash instead of a (txid, nOutput) pair.
// The leading OP_RETURN makes the output unspendable (no UTXO, dust-exempt), and
// OP_PUSHCODE as the magic byte distinguishes it from a plain nulldata output.
static const unsigned int MAX_PUSHCODE_PARAMS = 5;
static bool MatchPushCode(const CScript& script, std::vector<valtype>& params)
{
    params.clear();
    CScript::const_iterator it = script.begin();
    opcodetype opcode;
    valtype vch;
    // Require the OP_RETURN OP_PUSHCODE magic prefix.
    if (!script.GetOp(it, opcode, vch) || opcode != OP_RETURN) return false;
    if (!script.GetOp(it, opcode, vch) || opcode != OP_PUSHCODE) return false;
    // Everything after the prefix is params (pushes / small integers), 1..5 of them.
    while (it < script.end()) {
        if (!script.GetOp(it, opcode, vch)) return false;
        if (params.size() >= MAX_PUSHCODE_PARAMS) return false;
        if (!vch.empty()) {
            params.push_back(std::move(vch));
        } else if (opcode == OP_0) {
            params.push_back(valtype(1, 0));
        } else if (opcode >= OP_1 && opcode <= OP_16) {
            params.push_back(valtype(1, (unsigned char)(opcode - OP_RESERVED)));
        } else {
            return false; // only pushes / small integers are valid params
        }
    }
    return !params.empty(); // at least one param (the code chunk, or a delete range)
}

// Decode one pushed value that is a small number: a data push of <= max_bytes, or
// a small-int opcode (OP_0 / OP_1..OP_16). Normalizes to a byte vector holding the
// value's little-endian bytes (as MatchPushCode does for params).
static bool NextNum(const CScript& s, CScript::const_iterator& it, unsigned max_bytes, valtype& out)
{
    opcodetype opcode;
    valtype vch;
    if (!s.GetOp(it, opcode, vch)) return false;
    if (!vch.empty()) {
        if (vch.size() > max_bytes) return false;
        out = std::move(vch);
    } else if (opcode == OP_0) {
        out = valtype();
    } else if (opcode >= OP_1 && opcode <= OP_16) {
        out = valtype(1, (unsigned char)(opcode - OP_RESERVED));
    } else {
        return false;
    }
    return true;
}

static bool NextOp(const CScript& s, CScript::const_iterator& it, opcodetype want)
{
    opcodetype opcode;
    valtype vch;
    return s.GetOp(it, opcode, vch) && opcode == want;
}

// Bitmark FEE_VOTE: OP_RETURN OP_VOTE <branch:32> <slot>, unspendable. Its
// (fee-based) weight comes from the transaction, not the output; the output just
// declares the vote. vSolutions = [branch(32), slot(<=1 byte)].
static bool MatchFeeVote(const CScript& script, std::vector<valtype>& sols)
{
    sols.clear();
    CScript::const_iterator it = script.begin();
    if (!NextOp(script, it, OP_RETURN)) return false;
    if (!NextOp(script, it, OP_VOTE)) return false;
    opcodetype opcode; valtype branch;
    if (!script.GetOp(it, opcode, branch) || branch.size() != 32) return false;
    valtype slot;
    if (!NextNum(script, it, 1, slot)) return false;
    if (it != script.end()) return false;
    sols.push_back(std::move(branch));
    sols.push_back(std::move(slot));
    return true;
}

// Bitmark STAKE_VOTE: a spendable, CSV-timelocked output that self-describes the
// vote:  <lock> OP_CSV OP_DROP OP_VOTE <branch:32> OP_DROP <slot> OP_DROP <payout>.
// Its (stake-based) weight is the output's value (counted when lock >= the voting
// period). vSolutions = [branch(32), slot(<=1 byte), lock(<=5 bytes), payout].
static bool MatchStakeVote(const CScript& script, std::vector<valtype>& sols)
{
    sols.clear();
    CScript::const_iterator it = script.begin();
    valtype lock;
    if (!NextNum(script, it, 5, lock)) return false;              // <lock>
    if (!NextOp(script, it, OP_CHECKSEQUENCEVERIFY)) return false;
    if (!NextOp(script, it, OP_DROP)) return false;
    if (!NextOp(script, it, OP_VOTE)) return false;
    opcodetype opcode; valtype branch;
    if (!script.GetOp(it, opcode, branch) || branch.size() != 32) return false; // <branch:32>
    if (!NextOp(script, it, OP_DROP)) return false;
    valtype slot;
    if (!NextNum(script, it, 1, slot)) return false;             // <slot>
    if (!NextOp(script, it, OP_DROP)) return false;
    if (it >= script.end()) return false;                        // <payout> (non-empty)
    valtype payout(it, script.end());
    sols.push_back(std::move(branch));
    sols.push_back(std::move(slot));
    sols.push_back(std::move(lock));
    sols.push_back(std::move(payout));
    return true;
}

TxoutType Solver(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& vSolutionsRet)
{
    vSolutionsRet.clear();

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return TxoutType::SCRIPTHASH;
    }

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_KEYHASH_SIZE) {
            vSolutionsRet.push_back(std::move(witnessprogram));
            return TxoutType::WITNESS_V0_KEYHASH;
        }
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            vSolutionsRet.push_back(std::move(witnessprogram));
            return TxoutType::WITNESS_V0_SCRIPTHASH;
        }
        if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE) {
            vSolutionsRet.push_back(std::move(witnessprogram));
            return TxoutType::WITNESS_V1_TAPROOT;
        }
        if (witnessversion != 0) {
            vSolutionsRet.push_back(std::vector<unsigned char>{(unsigned char)witnessversion});
            vSolutionsRet.push_back(std::move(witnessprogram));
            return TxoutType::WITNESS_UNKNOWN;
        }
        return TxoutType::NONSTANDARD;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        return TxoutType::NULL_DATA;
    }

    std::vector<unsigned char> data;
    if (MatchPayToPubkey(scriptPubKey, data)) {
        vSolutionsRet.push_back(std::move(data));
        return TxoutType::PUBKEY;
    }

    if (MatchPayToPubkeyHash(scriptPubKey, data)) {
        vSolutionsRet.push_back(std::move(data));
        return TxoutType::PUBKEYHASH;
    }

    int required;
    std::vector<std::vector<unsigned char>> keys;
    if (MatchMultisig(scriptPubKey, required, keys)) {
        vSolutionsRet.push_back({static_cast<unsigned char>(required)}); // safe as required is in range 1..20
        vSolutionsRet.insert(vSolutionsRet.end(), keys.begin(), keys.end());
        vSolutionsRet.push_back({static_cast<unsigned char>(keys.size())}); // safe as size is in range 1..20
        return TxoutType::MULTISIG;
    }

    std::vector<valtype> params;
    if (MatchPushCode(scriptPubKey, params)) {
        vSolutionsRet = std::move(params);
        return TxoutType::PUSHCODE;
    }
    if (MatchFeeVote(scriptPubKey, params)) {
        vSolutionsRet = std::move(params);
        return TxoutType::FEE_VOTE;
    }
    if (MatchStakeVote(scriptPubKey, params)) {
        vSolutionsRet = std::move(params);
        return TxoutType::STAKE_VOTE;
    }

    vSolutionsRet.clear();
    return TxoutType::NONSTANDARD;
}

CScript GetScriptForRawPubKey(const CPubKey& pubKey)
{
    return CScript() << std::vector<unsigned char>(pubKey.begin(), pubKey.end()) << OP_CHECKSIG;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    CScript script;

    script << nRequired;
    for (const CPubKey& key : keys)
        script << ToByteVector(key);
    script << keys.size() << OP_CHECKMULTISIG;

    return script;
}
