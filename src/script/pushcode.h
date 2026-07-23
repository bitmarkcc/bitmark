// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_PUSHCODE_H
#define BITCOIN_SCRIPT_PUSHCODE_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class CTransaction;

/** Structured params of a valid PUSHCODE output (filled by ParsePushCode). The
 *  code chunk itself is solutions.back() and is not copied here. */
struct PushCodeParams {
    uint8_t op{0};            // low bit of pushtype: 0 INSERT, 1 REPLACE
    bool has_parent{false};   // false only for a NEW root entry
    uint256 parent_hash;      // content hash of the referenced entry (if has_parent)
    bool has_part{false};
    uint32_t nPart{0};
    bool has_part2{false};
    uint32_t nPart2{0};
};

// OP_PUSHCODE consensus grammar (Bitmark). A PUSHCODE output classified by
// Solver() as TxoutType::PUSHCODE carries 1..5 push params; the last is always
// the code chunk, and a referenced entry is a single 32-byte content hash
// (Hash() of the referenced scriptPubKey), not a txid+nOutput outpoint.
//
// Forms by param count:
//   1: [code]                                     NEW branch (root, no parent)
//   2: [codehash][code]                           INSERT code at end of branch
//   3: [pushtype][codehash][code]                 op on branch, at end
//   4: [pushtype][codehash][nPart][code]          op at part index nPart
//   5: [pushtype][codehash][nPart][nPart2][code]  REPLACE range [nPart,nPart2]
// pushtype low bit: 0 = INSERT, 1 = REPLACE (empty code on REPLACE = delete).
//
// These functions validate STRUCTURE, sizes and consistency only (phase 3a).
// Reference resolution (the content hash must name a confirmed entry) and code
// assembly / MAX_PUSHCODE_* limits are separate (phases 3b/3c).

/** Validate one PUSHCODE output's params (Solver's vSolutions) AND extract them
 *  into `out`. Returns true if valid; on false, `reason` is a reject reason. */
bool ParsePushCode(const std::vector<std::vector<unsigned char>>& solutions,
                   PushCodeParams& out, std::string& reason);

/** Validate one PUSHCODE output's params (grammar only). Returns true if valid;
 *  on false, `reason` is set to a consensus reject reason string. */
bool CheckPushCodeGrammar(const std::vector<std::vector<unsigned char>>& solutions,
                          std::string& reason);

/** Validate every OP_PUSHCODE output of a transaction (grammar only). Returns
 *  true if all are valid (or none are PUSHCODE); on false, `reason` is set. */
bool CheckPushCodeOutputs(const CTransaction& tx, std::string& reason);

#endif // BITCOIN_SCRIPT_PUSHCODE_H
