// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/pushcode.h>

#include <primitives/transaction.h>
#include <script/script.h>   // CScriptNum, scriptnum_error
#include <script/solver.h>   // Solver, TxoutType

#include <cstdint>

namespace {
// Decode a PUSHCODE numeric param (pushtype / nPart / nPart2). These live on the
// script stack as CScriptNum (little-endian sign-magnitude, no length prefix --
// distinct from CompactSize), so <=4 bytes is the full int32 range. Not required
// to be minimally encoded, since MatchPushCode emits OP_0 as a 1-byte {0x00}.
bool DecodePushCodeNum(const std::vector<unsigned char>& vch, int64_t& out)
{
    if (vch.size() > 4) return false;
    try {
        out = CScriptNum(vch, /*fRequireMinimal=*/false, /*nMaxNumSize=*/4).getint();
    } catch (const scriptnum_error&) {
        return false;
    }
    return true;
}
} // namespace

bool ParsePushCode(const std::vector<std::vector<unsigned char>>& sol,
                   PushCodeParams& out, std::string& reason)
{
    out = PushCodeParams{};
    const size_t n = sol.size();
    if (n < 1 || n > 5) { reason = "bad-pushcode-nparams"; return false; }
    const std::vector<unsigned char>& code = sol.back();

    // NEW (n==1): a root entry that seeds a branch; it needs an initial chunk.
    if (n == 1) {
        if (code.empty()) { reason = "bad-pushcode-empty"; return false; }
        return true; // op INSERT, no parent, no parts
    }

    // n>=2: a reference form. The content hash lives at index 0 (n==2) or 1.
    const size_t hash_idx = (n == 2) ? 0 : 1;
    if (sol[hash_idx].size() != 32) { reason = "bad-pushcode-codehash"; return false; }
    out.has_parent = true;
    out.parent_hash = uint256(sol[hash_idx]);

    int64_t pushtype = 0; // n==2 has no explicit pushtype => INSERT
    if (n >= 3) {
        if (!DecodePushCodeNum(sol[0], pushtype) || pushtype < 0) {
            reason = "bad-pushcode-pushtype"; return false;
        }
    }
    out.op = static_cast<uint8_t>(pushtype & 1);
    out.is_delete = (pushtype & 2) != 0;
    const bool is_delete = out.is_delete;
    const bool is_replace = out.op != 0;

    // DELETE (pushtype bit 1) is a REPLACE with no replacement: it carries NO code
    // param, so the trailing pushes are the part range being removed. Forms:
    //   n==3: [pushtype][codehash][nPart]           delete single part nPart
    //   n==4: [pushtype][codehash][nPart][nPart2]   delete range [nPart, nPart2]
    if (out.is_delete) {
        if (!is_replace) { reason = "bad-pushcode-delete-requires-replace"; return false; }
        if (n < 3 || n > 4) { reason = "bad-pushcode-delete-nparams"; return false; }
        int64_t nPart = 0;
        if (!DecodePushCodeNum(sol[2], nPart) || nPart < 0) { reason = "bad-pushcode-npart"; return false; }
        out.has_part = true;
        out.nPart = static_cast<uint32_t>(nPart);
        if (n == 4) {
            int64_t nPart2 = 0;
            if (!DecodePushCodeNum(sol[3], nPart2) || nPart2 < 0) { reason = "bad-pushcode-npart2"; return false; }
            if (nPart2 < nPart) { reason = "bad-pushcode-range"; return false; }
            out.has_part2 = true;
            out.nPart2 = static_cast<uint32_t>(nPart2);
        }
        return true; // no code chunk for a delete
    }

    int64_t nPart = 0, nPart2 = 0;
    if (n >= 4) {
        if (!DecodePushCodeNum(sol[2], nPart) || nPart < 0) {
            reason = "bad-pushcode-npart"; return false;
        }
        out.has_part = true;
        out.nPart = static_cast<uint32_t>(nPart);
    }
    if (n == 5) {
        if (!DecodePushCodeNum(sol[3], nPart2) || nPart2 < 0) {
            reason = "bad-pushcode-npart2"; return false;
        }
        if (!is_replace) { reason = "bad-pushcode-range-insert"; return false; } // range => REPLACE
        if (nPart2 < nPart) { reason = "bad-pushcode-range"; return false; }
        out.has_part2 = true;
        out.nPart2 = static_cast<uint32_t>(nPart2);
    }

    // A non-delete op must carry a real code chunk: removal is expressed only via
    // the DELETE bit (which returned above with no code), never via an empty chunk
    // -- and an empty final push isn't even representable (it encodes as OP_0 =>
    // {0x00}), so this also guards that.
    if (!is_delete && code.empty()) { reason = "bad-pushcode-empty"; return false; }
    return true;
}

bool CheckPushCodeGrammar(const std::vector<std::vector<unsigned char>>& sol,
                          std::string& reason)
{
    PushCodeParams parsed;
    return ParsePushCode(sol, parsed, reason);
}

bool CheckPushCodeOutputs(const CTransaction& tx, std::string& reason)
{
    for (const CTxOut& out : tx.vout) {
        std::vector<std::vector<unsigned char>> sol;
        if (Solver(out.scriptPubKey, sol) != TxoutType::PUSHCODE) continue;
        if (!CheckPushCodeGrammar(sol, reason)) return false;
    }
    return true;
}
