// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <core_io.h>
#include <node/blockstorage.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <pushcodedb.h>
#include <rpc/protocol.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/pushcode.h>
#include <script/script.h>
#include <script/solver.h>
#include <sync.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace {

// Parse an "op" field to its pushtype value: insert=0, replace=1, delete=3
// (delete sets the replace bit too, since a delete is a replace with no code).
uint8_t ParsePushCodePushtype(const std::string& s)
{
    if (s == "insert") return 0;
    if (s == "replace") return 1;
    if (s == "delete") return 3;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "op must be \"insert\", \"replace\", or \"delete\"");
}

// Read a non-negative part index in the CScriptNum int32 range.
uint32_t ParsePartIndex(const UniValue& v, const std::string& name)
{
    const int64_t n = v.getInt<int64_t>();
    if (n < 0 || n > std::numeric_limits<int32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, name + " out of range");
    }
    return static_cast<uint32_t>(n);
}

std::string PushCodeStatusName(PushCodeStatus s)
{
    switch (s) {
    case PushCodeStatus::COMPLETE: return "complete";
    case PushCodeStatus::INCOMPLETE: return "incomplete";
    case PushCodeStatus::INVALID: return "invalid";
    }
    return "unknown";
}

// Add the fields shared by a code entry and a constructed script to a JSON object.
void PushEntryFields(UniValue& o, uint8_t op, bool is_delete, bool has_parent,
                     const uint256& parent, bool has_part, uint32_t part,
                     bool has_part2, uint32_t part2)
{
    o.pushKV("op", is_delete ? "delete" : (op == PUSHCODE_OP_REPLACE ? "replace" : "insert"));
    o.pushKV("is_new", !has_parent);
    if (has_parent) o.pushKV("parent", parent.GetHex());
    if (has_part) o.pushKV("part", (uint64_t)part);
    if (has_part2) o.pushKV("part2", (uint64_t)part2);
}

// Build a PUSHCODE scriptPubKey from a {code, parent?, op?, part?, part2?} object
// (unknown extra keys such as "amount" are ignored), validating against the
// consensus grammar. Fills `parsed` from a Solver+ParsePushCode round-trip, which
// is the final gate. Throws JSONRPCError on any inconsistency.
CScript BuildPushCodeScript(const UniValue& o, PushCodeParams& parsed)
{
    RPCTypeCheckObj(o, {
        {"code", UniValueType(UniValue::VSTR)},
        {"parent", UniValueType(UniValue::VSTR)},
        {"op", UniValueType(UniValue::VSTR)},
        {"part", UniValueType(UniValue::VNUM)},
        {"part2", UniValueType(UniValue::VNUM)},
    }, /*fAllowNull=*/true);

    const UniValue& op_v = o.find_value("op");
    const uint8_t pushtype = op_v.isNull() ? 0 : ParsePushCodePushtype(op_v.get_str());
    const uint8_t op = pushtype & 1;
    const bool is_delete = (pushtype & 2) != 0;

    const UniValue& code_v = o.find_value("code");
    const bool has_code = !code_v.isNull();
    if (has_code && !code_v.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "code must be a hex string");
    }
    const std::string code_str = has_code ? code_v.get_str() : "";
    if (!code_str.empty() && !IsHex(code_str)) { // "" is empty code, not a bad hex string
        throw JSONRPCError(RPC_INVALID_PARAMETER, "code must be a hex string");
    }
    const std::vector<unsigned char> code = ParseHex(code_str);

    const UniValue& parent_v = o.find_value("parent");
    const bool has_parent = !parent_v.isNull();
    uint256 parent;
    if (has_parent) parent = ParseHashV(parent_v, "parent");

    const UniValue& part_v = o.find_value("part");
    const bool has_part = !part_v.isNull();
    const uint32_t part = has_part ? ParsePartIndex(part_v, "part") : 0;

    const UniValue& part2_v = o.find_value("part2");
    const bool has_part2 = !part2_v.isNull();
    const uint32_t part2 = has_part2 ? ParsePartIndex(part2_v, "part2") : 0;

    // Consistency checks (mirroring the consensus grammar) before building.
    if (has_part2 && !has_part) throw JSONRPCError(RPC_INVALID_PARAMETER, "part2 requires part");
    if (has_part2 && part2 < part) throw JSONRPCError(RPC_INVALID_PARAMETER, "part2 must be >= part");
    if (!has_parent) {
        if (pushtype != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "a NEW entry must be an insert (no parent)");
        if (has_part || has_part2) throw JSONRPCError(RPC_INVALID_PARAMETER, "a NEW entry takes no part index");
        if (code.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "a NEW entry needs a non-empty code chunk");
    } else if (is_delete) {
        if (!has_part) throw JSONRPCError(RPC_INVALID_PARAMETER, "delete needs a part (or part range) to remove");
        if (has_code) throw JSONRPCError(RPC_INVALID_PARAMETER, "delete takes no code chunk");
    } else {
        if (has_part2 && op != PUSHCODE_OP_REPLACE) throw JSONRPCError(RPC_INVALID_PARAMETER, "a range (part2) requires op=replace or op=delete");
        if (code.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "insert/replace needs a non-empty code chunk");
    }

    // Build the scriptPubKey: the OP_RETURN OP_PUSHCODE magic prefix (making the
    // output provably unspendable) followed by the params in minimal grammar form,
    // pushing small integers as OP_N (one byte) via the int64_t overload.
    CScript script;
    script << OP_RETURN << OP_PUSHCODE; // magic prefix
    if (!has_parent) {
        script << code; // form 1: NEW [code]
    } else if (is_delete) {
        script << (int64_t)pushtype << ToByteVector(parent) << (int64_t)part; // [pushtype][codehash][nPart]
        if (has_part2) script << (int64_t)part2;                              // [nPart2]
    } else if (op == PUSHCODE_OP_INSERT && !has_part) {
        script << ToByteVector(parent) << code; // form 2: [codehash][code]
    } else {
        script << (int64_t)pushtype << ToByteVector(parent); // form 3: [pushtype][codehash]
        if (has_part) script << (int64_t)part;              // form 4: [nPart]
        if (has_part2) script << (int64_t)part2;            // form 5: [nPart2]
        script << code;
    }

    // Round-trip through the consensus classifier/parser as the final gate.
    std::vector<std::vector<unsigned char>> sol;
    std::string reason;
    if (Solver(script, sol) != TxoutType::PUSHCODE || !ParsePushCode(sol, parsed, reason)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "constructed script is not a valid PUSHCODE output: " + reason);
    }
    return script;
}

} // namespace

static RPCHelpMan createpushcodescript()
{
    return RPCHelpMan{
        "createpushcodescript",
        "\nBuild an OP_PUSHCODE output scriptPubKey from structured parameters and\n"
        "return its hex plus content hash. This does NOT fund, sign, or broadcast a\n"
        "transaction -- drop the returned hex into a raw transaction output (funding\n"
        "is a wallet operation). References are content hashes; the referenced entry\n"
        "need not exist yet (forward references are permitted).\n",
        {
            {"params", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The PUSHCODE parameters",
                {
                    {"code", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The code chunk, in hex (required except for op=delete, which takes no code)"},
                    {"parent", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte content hash of the referenced entry; omit for a NEW (root) entry"},
                    {"op", RPCArg::Type::STR, RPCArg::Default{"insert"}, "\"insert\", \"replace\", or \"delete\" (only meaningful with a parent)"},
                    {"part", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Part index: insert before it, or start of a replace/delete range"},
                    {"part2", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "End of a replace/delete range [part, part2] (requires op=replace/delete and part)"},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The PUSHCODE scriptPubKey"},
                {RPCResult::Type::STR_HEX, "hash", "The content hash of this entry (what a child references)"},
                {RPCResult::Type::STR, "op", "\"insert\", \"replace\", or \"delete\""},
                {RPCResult::Type::BOOL, "is_new", "Whether this is a NEW (root) entry"},
                {RPCResult::Type::STR_HEX, "parent", /*optional=*/true, "The referenced content hash, if any"},
                {RPCResult::Type::NUM, "part", /*optional=*/true, "The part index, if given"},
                {RPCResult::Type::NUM, "part2", /*optional=*/true, "The replace-range end, if given"},
            }
        },
        RPCExamples{
            HelpExampleCli("createpushcodescript", "'{\"code\":\"0102\"}'") +
            HelpExampleCli("createpushcodescript", "'{\"op\":\"insert\",\"parent\":\"aa..\",\"part\":1,\"code\":\"0304\"}'") +
            HelpExampleRpc("createpushcodescript", "{\"code\":\"0102\"}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            PushCodeParams parsed;
            const CScript script = BuildPushCodeScript(request.params[0].get_obj(), parsed);

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", HexStr(script));
            result.pushKV("hash", PushCodeHash(script).GetHex());
            PushEntryFields(result, parsed.op, parsed.is_delete, parsed.has_parent, parsed.parent_hash,
                            parsed.has_part, parsed.nPart, parsed.has_part2, parsed.nPart2);
            return result;
        },
    };
}

static RPCHelpMan getpushcode()
{
    return RPCHelpMan{
        "getpushcode",
        "\nAssemble the code of an OP_PUSHCODE branch tip identified by its content\n"
        "hash: walk the parent chain to the NEW root and replay the insert/replace\n"
        "operations. A missing referenced entry (or a pruned chunk) yields status\n"
        "\"incomplete\"; an out-of-range operation or a blown limit yields \"invalid\".\n",
        {
            {"codehash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte content hash of the branch tip"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "status", "\"complete\", \"incomplete\", or \"invalid\""},
                {RPCResult::Type::STR_HEX, "code", /*optional=*/true, "The assembled code (only when complete)"},
                {RPCResult::Type::NUM, "length", /*optional=*/true, "Assembled code length in bytes (only when complete)"},
                {RPCResult::Type::STR, "reason", /*optional=*/true, "Why assembly did not complete (when not complete)"},
            }
        },
        RPCExamples{
            HelpExampleCli("getpushcode", "\"<codehash>\"") +
            HelpExampleRpc("getpushcode", "\"<codehash>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const uint256 hash = ParseHashV(request.params[0], "codehash");
            ChainstateManager& chainman = EnsureAnyChainman(request.context);

            std::vector<unsigned char> code;
            std::string reason;
            PushCodeStatus status;
            {
                LOCK(cs_main);
                status = chainman.ActiveChainstate().AssemblePushCode(hash, code, reason);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("status", PushCodeStatusName(status));
            if (status == PushCodeStatus::COMPLETE) {
                result.pushKV("code", HexStr(code));
                result.pushKV("length", (uint64_t)code.size());
            } else {
                result.pushKV("reason", reason);
            }
            return result;
        },
    };
}

static RPCHelpMan getpushcodeentry()
{
    return RPCHelpMan{
        "getpushcodeentry",
        "\nReturn the raw code-DB entry for an OP_PUSHCODE content hash (the immutable\n"
        "record stored when the output was confirmed). Use getpushcode to assemble the\n"
        "full branch.\n",
        {
            {"codehash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte content hash of the entry"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "op", "\"insert\", \"replace\", or \"delete\""},
                {RPCResult::Type::BOOL, "is_new", "Whether this is a NEW (root) entry"},
                {RPCResult::Type::STR_HEX, "parent", /*optional=*/true, "The referenced content hash, if any"},
                {RPCResult::Type::NUM, "part", /*optional=*/true, "The part index, if given"},
                {RPCResult::Type::NUM, "part2", /*optional=*/true, "The replace-range end, if given"},
                {RPCResult::Type::NUM, "height", "Canonical (first-appearance) block height of the entry"},
                {RPCResult::Type::NUM, "refcount", "Number of confirmed outputs (copies) backing this content hash"},
                {RPCResult::Type::ARR, "copies", "Each confirmed copy backing this content hash",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "height", "Block height of this copy"},
                                {RPCResult::Type::NUM, "vout", "Output index of the PUSHCODE output in its transaction"},
                            }},
                    }},
            }
        },
        RPCExamples{
            HelpExampleCli("getpushcodeentry", "\"<codehash>\"") +
            HelpExampleRpc("getpushcodeentry", "\"<codehash>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const uint256 hash = ParseHashV(request.params[0], "codehash");
            ChainstateManager& chainman = EnsureAnyChainman(request.context);

            CCodeEntry e;
            {
                LOCK(cs_main);
                const CCodeDB* db = chainman.m_blockman.m_code_db.get();
                if (!db) throw JSONRPCError(RPC_MISC_ERROR, "code DB not available");
                if (!db->ReadEntry(hash, e)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "no PUSHCODE entry with that content hash");
                }
            }

            UniValue result(UniValue::VOBJ);
            PushEntryFields(result, e.op, e.is_delete, e.has_parent, e.parent_hash,
                            e.has_part, e.nPart, e.has_part2, e.nPart2);
            result.pushKV("height", (int64_t)e.Height());
            result.pushKV("refcount", (uint64_t)e.refcount());
            UniValue copies(UniValue::VARR);
            for (const CCodeLocation& loc : e.locations) {
                UniValue c(UniValue::VOBJ);
                c.pushKV("height", (int64_t)loc.height);
                c.pushKV("vout", (uint64_t)loc.vout);
                copies.push_back(c);
            }
            result.pushKV("copies", copies);
            return result;
        },
    };
}

static RPCHelpMan createpushcoderawtransaction()
{
    return RPCHelpMan{
        "createpushcoderawtransaction",
        "\nCreate an unsigned raw transaction spending the given inputs to the given\n"
        "standard outputs PLUS one OP_PUSHCODE output (appended last). Like\n"
        "createrawtransaction, this only serializes the transaction -- it does not\n"
        "sign it, fund it, check its validity, or broadcast it. The caller balances\n"
        "inputs against outputs + the pushcode amount to leave a fee, then signs and\n"
        "sends it.\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The inputs",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'replaceable' and 'locktime' arguments"}, "The sequence number"},
                        }},
                }},
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Standard outputs (address/data), as in createrawtransaction; may be empty ([]).",
                {
                    {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "", {{"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the address, the value (float or string) is the amount in " + CURRENCY_UNIT}}},
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {{"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"data\", the value is hex-encoded data"}}},
                },
                RPCArgOptions{.skip_type_check = true}},
            {"pushcode", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The OP_PUSHCODE output to append",
                {
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Default{0}, "The value of the pushcode output in " + CURRENCY_UNIT + ". The output is provably unspendable (OP_RETURN), so any value here is BURNED; leave it 0."},
                    {"code", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The code chunk, in hex (required except for op=delete)"},
                    {"parent", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte content hash of the referenced entry; omit for a NEW (root) entry"},
                    {"op", RPCArg::Type::STR, RPCArg::Default{"insert"}, "\"insert\", \"replace\", or \"delete\""},
                    {"part", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Part index"},
                    {"part2", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "End of a replace/delete range"},
                }},
            {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
            {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Marks this transaction as BIP125-replaceable"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "transaction", "hex string of the transaction"},
        RPCExamples{
            HelpExampleCli("createpushcoderawtransaction", "'[{\"txid\":\"myid\",\"vout\":0}]' '[]' '{\"amount\":0.01,\"code\":\"0102\"}'") +
            HelpExampleRpc("createpushcoderawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[]\", \"{\\\"amount\\\":0.01,\\\"code\\\":\\\"0102\\\"}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::optional<bool> rbf;
            if (!request.params[4].isNull()) rbf = request.params[4].get_bool();
            CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[3], rbf);

            const UniValue& pc = request.params[2].get_obj();
            const UniValue& amount_v = pc.find_value("amount");
            const CAmount amount = amount_v.isNull() ? 0 : AmountFromValue(amount_v);
            PushCodeParams parsed;
            const CScript script = BuildPushCodeScript(pc, parsed);
            rawTx.vout.emplace_back(amount, script);

            return EncodeHexTx(CTransaction(rawTx));
        },
    };
}

void RegisterPushCodeRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"op_pushcode", &createpushcodescript},
        {"op_pushcode", &createpushcoderawtransaction},
        {"op_pushcode", &getpushcode},
        {"op_pushcode", &getpushcodeentry},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
