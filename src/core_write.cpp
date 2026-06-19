// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>

#include <base38.h>
#include <base82.h>
#include <common/system.h>
#include <crypto/sha256.h>
#include <crypto/sha512.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <streams.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <map>
#include <string>
#include <vector>

UniValue ValueFromAmount(const CAmount amount)
{
    static_assert(COIN > 1);
    int64_t quotient = amount / COIN;
    int64_t remainder = amount % COIN;
    if (amount < 0) {
        quotient = -quotient;
        remainder = -remainder;
    }
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", amount < 0 ? "-" : "", quotient, remainder));
}

std::string FormatScript(const CScript& script)
{
    std::string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        std::vector<unsigned char> vch;
        if (script.GetOp(it, op, vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            } else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } else if (op >= OP_NOP && op <= OP_NOP10) {
                std::string str(GetOpName(op));
                if (str.substr(0, 3) == std::string("OP_")) {
                    ret += str.substr(3, std::string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(std::vector<uint8_t>(it2, it - vch.size())),
                                               HexStr(std::vector<uint8_t>(it - vch.size(), it)));
            } else {
                ret += strprintf("0x%x ", HexStr(std::vector<uint8_t>(it2, it)));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(std::vector<uint8_t>(it2, script.end())));
        break;
    }
    return ret.substr(0, ret.empty() ? ret.npos : ret.size() - 1);
}

const std::map<unsigned char, std::string> mapSigHashTypes = {
    {static_cast<unsigned char>(SIGHASH_ALL), std::string("ALL")},
    {static_cast<unsigned char>(SIGHASH_ALL|SIGHASH_ANYONECANPAY), std::string("ALL|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_NONE), std::string("NONE")},
    {static_cast<unsigned char>(SIGHASH_NONE|SIGHASH_ANYONECANPAY), std::string("NONE|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_SINGLE), std::string("SINGLE")},
    {static_cast<unsigned char>(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), std::string("SINGLE|ANYONECANPAY")},
};

std::string SighashToStr(unsigned char sighash_type)
{
    const auto& it = mapSigHashTypes.find(sighash_type);
    if (it == mapSigHashTypes.end()) return "";
    return it->second;
}

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash types on data within the script that matches the format
 *                                     of a signature. Only pass true for scripts you believe could contain signatures. For example,
 *                                     pass false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
std::string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode)
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<std::vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            } else {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    std::string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, nullptr)) {
                        const unsigned char chSigHashType = vch.back();
                        const auto it = mapSigHashTypes.find(chSigHashType);
                        if (it != mapSigHashTypes.end()) {
                            strSigHashDecode = "[" + it->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                } else {
                    str += HexStr(vch);
                }
            }
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}

std::string EncodeHexTx(const CTransaction& tx)
{
    DataStream ssTx;
    ssTx << TX_WITH_WITNESS(tx);
    return HexStr(ssTx);
}

bool ExtractMarking(const CScript& scriptPubKey, const TxoutType type, UniValue& marking)
{
    if (type == TxoutType::NULL_DATA) {
	std::string data = HexStr(scriptPubKey);
	marking.pushKV("data",data.substr(4));
	return true;
    }
    else if (type == TxoutType::MULTISIG) {
	std::string d1name;
	size_t iPK = 0;
	size_t nPubkey = 0;
	size_t nSigkey = 0;
	size_t keyPos = 1; // byte offset past OP_1
	while (iPK < 3) {
	    int ipk = 0;
	    int pk1len = scriptPubKey[keyPos];
	    std::string d1name;
	    char d1prefix = scriptPubKey[keyPos+1];
	    char d1code = scriptPubKey[keyPos+2];
	    if (d1code == 'h' && d1prefix == 6) {
		d1name = "hash";
	    }
	    else if (d1code == 'l' && d1prefix == 6) {
		d1name = "link";
	    }
	    else if (d1code == 'd' && d1prefix == 6) {
		d1name = "desc";
	    }
	    else if (nSigkey == 0 && d1prefix == 7) {
		d1name = "sig";
		nSigkey++;
	    }
	    else if (nSigkey == 1 && (d1prefix == 3 || d1prefix == 7)) {
		d1name = "sighash";
		nSigkey++;
	    }
	    else {
		if (nPubkey==2)
		    d1name = "pubkey3";
		else if (nPubkey == 1)
		    d1name = "pubkey2";
		else
		    d1name = "pubkey";
		nPubkey++;
	    }
	    if (d1name.find("pubkey") != 0 && d1name.find("sig") != 0) {
		while (ipk < 65) {
		    unsigned char d11Code = scriptPubKey[keyPos+3+ipk];
		    if (d11Code == 0) {
			ipk = 65;
			continue;
		    }
		    ipk++;
		    unsigned char d11Len = 0;
		    int rem = d11Code % 16;
		    int i = 0;
		    std::string d11name;
		    if (rem == 0) {
			while (d11Code > 15)
			    d11Code >>= 4;
			d11Len = scriptPubKey[keyPos+3+ipk];
			ipk++;
			i = keyPos + 3 + ipk;
		    }
		    else {
			while (d11Code > 15)
			    d11Code >>= 4;
			d11Len = rem;
			i = keyPos + 3 + ipk;
		    }
		    if (!d1name.compare("hash")) {
			if (d11Code == 1) {
			    d11name = "hash type";
			}
			else if (d11Code == 2) {
			    d11name = "hash hex";
			}
		    }
		    else if (!d1name.compare("link")) {
			if (d11Code == 1) {
			    d11name = "link protocol";
			}
			else if (d11Code == 2) {
			    d11name = "link host";
			}
			else if (d11Code == 3) {
			    d11name = "link port";
			}
			else if (d11Code == 4) {
			    d11name = "link path";
			}
			else if (d11Code == 5) {
			    d11name = "link cert hash type";
			}
			else if (d11Code == 6) {
			    d11name = "link cert hash hex";
			}
		    }
		    else if (!d1name.compare("desc")) {
			if (d11Code == 1) {
			    d11name = "desc language";
			}
			else if (d11Code == 2) {
			    d11name = "desc text";
			}	    
		    }
		    std::vector<unsigned char> d11value;
		    if (ipk+d11Len<65) {
			for (int j=i; j<i+d11Len; j++) {
			    d11value.push_back(scriptPubKey[j]);
			}
			ipk += d11Len;
			std::string sd11value;
			if (d11name.find("link path") != std::string::npos) {
			    sd11value = EncodeBase82(d11value);
			}
			else if (d11name.find("hex") == std::string::npos) {
			    sd11value = EncodeBase38(d11value);
			}
			else {
			    sd11value = HexStr(d11value);
			}
			marking.pushKV(d11name,sd11value);
		    }
		    else {
			ipk = 65;
		    }
		}
	    }
	    if (d1name.find("pubkey") == 0) {
		std::vector<unsigned char> pubkey;
		for (size_t j=keyPos+1; j<keyPos+1+pk1len; j++) {
		    pubkey.push_back(scriptPubKey[j]);
		}
		marking.pushKV(d1name,HexStr(pubkey));
	    }
	    else if (d1name.find("sig") == 0) {
		std::vector<unsigned char> sigkey;
		for (size_t j=keyPos+2; j<keyPos+1+pk1len; j++) {
		    sigkey.push_back(scriptPubKey[j]);
		}
		marking.pushKV(d1name,HexStr(sigkey));
	    }
	    keyPos += 1 + pk1len; // advance past length byte + key data
	    iPK++;
	}
	// Collect the 0x06-prefixed keys (marking data) and hash them
	std::vector<unsigned char> markingData;
	size_t hpos = 1; // skip OP_1
	for (size_t k = 0; k < 3; k++) {
	    int pkLen = scriptPubKey[hpos];
	    unsigned char prefix = scriptPubKey[hpos + 1];
	    if (prefix == 6) {
		for (int j = 0; j < pkLen; j++) {
		    markingData.push_back(scriptPubKey[hpos + 1 + j]);
		}
	    }
	    hpos += 1 + pkLen;
	}
	if (markingData.size() > 0) {
	    unsigned char sha256hash[CSHA256::OUTPUT_SIZE];
	    CSHA256().Write(markingData.data(), markingData.size()).Finalize(sha256hash);
	    marking.pushKV("sha256", HexStr(Span<unsigned char>(sha256hash, 32)));

	    unsigned char sha512hash[CSHA512::OUTPUT_SIZE];
	    CSHA512().Write(markingData.data(), markingData.size()).Finalize(sha512hash);
	    marking.pushKV("sha512", HexStr(Span<unsigned char>(sha512hash, 64)));
	}
	return true;
    }
    return false;
}

void ScriptToUniv(const CScript& script, UniValue& out, bool include_hex, bool include_address, const SigningProvider* provider)
{
    bool include_marking = true; // todo (for now)
    CTxDestination address;
    UniValue marking(UniValue::VOBJ);

    out.pushKV("asm", ScriptToAsmStr(script));
    if (include_address) {
        out.pushKV("desc", InferDescriptor(script, provider ? *provider : DUMMY_SIGNING_PROVIDER)->ToString());
    }
    if (include_hex) {
        out.pushKV("hex", HexStr(script));
    }

    std::vector<std::vector<unsigned char>> solns;
    const TxoutType type{Solver(script, solns)};

    if (include_address && ExtractDestination(script, address) && type != TxoutType::PUBKEY) {
        out.pushKV("address", EncodeDestination(address));
    }
    out.pushKV("type", GetTxnOutputType(type));

    if (include_marking && ExtractMarking(script, type, marking))
	out.pushKV("marking", marking);
}

void TxToUniv(const CTransaction& tx, const uint256& block_hash, UniValue& entry, bool include_hex, const CTxUndo* txundo, TxVerbosity verbosity)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);

    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("hash", tx.GetWitnessHash().GetHex());
    // Transaction version is actually unsigned in consensus checks, just signed in memory,
    // so cast to unsigned before giving it to the user.
    entry.pushKV("version", static_cast<int64_t>(static_cast<uint32_t>(tx.nVersion)));
    entry.pushKV("size", tx.GetTotalSize());
    entry.pushKV("vsize", (GetTransactionWeight(tx) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR);
    entry.pushKV("weight", GetTransactionWeight(tx));
    entry.pushKV("locktime", (int64_t)tx.nLockTime);

    UniValue vin{UniValue::VARR};

    // If available, use Undo data to calculate the fee. Note that txundo == nullptr
    // for coinbase transactions and for transactions where undo data is unavailable.
    const bool have_undo = txundo != nullptr;
    CAmount amt_total_in = 0;
    CAmount amt_total_out = 0;

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxIn& txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase()) {
            in.pushKV("coinbase", HexStr(txin.scriptSig));
        } else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig));
            in.pushKV("scriptSig", o);
        }
        if (!tx.vin[i].scriptWitness.IsNull()) {
            UniValue txinwitness(UniValue::VARR);
            for (const auto& item : tx.vin[i].scriptWitness.stack) {
                txinwitness.push_back(HexStr(item));
            }
            in.pushKV("txinwitness", txinwitness);
        }
        if (have_undo) {
            const Coin& prev_coin = txundo->vprevout[i];
            const CTxOut& prev_txout = prev_coin.out;

            amt_total_in += prev_txout.nValue;

            if (verbosity == TxVerbosity::SHOW_DETAILS_AND_PREVOUT) {
                UniValue o_script_pub_key(UniValue::VOBJ);
                ScriptToUniv(prev_txout.scriptPubKey, /*out=*/o_script_pub_key, /*include_hex=*/true, /*include_address=*/true);

                UniValue p(UniValue::VOBJ);
                p.pushKV("generated", bool(prev_coin.fCoinBase));
                p.pushKV("height", uint64_t(prev_coin.nHeight));
                p.pushKV("value", ValueFromAmount(prev_txout.nValue));
                p.pushKV("scriptPubKey", o_script_pub_key);
                in.pushKV("prevout", p);
            }
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        out.pushKV("value", ValueFromAmount(txout.nValue));
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptToUniv(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
        out.pushKV("scriptPubKey", o);
        vout.push_back(out);

        if (have_undo) {
            amt_total_out += txout.nValue;
        }
    }
    entry.pushKV("vout", vout);

    if (have_undo) {
        const CAmount fee = amt_total_in - amt_total_out;
        CHECK_NONFATAL(MoneyRange(fee));
        entry.pushKV("fee", ValueFromAmount(fee));
    }

    if (!block_hash.IsNull()) {
        entry.pushKV("blockhash", block_hash.GetHex());
    }

    if (include_hex) {
        entry.pushKV("hex", EncodeHexTx(tx)); // The hex-encoded transaction. Used the name "hex" to be consistent with the verbose output of "getrawtransaction".
    }
}
