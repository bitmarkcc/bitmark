#!/usr/bin/env python3
# Copyright (c) 2026 The Bitmark developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the OP_PUSHCODE RPCs: createpushcodescript, getpushcode, getpushcodeentry.

Drives the full round-trip against a running node with the fork active:
build a PUSHCODE scriptPubKey with createpushcodescript, put it in a mined
transaction, then assemble it back with getpushcode and inspect the stored entry
with getpushcodeentry. Exercises NEW / insert / replace / delete ops and a
forward reference (which assembles as "incomplete").
"""

from io import BytesIO

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import CTransaction
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet, MiniWalletMode


def tx_vout_scripts(raw_hex):
    """Deserialize a raw tx and return its output scriptPubKeys as hex strings.
    (Avoids decoderawtransaction, whose scriptPubKey carries an undocumented
    Bitmark 'marking' field that trips the node's RPC doc self-check.)"""
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(raw_hex)))
    return [out.scriptPubKey.hex() for out in tx.vout]


class PushCodeRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Default -blockversion is CURRENT_VERSION (5), so mining any run of
        # blocks past the regtest threshold activates OP_PUSHCODE.

    def mine_script(self, script_hex):
        """Put one PUSHCODE output (the given scriptPubKey) in a mined block."""
        tx = self.wallet.create_self_transfer()["tx"]
        tx.vout[0].scriptPubKey = bytes.fromhex(script_hex)
        self.nodes[0].generateblock(self.wallet.get_address(), [tx.serialize().hex()], invalid_call=False)

    def create_and_mine(self, params):
        """createpushcodescript(params), mine it, return the RPC result dict."""
        out = self.nodes[0].createpushcodescript(params)
        self.mine_script(out["hex"])
        return out

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_OP_TRUE)

        # Mine past coinbase maturity; this also drives base-version-5 blocks well
        # past the regtest activation threshold, so OP_PUSHCODE is active and the
        # code DB records entries.
        self.generate(self.wallet, COINBASE_MATURITY + 120)

        # ---- createpushcodescript validation (no chain needed) ----
        assert_raises_rpc_error(-8, "a NEW entry needs a non-empty code chunk",
                                node.createpushcodescript, {"code": ""})
        assert_raises_rpc_error(-8, "a NEW entry must be an insert",
                                node.createpushcodescript, {"op": "replace", "code": "01"})
        assert_raises_rpc_error(-8, "delete takes no code chunk",
                                node.createpushcodescript, {"op": "delete", "parent": "aa" * 32, "part": 0, "code": "01"})
        assert_raises_rpc_error(-8, "delete needs a part",
                                node.createpushcodescript, {"op": "delete", "parent": "aa" * 32})

        # ---- createpushcoderawtransaction: appends a PUSHCODE output (no chain needed) ----
        spk = node.createpushcodescript({"code": "0102"})["hex"]
        raw = node.createpushcoderawtransaction(
            [{"txid": "00" * 32, "vout": 0}], [], {"amount": 1.0, "code": "0102"})
        assert_equal(tx_vout_scripts(raw), [spk])
        # the pushcode output is appended after any standard outputs
        raw2 = node.createpushcoderawtransaction(
            [{"txid": "00" * 32, "vout": 0}], [{"data": "beef"}], {"amount": 1.0, "code": "0102"})
        vouts = tx_vout_scripts(raw2)
        assert_equal(len(vouts), 2)
        assert_equal(vouts[0], "6a02beef")  # OP_RETURN "beef" (standard output first)
        assert_equal(vouts[1], spk)         # PUSHCODE output appended last

        # ---- NEW root: seeds [0102] ----
        new = self.create_and_mine({"code": "0102"})
        assert_equal(new["is_new"], True)
        assert_equal(new["op"], "insert")
        got = node.getpushcode(new["hash"])
        assert_equal(got["status"], "complete")
        assert_equal(got["code"], "0102")
        assert_equal(got["length"], 2)

        # ---- INSERT (append): [0102] -> [0102, 0304] ----
        ins = self.create_and_mine({"parent": new["hash"], "code": "0304"})
        assert_equal(node.getpushcode(ins["hash"])["code"], "01020304")

        # ---- REPLACE part 0: [0102, 0304] -> [ff, 0304] ----
        rep = self.create_and_mine({"op": "replace", "parent": ins["hash"], "part": 0, "code": "ff"})
        assert_equal(rep["op"], "replace")
        assert_equal(node.getpushcode(rep["hash"])["code"], "ff0304")

        # ---- DELETE part 0: [0102, 0304] -> [0304] ----
        dele = self.create_and_mine({"op": "delete", "parent": ins["hash"], "part": 0})
        assert_equal(dele["op"], "delete")
        assert_equal(node.getpushcode(dele["hash"])["code"], "0304")

        # ---- getpushcodeentry reflects the stored entry ----
        entry = node.getpushcodeentry(dele["hash"])
        assert_equal(entry["op"], "delete")
        assert_equal(entry["is_new"], False)
        assert_equal(entry["parent"], ins["hash"])
        assert_equal(entry["part"], 0)
        assert_equal(entry["refcount"], 1)
        assert_raises_rpc_error(-5, "no PUSHCODE entry", node.getpushcodeentry, "bb" * 32)

        # ---- forward reference: parent not on chain -> incomplete ----
        fwd = self.create_and_mine({"parent": "cc" * 32, "code": "99"})
        assert_equal(node.getpushcode(fwd["hash"])["status"], "incomplete")

        self.log.info("createpushcodescript / getpushcode / getpushcodeentry round-trip OK (incl. delete)")


if __name__ == '__main__':
    PushCodeRPCTest().main()
