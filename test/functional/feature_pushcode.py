#!/usr/bin/env python3
# Copyright (c) 2026 The Bitmark developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test OP_PUSHCODE (Bitmark) soft-fork activation and consensus behaviour.

OP_PUSHCODE (= OP_NOP4 = 0xb3) activates by miner supermajority: on regtest,
75 of the last 100 blocks at base version >= 5. Before activation it is an
inert NOP; after activation a malformed PUSHCODE output invalidates the block,
while well-formed outputs -- including references to code that is not (yet) on
the chain -- are accepted (references are content-addressed commitments,
resolved lazily at assembly time).

The test mines a version-4 chain first (fork never active), then switches to
version-5 blocks to cross the activation threshold, driving the node's own
miner via generateblock so the real (scrypt) proof-of-work and full block
validation are exercised.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import CScript, OP_NOP4  # OP_PUSHCODE == OP_NOP4 == 0xb3
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet import MiniWallet, MiniWalletMode


class PushCodeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Phase 1: mine only base-version-4 blocks, so OP_PUSHCODE never activates.
        self.extra_args = [["-blockversion=4"]]

    def pushcode_rawtx(self, wallet, params):
        """A raw tx spending one wallet UTXO into a single <params> OP_PUSHCODE output."""
        tx = wallet.create_self_transfer()["tx"]
        tx.vout[0].scriptPubKey = CScript(list(params) + [OP_NOP4])
        return tx.serialize().hex()

    def generateblock_with(self, wallet, params):
        rawtx = self.pushcode_rawtx(wallet, params)
        return self.nodes[0].generateblock(wallet.get_address(), [rawtx], invalid_call=False)

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_OP_TRUE)

        ref = b'\xab' * 32   # a 32-byte content-hash reference (need not exist yet)
        code = b'\x01\x02\x03'
        bad_ref = b'\xbb' * 31  # 31 bytes -> not a valid content hash

        # ---- Phase 1: OP_PUSHCODE NOT active (version-4 chain) ----
        # Mine past coinbase maturity so the wallet has spendable coins; all base
        # version 4, so OP_PUSHCODE never activates no matter how many we mine.
        self.generate(wallet, COINBASE_MATURITY + 5)
        # A malformed PUSHCODE output is just an OP_NOP4 with data here, so the
        # block is accepted -- the fork gate is off.
        self.generateblock_with(wallet, [bad_ref, code])
        self.log.info("pre-activation: malformed PUSHCODE output ignored (block accepted)")

        # ---- Phase 2: activate OP_PUSHCODE (switch to base version-5 blocks) ----
        self.restart_node(0, extra_args=[])  # default -blockversion = CURRENT_VERSION = 5
        wallet.rescan_utxos()
        self.generate(wallet, 100)  # last 100 blocks now version 5 => fork active

        # A well-formed NEW entry ([code] OP_PUSHCODE) is accepted.
        self.generateblock_with(wallet, [code])
        self.log.info("post-activation: well-formed NEW PUSHCODE accepted")

        # A forward reference ([codehash][code] OP_PUSHCODE) to code that is not on
        # the chain is accepted -- references are commitments, not resolved here.
        self.generateblock_with(wallet, [ref, code])
        self.log.info("post-activation: forward reference accepted")

        # A malformed output (31-byte "content hash") now makes the block invalid.
        assert_raises_rpc_error(
            -25, "bad-pushcode-codehash",
            lambda: self.generateblock_with(wallet, [bad_ref, code]))
        self.log.info("post-activation: malformed PUSHCODE output rejected by consensus")


if __name__ == '__main__':
    PushCodeTest().main()
