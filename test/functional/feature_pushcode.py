#!/usr/bin/env python3
# Copyright (c) 2026 The Bitmark developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test OP_PUSHCODE (Bitmark) soft-fork activation and consensus behaviour.

OP_PUSHCODE (= OP_NOP4 = 0xb3) activates by miner supermajority at base version 5,
required WITHIN EACH mPoW algo (regtest: 9 of each algo's last 12 blocks). Before
activation it is an inert NOP; after activation a malformed PUSHCODE output
invalidates the block, while well-formed outputs -- including references to code
that is not (yet) on the chain -- are accepted (references are content-addressed
commitments, resolved lazily at assembly time).

The test first mines a version-4 chain past the regtest Multi-PoW fork gate (v4
supermajority 750/1000) so the miner will set per-algo bits, then mines version-5
blocks of every algo to cross the per-algo activation threshold, driving the node's
own miner via generate/generateblock so the real proof-of-work and full block
validation are exercised.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import CScript, OP_NOP4, OP_RETURN  # OP_PUSHCODE == OP_NOP4 == 0xb3
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet import MiniWallet, MiniWalletMode

NUM_ALGOS = 8


class PushCodeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Phase 1: mine only base-version-4 blocks, so OP_PUSHCODE never activates.
        self.extra_args = [["-blockversion=4"]]
        # Phase 2 mines a few blocks of every algo, including the memory-hard ones
        # (equihash / cryptonight / ...), whose PoW is slow to compute even at regtest
        # difficulty. Allow generous RPC time for those.
        self.rpc_timeout = 600

    def pushcode_rawtx(self, wallet, params):
        """A raw tx spending one wallet UTXO into a single unspendable
        OP_RETURN OP_PUSHCODE <params...> output."""
        tx = wallet.create_self_transfer()["tx"]
        tx.vout[0].scriptPubKey = CScript([OP_RETURN, OP_NOP4] + list(params))
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
        # Mine > 750 base-version-4 blocks: past coinbase maturity (so the wallet has
        # spendable coins) AND across the regtest Multi-PoW fork gate (v4 supermajority
        # 750/1000). All base version 4, so the per-algo VERSION-5 PUSHCODE fork never
        # activates; but the Multi-PoW fork does, which is what lets phase 2's
        # setminingalgo set per-algo bits so every algo can signal v5.
        self.generate(wallet, 760)
        # A malformed PUSHCODE output is just an OP_NOP4 with data here, so the
        # block is accepted -- the fork gate is off.
        self.generateblock_with(wallet, [bad_ref, code])
        self.log.info("pre-activation: malformed PUSHCODE output ignored (block accepted)")

        # ---- Phase 2: activate OP_PUSHCODE (per-algo base-version-5 supermajority) ----
        # The v5 fork requires the supermajority WITHIN EACH mPoW algo (regtest: 9 of each
        # algo's last 12 blocks), so a single-algo v5 run does NOT activate it. Mine v5
        # blocks of every algo via setminingalgo so all 8 signal. (Phase 1's >= 750 v4
        # blocks already activated the Multi-PoW fork, so the miner sets the per-algo bits.)
        self.restart_node(0, extra_args=[])  # default -blockversion = CURRENT_VERSION = 5
        wallet.rescan_utxos()
        for a in range(NUM_ALGOS):
            node.setminingalgo(a)
            # Mine one block at a time: a single 15-block generate() call can exceed the
            # RPC timeout for the memory-hard algos (their PoW is slow to compute).
            for _ in range(15):  # >= 12 => each algo's last 12 are v5 once all 8 signalled
                self.generate(wallet, 1)
        node.setminingalgo(0)

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
