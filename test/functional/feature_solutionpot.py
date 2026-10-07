#!/usr/bin/env python3
# Copyright (c) 2026 The Bitmark developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the dynamic-algo solution pot's miner-facing side.

Covers what does NOT require an algo to be activated in a slot:

  * the voluntary readiness marker (OP_RETURN OP_SOLUTIONPOT) and its two gates --
    it appears only once the dynamic-algo FORK is active, and only while the mined
    slot has no active algo;
  * -signalalgoreadiness=0 opting out;
  * getalgoreadiness reporting coverage per slot, and never miscounting a real pot
    as a free marker;
  * getblocktemplate offering `coinbasesignal`, and offering NO `coinbaserequired`
    while the slot is primitive-only -- i.e. mining such a slot is unchanged;
  * that an ORDINARY transaction is still held to CLEANSTACK, i.e. that the covenant
    carve-out in PolicyScriptChecks has not loosened script policy for all traffic;
  * as a side effect of the restart, that a node can still connect blocks after startup
    verification has run with the dynamic-algo fork active (VerifyDB must not disturb the
    activation store or the code DB).

NOT covered here, and still untested: the pot covenant itself (claim-on-solution,
consolidate, the required coinbase pot output). All of that needs a branch ACTIVATED
in a slot, which means pushing a wasm module on-chain with OP_PUSHCODE, winning an
anchored OP_VOTE window with 75% of both the fee and stake constituencies above the
fee floor, and then waiting out the 720-block activation delay. See the notes at the
bottom of this file.
"""

from io import BytesIO

from test_framework.blocktools import NORMAL_GBT_REQUEST_PARAMS
from test_framework.messages import CBlock
from test_framework.script import CScript, OP_1
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error
from test_framework.wallet import MiniWallet, MiniWalletMode

NUM_ALGOS = 8
# OP_RETURN OP_SOLUTIONPOT == 0x6a 0xb7. The whole script, so an exact match is safe.
READINESS_MARKER_SPK = "6ab7"


class SolutionPotTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Activating the fork mines a few blocks of every algo, including the
        # memory-hard ones, whose PoW is slow even at regtest difficulty.
        self.rpc_timeout = 600

    # ---- helpers ----------------------------------------------------------------

    def coinbase_of(self, height):
        """The coinbase tx of the block at `height`, deserialized.

        Read as raw hex and parsed locally rather than via getblock verbosity or
        decoderawtransaction: the node's JSON scriptPubKey carries an extra Bitmark
        'marking' field, and avoiding it keeps this test independent of that.
        """
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(
            self.nodes[0].getblock(self.nodes[0].getblockhash(height), 0))))
        return block.vtx[0]

    def has_marker(self, height):
        return any(o.scriptPubKey.hex() == READINESS_MARKER_SPK
                   for o in self.coinbase_of(height).vout)

    def activate_fork(self, wallet):
        """Mine a chain with the dynamic-algo fork active.

        Two gates. First the regtest Multi-PoW fork (height 750), which is what makes
        the miner set per-algo version bits; 760 blocks also puts the wallet past
        coinbase maturity. Then the version-5 dynamic fork, which needs the
        supermajority WITHIN EACH mPoW algo (regtest: 9 of each algo's last 12), so a
        single-algo run never activates it however long.
        """
        node = self.nodes[0]
        self.generate(wallet, 760)
        for a in range(NUM_ALGOS):
            node.setminingalgo(a)
            # One block at a time: a single 15-block generate can exceed the RPC
            # timeout for the memory-hard algos.
            for _ in range(15):
                self.generate(wallet, 1)
        node.setminingalgo(0)

    def check_cleanstack_still_enforced(self, p2pk):
        """An ordinary input must still be judged with CLEANSTACK.

        PolicyScriptChecks drops SCRIPT_VERIFY_CLEANSTACK when any input spends a
        covenant output (a solution pot or a reserve fee): those are bare scripts that
        leave more than one item on the stack by construction, and their arity varies
        with the spend path, so the rule cannot hold for them -- ParseCovenantScriptSig
        pins their scriptSig in consensus instead. That carve-out is decided per
        transaction, on every mempool acceptance, for all traffic; nothing else in the
        suite checks that it declines to fire for an ordinary input, so check it here.

        P2PK rather than the test's usual anyone-can-spend output, because the point is
        a spend that is valid, standard and relayable until one junk push is PREPENDED
        to its scriptSig -- which the legacy sighash does not cover, so the signature
        still verifies and only CLEANSTACK stands between the mempool and a third party
        malleating someone else's transaction.
        """
        node = self.nodes[0]
        tx = p2pk.create_self_transfer()["tx"]
        honest = tx.serialize().hex()

        tx.vin[0].scriptSig = CScript(bytes(CScript([OP_1])) + bytes(tx.vin[0].scriptSig))
        assert_raises_rpc_error(
            -26,
            "non-mandatory-script-verify-flag (Stack size must be exactly one after execution)",
            node.sendrawtransaction, tx.serialize().hex())

        # And the unmalleated spend does relay -- without this the assertion above would
        # also pass if the transaction were broken for some unrelated reason.
        node.sendrawtransaction(honest)

    # ---- the test ---------------------------------------------------------------

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_OP_TRUE)
        # Funded here, at the bottom of the chain, so that its coinbase is past the
        # 720-block maturity by the time check_cleanstack_still_enforced spends it.
        p2pk = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)

        self.log.info("pre-fork: no readiness marker, since no slot can be activated yet")
        self.generate(p2pk, 1)
        self.generate(wallet, 20)
        for h in range(1, node.getblockcount() + 1):
            assert not self.has_marker(h), f"marker in pre-fork block {h}"
        # The RPC still answers, with everything at zero.
        pre = node.getalgoreadiness()
        assert_equal(len(pre["slots"]), NUM_ALGOS)
        assert_equal(sum(s["signalled"] for s in pre["slots"]), 0)
        assert all(not s["algo_active"] for s in pre["slots"])

        self.log.info("activating the dynamic-algo fork (mines every algo; slow)")
        self.activate_fork(wallet)
        fork_height = node.getblockcount()

        self.log.info("post-fork: the marker appears, since a slot could now be activated")
        self.generate(wallet, 5)
        for h in range(fork_height + 1, node.getblockcount() + 1):
            assert self.has_marker(h), f"no marker in post-fork block {h}"

        self.log.info("getalgoreadiness reports coverage for the mined slot")
        # Scan only the blocks just mined, all of which are algo 0 and all marked.
        r = node.getalgoreadiness(5)
        assert_equal(r["to"], node.getblockcount())
        slot0 = r["slots"][0]
        assert_equal(slot0["slot"], 0)
        assert_greater_than(slot0["blocks"], 0)
        assert_equal(slot0["signalled"], slot0["blocks"])
        assert_equal(slot0["pct"], 1.0)
        # No algo is activated, so the obligation is not live anywhere.
        assert all(not s["algo_active"] for s in r["slots"])

        self.log.info("getblocktemplate offers the signal and requires nothing")
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert "coinbasesignal" in tmpl
        assert_equal(tmpl["coinbasesignal"]["scriptPubKey"], READINESS_MARKER_SPK)
        assert_equal(tmpl["coinbasesignal"]["value"], 0)
        # A primitive-only slot imposes no coinbase obligations at all, so mining it is
        # exactly as it was before this feature existed.
        assert "coinbaserequired" not in tmpl

        self.log.info("-signalalgoreadiness=0 opts out")
        # The restart also exercises startup verification against the consensus side-DBs:
        # VerifyDB disconnects the last -checkblocks blocks against a throwaway coins view,
        # and the activation store and code DB must come through that untouched. If they
        # don't, the store is left behind the chain and the generate below dies with a
        # fatal "activation store is at height X, cannot connect height Y".
        self.restart_node(0, extra_args=["-signalalgoreadiness=0"])
        wallet.rescan_utxos()
        before = node.getblockcount()
        self.generate(wallet, 3)
        for h in range(before + 1, node.getblockcount() + 1):
            assert not self.has_marker(h), f"marker present despite opt-out, block {h}"
        # The template still OFFERS it -- opting out is about what this node mines, not
        # about what it tells a pool is available.
        assert "coinbasesignal" in node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        # Coverage now reflects the opted-out blocks.
        r = node.getalgoreadiness(3)
        assert_equal(r["slots"][0]["signalled"], 0)

        self.log.info("the covenant CLEANSTACK carve-out does not reach ordinary inputs")
        p2pk.rescan_utxos()
        self.check_cleanstack_still_enforced(p2pk)

        self.log.info("solution-pot miner-side checks OK")


# ---- Still to cover (needs an ACTIVATED algo) -----------------------------------
#
# The pot covenant and the required coinbase output are untested, because reaching
# them needs a branch activated in a slot:
#
#   1. push a module (contrib/dynamicalgo/keccak_algo.wasm, ~3.2 kB) on-chain as an
#      OP_PUSHCODE branch -- ~7 chunks of <= 520 bytes via createpushcodescript /
#      createpushcoderawtransaction, as rpc_pushcode.py does;
#   2. win an anchored vote window for a slot: createfeevotescript +
#      createstakevotescript, needing >= 75% of BOTH the fee-weight and stake
#      constituencies across nVotingPeriod (20 on regtest) blocks, with the window's
#      FIRST block voting for the winner, and fee_total at or above the participation
#      floor. Stake votes need real BIP68-locked coins;
#   3. mine out the 720-block activation delay (cheap: sha256d regtest blocks);
#   4. then assert: a no-solution block's coinbase carries a pot output of exactly the
#      withheld fees and getblocktemplate lists it in `coinbaserequired`; omitting it
#      is rejected (solutionpot-coinbase-amount); a claim without a valid solution is
#      rejected (solutionpot-claim-nosolution); consolidate preserves value; and the
#      marker stops appearing for that slot once it is activated.
#
# Steps 1-3 also require wamrc to be available, or ResolveAlgoReward cannot materialize
# the module and the node stops with a fatal error -- so that layer must skip cleanly
# when the node was built with --disable-wamrc.
#
# Rejection cases in step 4 need hand-built blocks via submitblock rather than
# generate, since generateblock builds its own coinbase (the feature_block.py pattern).


if __name__ == '__main__':
    SolutionPotTest().main()
