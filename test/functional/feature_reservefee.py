#!/usr/bin/env python3
# Copyright (c) 2026 The Bitmark developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test OP_RESERVEFEE (Bitmark) reserve-fee covenant activation and consensus.

OP_RESERVEFEE (= OP_NOP7 = 0xb6) is a spendable covenant output

    <algo> <s0> <refund_pkh> OP_RESERVEFEE

carrying a hashrate-contingent reserve fee (see doc/dynamic-algo-mining.md sec 6).
Enforcement activates with the dynamic-algo soft fork (base version-5 supermajority).
Every release path sends value to FEE: claim (keyless, dedicated 1-in/1-out tx, algo
& mature & s_t>s0, rollover), refund (user-signed fee-redirect, s_t<=s0, <expiry) and
sweep (keyless, any miner, age>=expiry).

All blocks are mined with uniform mocktime spacing so the per-algo RSF is well-defined
(every 90-block window identical => s_t = max); a slow tail lowers s_t for the refund.
The exact Q32 s_t the covenant uses is read back with the getreservefeersf RPC so the
test can compute the precise claimable / choose s0. On regtest nReserveFeeExpiry is
720*14 (~2 weeks), so the sweep path is reachable.
"""

import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import ECKey
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint
from test_framework.script import (
    CScript, OP_TRUE, OP_RETURN, OP_NOP7, LegacySignatureHash, SIGHASH_ALL, hash160,
)  # OP_RESERVEFEE == OP_NOP7 == 0xb6
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet import MiniWallet, MiniWalletMode

OP_RESERVEFEE = OP_NOP7
NUM_ALGOS = 8
Q32 = 1 << 32
STEP = 600           # uniform seconds/block => every RSF window identical => s_t = max
SLOW = STEP * 3      # slow tail => current hashrate ~1/3 of peak => s_t < max


def reservefee_spk(algo, s0_q16, pkh):
    """<algo> <s0:2 bytes LE> <refund_pkh:20> OP_RESERVEFEE."""
    return CScript([algo, s0_q16.to_bytes(2, 'little'), pkh, OP_RESERVEFEE])


class ReserveFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-blockversion=4"]]  # phase 1: fork never active
        # Aging the reserve past nReserveFeeExpiry (regtest 720*14) is a lot of blocks;
        # allow long generate calls.
        self.rpc_timeout = 600

    # --- mocktime-uniform block production -------------------------------------
    def gen(self, n, step=STEP):
        for _ in range(n):
            self.mtime += step
            self.nodes[0].setmocktime(self.mtime)
            self.generate(self.wallet, 1)

    def gen_block_with(self, rawtx, step=STEP):
        self.mtime += step
        self.nodes[0].setmocktime(self.mtime)
        return self.nodes[0].generateblock(self.wallet.get_address(), [rawtx], invalid_call=False)

    def create_reservefee(self, algo, s0_q16, pkh, step=STEP):
        """Mine a block creating one (V, RESERVEFEE) output; return (hash_int, n, value)."""
        tx = self.wallet.create_self_transfer()["tx"]
        tx.vout[0].scriptPubKey = reservefee_spk(algo, s0_q16, pkh)
        self.gen_block_with(tx.serialize().hex(), step)
        tx.rehash()
        return tx.sha256, 0, tx.vout[0].nValue

    def spend_hex(self, prev_hash, n, selector_script, outputs):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(prev_hash, n), selector_script)]
        tx.vout = outputs
        return tx.serialize().hex()

    def assert_rejected(self, rawtx, reason):
        assert_raises_rpc_error(
            -25, reason,
            lambda: self.nodes[0].generateblock(self.wallet.get_address(), [rawtx], invalid_call=False))

    def rsf(self, algo):
        return self.nodes[0].getreservefeersf(algo)["q32"]

    # --- the test --------------------------------------------------------------
    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_OP_TRUE)
        # Start the mocktime base well in the past so that after advancing +STEP per
        # block over the whole test the chain tip never ends up ahead of real time
        # (a future-dated tip makes the node abort on restart). Absolute time doesn't
        # matter for the RSF -- only the relative spacing between blocks does.
        self.mtime = int(time.time()) - 60 * 24 * 3600  # ~60 days ago
        node.setmocktime(self.mtime)
        pkh = b'\xee' * 20
        op_true = CScript([OP_TRUE])
        bad_algo_spk = reservefee_spk(8, 0x8000, pkh)  # algo 8 is out of [0, NUM_ALGOS)

        # ---- Phase 1: covenant NOT active (version-4 chain) ----
        self.gen(COINBASE_MATURITY + 5)
        tx = self.wallet.create_self_transfer()["tx"]
        tx.vout[0].scriptPubKey = bad_algo_spk
        self.gen_block_with(tx.serialize().hex())  # inert NOP -> accepted
        self.log.info("pre-activation: bad-algo RESERVEFEE output inert (block accepted)")

        # ---- Phase 2: activate the fork (base version-5 blocks, all algos) ----
        # The version-5 fork now needs the supermajority WITHIN EACH mPoW algo
        # (regtest: 9 of each algo's last 12 blocks). Mine v5 blocks of every algo via
        # setminingalgo so all 8 algos signal; then switch back to scrypt (algo 0) for
        # the RSF-sensitive claim/refund phases.
        self.restart_node(0, extra_args=[])
        self.wallet.rescan_utxos()
        node.setmocktime(self.mtime)
        for a in range(NUM_ALGOS):
            node.setminingalgo(a)
            self.gen(15)  # >= 12; all v5 => 12/12 of this algo's last 12 are >= v5
        node.setminingalgo(0)  # scrypt for the RSF phases

        # ---- creation validation ----
        tx = self.wallet.create_self_transfer()["tx"]
        tx.vout[0].scriptPubKey = bad_algo_spk
        self.assert_rejected(tx.serialize().hex(), "reservefee-bad-algo")
        h0, n0, v0 = self.create_reservefee(0, 0x8000, pkh)  # algo 0 (SCRYPT), s0 = 0.5
        self.log.info("post-activation: bad-algo creation rejected, valid creation accepted")

        # ---- spend-path early rejections (RSF-independent) ----
        rollover0 = reservefee_spk(0, 0x8000, pkh)
        self.assert_rejected(self.spend_hex(h0, n0, CScript([3]), [CTxOut(v0 - 1000, op_true)]),
                             "reservefee-bad-selector")
        self.assert_rejected(self.spend_hex(h0, n0, CScript([2]), [CTxOut(v0 - 1000, op_true)]),
                             "reservefee-sweep-tooearly")
        self.assert_rejected(self.spend_hex(h0, n0, CScript([0]),
                                            [CTxOut(v0 - 2000, op_true), CTxOut(1000, op_true)]),
                             "reservefee-claim-shape")
        h1, n1, v1 = self.create_reservefee(1, 0x8000, pkh)  # reserve algo 1 vs block algo 0
        self.assert_rejected(self.spend_hex(h1, n1, CScript([0]),
                                            [CTxOut(v1 - 1000, reservefee_spk(1, 0x8000, pkh))]),
                             "reservefee-claim-algo")
        self.assert_rejected(self.spend_hex(h0, n0, CScript([0]), [CTxOut(v0 - 1000, rollover0)]),
                             "reservefee-claim-immature")
        self.log.info("post-activation: spend-path early-rejections enforced")

        # ---- positive CLAIM: mature, s_t > s0, exact rollover ----
        # s0 = 0 so any positive s_t recovers; uniform timing gives s_t = max.
        hc, nc, vc = self.create_reservefee(0, 0x0000, pkh)
        self.gen(95)  # > HASHRATE_CYCLE (90) algo-0 blocks: matured + full RSF window
        s_t = self.rsf(0)
        assert s_t > 0, "expected a positive RSF under uniform timing"
        claimable = (vc * s_t) // Q32       # s0 = 0
        assert 0 < claimable < vc
        rollover = vc - claimable
        claim_spk = reservefee_spk(0, 0x0000, pkh)
        self.gen_block_with(self.spend_hex(hc, nc, CScript([0]), [CTxOut(rollover, claim_spk)]))
        self.log.info("post-activation: valid claim accepted (claimable=%d, rollover=%d)" % (claimable, rollover))
        # a wrong rollover value is rejected
        hc2, nc2, vc2 = self.create_reservefee(0, 0x0000, pkh)
        self.gen(95)
        s_t2 = self.rsf(0)
        bad_rollover = vc2 - ((vc2 * s_t2) // Q32) + 1  # off by one satoshi
        self.assert_rejected(self.spend_hex(hc2, nc2, CScript([0]),
                                            [CTxOut(bad_rollover, claim_spk)]),
                             "reservefee-claim-rollover")
        self.log.info("post-activation: wrong-rollover claim rejected")

        # ---- positive REFUND: user-signed fee-redirect with s_t <= s0 ----
        # A slow tail drops the current hashrate below the peak so s_t < max, leaving
        # room to set s0 just above s_t.
        self.gen(95, step=SLOW)
        s_t = self.rsf(0)
        assert s_t < Q32 - 1, "slow tail should push s_t below max"
        s0_q16 = (s_t >> 16) + 1             # just above s_t, still fits in 16 bits
        assert s0_q16 <= 0xFFFF
        key = ECKey()
        key.generate()
        pub = key.get_pubkey().get_bytes()   # 33-byte compressed
        rpkh = hash160(pub)
        hr, nr, vr = self.create_reservefee(0, s0_q16, rpkh, step=SLOW)
        refund_spk = reservefee_spk(0, s0_q16, rpkh)
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(hr, nr), CScript())]     # scriptSig filled in after signing
        tx.vout = [CTxOut(0, CScript([OP_RETURN, b'\x00']))]  # V_rem -> fee (fee = vr)
        sighash = LegacySignatureHash(refund_spk, tx, 0, SIGHASH_ALL)[0]
        sig = key.sign_ecdsa(sighash) + bytes([SIGHASH_ALL])
        tx.vin[0].scriptSig = CScript([1, sig, pub])       # selector 1, sig, pubkey
        self.gen_block_with(tx.serialize().hex(), step=SLOW)
        self.log.info("post-activation: valid refund (fee-redirect) accepted")
        # a bad signature is rejected
        hr2, nr2, vr2 = self.create_reservefee(0, s0_q16, rpkh, step=SLOW)
        tx2 = CTransaction()
        tx2.vin = [CTxIn(COutPoint(hr2, nr2), CScript([1, b'\x30' * 70, pub]))]  # garbage sig
        tx2.vout = [CTxOut(0, CScript([OP_RETURN, b'\x00']))]
        self.assert_rejected(tx2.serialize().hex(), "reservefee-refund-badsig")
        self.log.info("post-activation: bad-signature refund rejected")

        # ---- positive SWEEP: any miner, after the expiry ----
        hs, ns, vs = self.create_reservefee(0, 0x8000, pkh)
        # Age the reserve past nReserveFeeExpiry (regtest 720*14). Age is just a total
        # block count, so mine with SCRYPT only (fast PoW): the other algos keep their
        # activation blocks so the fork stays active, and OnFork() is O(1) so the
        # receding-algo fork check stays cheap. (We do NOT cycle into equihash / the
        # memory-hard algos -- solving thousands of those PoWs is far too slow.)
        node.setminingalgo(0)
        target = 720 * 14
        done = 0
        while done < target:
            n = min(1000, target - done)
            # advance the node clock so the (~1s/block) timestamps don't run past
            # now + MAX_FUTURE_BLOCK_TIME (regtest bulk blocks freeze at mocktime).
            self.mtime += n + STEP
            node.setmocktime(self.mtime)
            self.generate(self.wallet, n)
            done += n
        # self.mtime already tracks the chain (advanced each batch above); step it
        # forward so the sweep block's timestamp is > MTP.
        self.mtime += STEP
        node.setmocktime(self.mtime)
        # sweep: keyless, V_rem -> fee (single 0-value OP_RETURN output)
        sweep = self.spend_hex(hs, ns, CScript([2]), [CTxOut(0, CScript([OP_RETURN, b'\x00']))])
        node.generateblock(self.wallet.get_address(), [sweep], invalid_call=False)
        self.log.info("post-activation: valid sweep accepted after expiry")


if __name__ == '__main__':
    ReserveFeeTest().main()
