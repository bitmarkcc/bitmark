#!/usr/bin/env python3
# Copyright (c) 2026 The Bitmark developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Activate a dynamic algo on an mPoW slot and exercise the reward rules it imposes.

This is the half of the dynamic-algo mechanism that cannot be reached without a slot
actually activated, which means the whole dance: push a module on-chain with
OP_PUSHCODE, win an anchored vote window, wait out the 720-block activation delay.
Everything after that is what no other test can see:

  * the no-solution branch -- the coinbase withholds fees into an <algo> OP_SOLUTIONPOT
    output, and getblocktemplate hands that obligation to pools as `coinbaserequired`;
  * the solution branch -- a solution tx relayed through the mempool is selected, placed
    first, and paid exactly floor(alpha * r) at its committed payout scriptPubKey;
  * the fall-through (doc sec 7 step 4) -- a solution that makes the verifier TRAP leaves
    the block valid on the no-solution branch, and the offending tx is still mined, so
    publishing garbage costs its author the fee;
  * first-wins (doc sec 7 step 3) -- with rivals in the mempool, the chosen solution is
    ordered first and is the one consensus reads.

The algo module is BUILT HERE rather than taken from contrib/dynamicalgo, whose .wasm
files are gitignored build products of a wasm toolchain no test machine need have. The
104-byte module below is assembled byte by byte, which also means the test chooses alpha
and beta and can reach all three of verify()'s outcomes from one module:

    solution empty      -> return 1, alpha/beta written   (the no-solution reading)
    solution[0] == 0xFF -> unreachable                    (the fall-through)
    otherwise           -> return 0                       (a valid solution)

That last one accepts ANY solution bytes, so the test never has to compute real
proof-of-work for the algo -- it is testing the node's reward and selection rules, not an
algo's difficulty check.

Requires the companion wamrc (the node must compile the on-chain .wasm to a .aot before it
can run it), so it skips cleanly on a --disable-wamrc build.
"""

import os
from decimal import Decimal

from test_framework.blocktools import (
    COINBASE_MATURITY,
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
)
from io import BytesIO

from test_framework.messages import COIN, COutPoint, CBlock, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript, CScriptNum, OP_0, OP_1, OP_2, OP_RETURN, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error
from test_framework.wallet import MiniWallet, MiniWalletMode

NUM_ALGOS = 8
SLOT = 0  # scrypt: the node can mine it quickly, and it is the default -miningalgo
SHA256D_SLOT = 1  # the one algo the Python framework can solve, so blocks can be hand-built

OP_SOLUTION = 0xB5
OP_SOLUTIONPOT = 0xB7

# The reward fractions the module reports, in Q32 (value = n / 2**32).
ALPHA_Q32 = 1 << 30  # 0.25 -- the dynamic miner's cut of r
BETA_Q32 = 1 << 30   # 0.25 -- the no-solution scale, so T = beta*(1-alpha) = 0.1875
TRAP_BYTE = 0xFF     # a solution starting with this makes the module trap

# The scriptPubKey a solution commits to as its payment target. It MUST differ from the
# address this test mines to: the coinbase pays its own share there too, so a shared
# scriptPubKey makes "what was paid to the payout" indistinguishable from "what the miner
# kept", and every assertion about alpha*r silently reads r instead.
PAYOUT_SPK = bytes(CScript([OP_TRUE]))

# Where a hand-built slot-1 block sends its own coinbase share. Distinct from PAYOUT_SPK,
# or assertions that sum "what was paid to the payout" would also count the miner's share.
MINER_SPK = bytes(CScript([OP_2]))


def fp_mul(x, q_q32):
    """floor(x * q / 2**32) -- dynamicalgo::fp_mul, which every reward figure goes through."""
    return (x * q_q32) >> 32


# ---- a minimal wasm module exporting the verify() ABI --------------------------------

def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        done = (n == 0 and not b & 0x40) or (n == -1 and b & 0x40)
        out.append(b if done else b | 0x80)
        if done:
            return bytes(out)


def _sec(sid, payload):
    return bytes([sid]) + _uleb(len(payload)) + payload


def _vec(items):
    return _uleb(len(items)) + b"".join(items)


def build_verify_wasm(alpha_q32=ALPHA_Q32, beta_q32=BETA_Q32, trap_byte=TRAP_BYTE):
    """int verify(anchor, payout, payout_len, nbits, nonce, nonce_len, out_ab) -- 7 i32 -> i32.

    Writes alpha then beta as little-endian u32 into out_ab (local 6), then returns 1 for
    an empty solution, traps when the solution's first byte is `trap_byte`, and otherwise
    returns 0. Not gas-instrumented: the node does not instrument modules (gasinstrument
    is a standalone tool), so an uninstrumented one simply charges nothing.
    """
    i32 = 0x7F
    ftype = bytes([0x60]) + _vec([bytes([i32])] * 7) + _vec([bytes([i32])])
    types = _sec(1, _vec([ftype]))
    funcs = _sec(3, _vec([_uleb(0)]))
    # One page is plenty: the host marshals only the anchor, payout, solution and out_ab,
    # and WAMR appends its own managed heap for those.
    mems = _sec(5, _vec([bytes([0x00]) + _uleb(1)]))
    exports = _sec(7, _vec([
        _uleb(len(b"verify")) + b"verify" + bytes([0x00]) + _uleb(0),
        _uleb(len(b"memory")) + b"memory" + bytes([0x02]) + _uleb(0),
    ]))

    body = bytearray()
    # out_ab[0:4] = alpha ; out_ab[4:8] = beta
    body += bytes([0x20, 6]) + bytes([0x41]) + _sleb(alpha_q32) + bytes([0x36, 0x02, 0x00])
    body += bytes([0x20, 6]) + bytes([0x41]) + _sleb(beta_q32) + bytes([0x36, 0x02, 0x04])
    body += bytes([0x20, 5, 0x45])              # local.get nonce_len ; i32.eqz
    body += bytes([0x04, i32])                  # if (result i32)
    body += bytes([0x41]) + _sleb(1)            #   1  -- empty solution is never valid
    body += bytes([0x05])                       # else
    body += bytes([0x20, 4, 0x2D, 0x00, 0x00])  #   local.get nonce ; i32.load8_u
    body += bytes([0x41]) + _sleb(trap_byte)
    body += bytes([0x46])                       #   i32.eq
    body += bytes([0x04, 0x40, 0x00, 0x0B])     #   if ; unreachable ; end
    body += bytes([0x41]) + _sleb(0)            #   0  -- accept
    body += bytes([0x0B])                       # end (if)
    body += bytes([0x0B])                       # end (function)

    entry = _uleb(0) + bytes(body)              # no local declarations
    code = _sec(10, _vec([_uleb(len(entry)) + entry]))
    return b"\x00asm\x01\x00\x00\x00" + types + funcs + mems + exports + code


def num_push(n):
    """The minimal data push of `n`, as the C++ `script << CScriptNum(n)` emits it.

    Not CScript([n]): that encodes 0..16 as OP_0/OP_N, while the consensus side pushes
    the CScriptNum bytes, and Solver's SOLUTION template wants a push.
    """
    enc = CScriptNum.encode(CScriptNum(n))
    return bytes(CScript([enc[1:] if enc else b""]))


def raw_txid(raw_hex):
    """The txid of a raw transaction, for looking it up in a mined block."""
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(raw_hex)))
    tx.rehash()
    return tx.hash


def solution_output(seq, chunk):
    """One OP_RETURN OP_SOLUTION <seq> <chunk> output (TxoutType::SOLUTION), 0-value."""
    return CTxOut(0, CScript(bytes([OP_RETURN, OP_SOLUTION]) + num_push(seq)
                             + bytes(CScript([chunk]))))


class DynamicAlgoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # ~1600 blocks, 120 of them on the memory-hard algos, plus AOT compilation.
        self.rpc_timeout = 1200

    def skip_test_if_missing_module(self):
        # The node execs wamrc to turn the on-chain .wasm into the .aot its AOT-only
        # runtime can load. It is built next to the daemon but installed to bindir, so a
        # build-tree run has to be pointed at it (doc sec 8.4).
        self.wamrc = os.path.join(self.config["environment"]["BUILDDIR"],
                                  "src", "wamr", "build-wamrc", "wamrc")
        if not os.path.isfile(self.wamrc):
            raise SkipTest("wamrc is not built; this node cannot materialize an on-chain "
                           "dynamic algo (configured with --disable-wamrc?)")
        self.extra_args = [[
            "-wamrc=" + self.wamrc,
            # Judge several mempool candidates per template. The default of 1 is right for
            # a real chain, where one anchor epoch spans ~8 blocks and verdicts carry over
            # within it; here only one algo is mined, so EVERY block starts a new epoch and
            # resets the budget -- and the memoized verdicts, which key on the anchor.
            "-maxsolutionverify=4",
        ]]

    # ---- getting a slot activated ----------------------------------------------------

    def activate_fork(self):
        """Mine a chain with the dynamic-algo fork active (see feature_solutionpot.py)."""
        node = self.nodes[0]
        self.generate(self.wallet, 760)
        for a in range(NUM_ALGOS):
            node.setminingalgo(a)
            for _ in range(15):  # >= 12, so each algo's last 12 blocks are v5
                self.generate(self.wallet, 1)
        node.setminingalgo(SLOT)

    def mine_tx(self, tx):
        """Mine one locally-built transaction, bypassing relay policy."""
        self.nodes[0].generateblock(self.wallet.get_address(), [tx.serialize().hex()],
                                    invalid_call=False)

    def push_module(self, wasm):
        """Put `wasm` on-chain as an OP_PUSHCODE branch and return its content hash."""
        node = self.nodes[0]
        out = node.createpushcodescript({"code": wasm.hex()})
        tx = self.wallet.create_self_transfer()["tx"]
        tx.vout[0].scriptPubKey = bytes.fromhex(out["hex"])
        self.mine_tx(tx)
        got = node.getpushcode(out["hash"])
        assert_equal(got["status"], "complete")
        assert_equal(got["code"], wasm.hex())
        return out["hash"]

    def win_vote_window(self, branch):
        """Win one anchored vote window for `branch` on SLOT; return `enforced_from`.

        A window is nVotingPeriod blocks whose FIRST block carries a vote for the winner,
        and the winner needs >= 75% of both the fee-weight and the stake constituencies,
        with the fee total above the participation floor. Only this test votes, so every
        share is 100%; what still has to be arranged is that BOTH totals are non-zero,
        hence one tx carrying a FEE_VOTE (weighted by the tx's fee) and a STAKE_VOTE
        (weighted by its own output value) in the window's first block.
        """
        node = self.nodes[0]
        # Both slots in ONE window: the windows are anchored at the same first block, so
        # they activate at the same height and SHA256D costs no extra 720-block wait. Slot
        # 1 is activated purely so the rejection tests below can hand-build blocks, since
        # sha256d is the one algo the Python framework can solve.
        tx = self.wallet.create_self_transfer(fee=Decimal("0.01"))["tx"]
        for slot in (SLOT, SHA256D_SLOT):
            fee_spk = node.createfeevotescript(branch, slot)["hex"]
            # The relative lock must be at least one voting period for the stake to count.
            stake_spk = node.createstakevotescript(branch, slot, 20,
                                                   self.wallet.get_address())["hex"]
            tx.vout[0].nValue -= 5 * COIN  # fund the stake vote out of the change
            tx.vout.append(CTxOut(5 * COIN, bytes.fromhex(stake_spk)))
            tx.vout.append(CTxOut(0, bytes.fromhex(fee_spk)))
        first = node.getblockcount() + 1
        self.mine_tx(tx)
        assert_equal(node.getblockcount(), first)

        # Fill out the window, then let the node tell us what it concluded.
        self.generate(self.wallet, 19)
        vote = node.getalgovote(SLOT)
        assert_equal(vote["winner"], branch)
        assert_equal(node.getalgovote(SHA256D_SLOT)["winner"], branch)
        assert_equal(vote["activation_block"], first + 20 + 720)
        assert_equal(vote["enforced_from"], vote["activation_block"] + 1)
        self.log.info("window [%d..%d] won by %s; recorded at %d, enforced from %d",
                      first, first + 19, branch[:16], vote["activation_block"],
                      vote["enforced_from"])
        return vote["activation_block"], vote["enforced_from"]

    # ---- helpers for reading what got mined ------------------------------------------

    def pot_utxos(self, height):
        """[(txid, vout, value_sat)] of the pot outputs in the coinbase at `height`."""
        node = self.nodes[0]
        block = node.getblock(node.getblockhash(height), 2)
        cb = block["tx"][0]
        want = format(OP_1 + SLOT, "02x") + format(OP_SOLUTIONPOT, "02x")
        return [(cb["txid"], n, int(round(o["value"] * COIN)))
                for n, o in enumerate(cb["vout"]) if o["scriptPubKey"]["hex"] == want]

    def coinbase_outs(self, height=None):
        """[(value_sat, scriptPubKey_hex)] of the coinbase at `height` (default: tip)."""
        node = self.nodes[0]
        if height is None:
            height = node.getblockcount()
        block = node.getblock(node.getblockhash(height), 2)
        return [(int(round(o["value"] * COIN)), o["scriptPubKey"]["hex"])
                for o in block["tx"][0]["vout"]]

    def pot_value(self, outs, slot=SLOT):
        """Total value in `slot`'s OP_SOLUTIONPOT outputs (0 if none).

        The slot is encoded as SLOT+1, so the script's last stack item is never a
        zero-valued push -- a 0-based encoding would leave every slot-0 pot unspendable.
        """
        # Canonically OP_1..OP_8 then OP_SOLUTIONPOT -- two bytes (see SolutionPotScript).
        want = format(OP_1 + slot, "02x") + format(OP_SOLUTIONPOT, "02x")
        return sum(v for v, spk in outs if spk == want)

    def broadcast(self, tx):
        """Relay a solution tx. maxfeerate is disabled because these fees are chosen for
        their ORDERING, not their size, and the default cap (0.10 BTC/kvB) is easy to trip
        on a ~150-byte transaction."""
        return self.nodes[0].sendrawtransaction(tx.serialize().hex(), 0)

    def solution_tx(self, solution_bytes, payout_spk, fee):
        """A relayable solution tx: payout in seq=0, the solution in seq=1."""
        tx = self.wallet.create_self_transfer(fee=fee)["tx"]
        tx.vout.append(solution_output(0, payout_spk))
        tx.vout.append(solution_output(1, solution_bytes))
        return tx

    def submit_sha256d_block(self, mutate):
        """Build, solve and submit a slot-1 (SHA256D) block, mutated by `mutate`.

        Everything structural comes from getblocktemplate -- `version` (so the algo bits
        AND the SSF flag are the node's own, not a reimplementation of SetUpdateSSF),
        `bits`, `curtime`, the transaction list, the coinbase value and its required
        outputs. Only what is under test gets changed, so a rejection is about the mutation
        rather than about this builder guessing Bitmark's reward arithmetic wrong.

        Returns submitblock's result: a reject reason, or None when accepted.
        """
        node = self.nodes[0]
        tmpl = node.getblocktemplate({"rules": ["segwit"], "algo": SHA256D_SLOT})

        cb = CTransaction()
        cb.vin = [CTxIn(COutPoint(0, 0xFFFFFFFF),
                        CScript([CScriptNum(tmpl["height"]), OP_0]), 0xFFFFFFFF)]
        cb.vout = [CTxOut(tmpl["coinbasevalue"], MINER_SPK)]
        for o in tmpl.get("coinbaserequired", []):
            cb.vout.append(CTxOut(o["value"], bytes.fromhex(o["scriptPubKey"])))

        block = CBlock()
        block.nVersion = tmpl["version"]
        block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
        block.nTime = tmpl["curtime"]
        block.nBits = int(tmpl["bits"], 16)
        block.nNonce = 0
        block.vtx = [cb]
        for t in tmpl["transactions"]:
            tx = CTransaction()
            tx.deserialize(BytesIO(bytes.fromhex(t["data"])))
            tx.rehash()
            block.vtx.append(tx)

        mutate(block)
        # Computes the commitment from the block's own wtxids and fixes up the merkle root,
        # so it must come after the mutation.
        add_witness_commitment(block)
        block.solve()
        return node.submitblock(block.serialize().hex())

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_OP_TRUE)
        payout_spk = PAYOUT_SPK

        self.log.info("activating the dynamic-algo fork")
        self.activate_fork()

        self.log.info("pushing the algo module on-chain (%d bytes)", len(build_verify_wasm()))
        branch = self.push_module(build_verify_wasm())

        # No activation may land until at least one voting period of FEE HISTORY has been
        # recorded, because the participation floor is an average and the store only
        # records fees from the fork-activation height onward -- otherwise the first
        # window would be judged against a floor averaged over a block or two. The fork
        # activates near the end of activate_fork(), so leave room for it here or the
        # window below wins and is then silently ignored.
        self.generate(self.wallet, 30)

        self.log.info("winning a vote window for slot %d", SLOT)
        activation_block, enforced_from = self.win_vote_window(branch)

        # Mine up to just below the recording height. Chunked: one generate of ~720
        # blocks can outrun the RPC timeout.
        self.log.info("mining out the activation delay to height %d", activation_block - 1)
        while node.getblockcount() < activation_block - 1:
            todo = min(200, activation_block - 1 - node.getblockcount())
            self.generate(self.wallet, todo)
        assert_equal(node.getblockcount(), activation_block - 1)

        # The template now being built IS the block that records the activation -- and it
        # is still judged primitively, because a slot's algo is read from the store, i.e.
        # the parent's state. That one-block offset is what keeps the miner and consensus
        # in agreement; without it the activating slot could not produce this block at all.
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert "coinbaserequired" not in tmpl
        self.generate(self.wallet, 1)
        assert_equal(node.getblockcount(), activation_block)
        assert_equal(self.pot_value(self.coinbase_outs()), 0)  # the recording block owes nothing
        # So the next block is the first that must comply -- which is what getalgovote
        # reports as enforced_from.
        assert_equal(node.getblockcount() + 1, enforced_from)

        # From here on the store holds the branch, so every block on this slot must comply.
        assert_equal(node.getalgovote(SLOT)["winner"], branch)
        # The witness used below is `coinbasesignal`, not `coinbaserequired`: the miner
        # emits the readiness marker exactly when the mined slot has NO active algo, so its
        # presence is a direct read of the activation store. `coinbaserequired` is not --
        # on the no-solution branch it appears only when there are fees to withhold, and
        # right after mining an empty block there are none.
        assert "coinbasesignal" not in node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)

        self.log.info("reorg across the activation puts the slot back to primitive-only")
        # The activation store is CONSENSUS state written as this block connected, so a
        # reorg has to unwind it -- ComputeDisconnect restores the slot's prior value from
        # the undo record that block wrote. Nothing had ever exercised that, and it is the
        # case the ChainMove work (VerifyDB / ReplayBlocks) did not cover. Done here, while
        # the activation is a block from the tip, so the reorg is shallow: at the end of
        # the test it would disconnect and reconnect ~730 blocks, each needing its own
        # verify() since the anchor moves every block on a single-algo chain.
        activation_hash = node.getblockhash(activation_block)
        node.invalidateblock(activation_hash)
        assert_equal(node.getblockcount(), activation_block - 1)

        # The STORE rolled back, not just the chain: the readiness marker reappears, which
        # the miner emits only while the mined slot has no active algo. Had the store kept
        # the branch, the template built on this tip would still think the slot was live.
        assert "coinbasesignal" in node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS), \
            "the activation survived a reorg"

        node.reconsiderblock(activation_hash)
        assert_equal(node.getblockcount(), activation_block)
        assert "coinbasesignal" not in node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS), \
            "the activation did not come back"

        # Advance the tip before anything else asks for a template. getblocktemplate caches
        # one and rebuilds only on a new tip, an algo change, or a mempool change that is
        # also more than five seconds old (rpc/mining.cpp) -- so a later call at THIS tip,
        # milliseconds from now, would be served the template just built above, with
        # whatever mempool it saw. Every other template call in this test happens to follow
        # a generate(); this one has to say so.
        self.generate(self.wallet, 1)

        self.log.info("no-solution branch: fees are withheld into the slot's pot")
        # A fee-paying tx, so the withheld amount is non-zero: with no fees the whole
        # subsidy is simply scaled and there is nothing to pot.
        self.wallet.send_self_transfer(from_node=node, fee=Decimal("0.01"))
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        required = tmpl["coinbaserequired"]
        assert_equal(len(required), 1)
        pot_required = required[0]["value"]  # GBT reports satoshis
        assert_greater_than(pot_required, 0)
        assert "coinbasesignal" not in tmpl  # the slot is activated; readiness is moot

        self.generate(self.wallet, 1)
        outs = self.coinbase_outs()
        assert_equal(self.pot_value(outs), pot_required)
        # coinbasevalue excludes the obligations, so appending them cannot over-claim.
        assert_equal(sum(v for v, _ in outs), tmpl["coinbasevalue"] + pot_required)

        self.log.info("solution branch: alpha*r is paid to the committed payout")
        tx = self.solution_tx(b"\x01\x02\x03", payout_spk, Decimal("0.01"))
        self.broadcast(tx)  # through relay, as a real one would
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        required = tmpl["coinbaserequired"]
        assert_equal(len(required), 1)
        payout_out = required[0]
        assert_equal(payout_out["scriptPubKey"], payout_spk.hex())
        # r = S + F is exactly what the coinbase may claim on this branch, and the
        # template splits it into the pool's share plus the obligations.
        payout_sat = payout_out["value"]
        r = tmpl["coinbasevalue"] + payout_sat
        assert_equal(payout_sat, fp_mul(r, ALPHA_Q32))

        self.generate(self.wallet, 1)
        block = node.getblock(node.getblockhash(node.getblockcount()), 1)
        assert tx.rehash() in block["tx"], "the solution tx was not mined"
        outs = self.coinbase_outs()
        assert_equal(self.pot_value(outs), 0)  # nothing withheld when a solution is paid
        assert_equal(sum(v for v, spk in outs if spk == payout_spk.hex()), payout_sat)

        self.log.info("rejections: a coinbase that ignores its obligations")
        # These need a coinbase this node's miner would never build, and generateblock
        # obliges by accident: it prices the coinbase against an EMPTY mempool and only
        # then appends the transactions it was given, so on an activated slot the result
        # is a coinbase that does not satisfy the dynamic rules. (That is also why
        # generateblock is unusable for honest mining on an activated slot -- see doc
        # sec 9.) TestBlockValidity inside it reports the rejection.
        #
        # Withheld fees with no pot output to hold them: the miner would simply keep them.
        fee_tx = self.wallet.create_self_transfer(fee=Decimal("0.01"))["tx"]
        assert_raises_rpc_error(-25, "solutionpot-coinbase-amount", node.generateblock,
                                self.wallet.get_address(), [fee_tx.serialize().hex()],
                                invalid_call=False)
        # A valid solution in the block but no alpha*r paid to its committed payout: the
        # dynamic miner does the work and is not paid.
        unpaid = self.solution_tx(b"\x07", payout_spk, Decimal("0.004"))
        assert_raises_rpc_error(-25, "bad-cb-dynamic-payout", node.generateblock,
                                self.wallet.get_address(), [unpaid.serialize().hex()],
                                invalid_call=False)

        self.log.info("rejections: a coinbase whose outputs are wrong, not merely missing")
        # These need control of the coinbase's OUTPUTS, which generateblock cannot give --
        # it builds its own. So hand-build a block on slot 1 (SHA256D), the one algo whose
        # proof-of-work the Python framework can solve: GetPoWHash for it is
        # Hash256(nVersion..nNonce), i.e. the standard 80-byte double-SHA256.
        #
        # A fee-paying tx first, so the slot-1 template owes a pot to mutate.
        self.wallet.send_self_transfer(from_node=node, fee=Decimal("0.01"))

        def wrong_slot_pot(block):
            mine = bytes([OP_1 + SHA256D_SLOT, OP_SOLUTIONPOT])
            for o in block.vtx[0].vout:
                if o.scriptPubKey == mine:
                    # Point it at another slot: one slot's missed solutions must not be
                    # able to fund a different slot's jackpot.
                    o.scriptPubKey = bytes([OP_1 + SHA256D_SLOT + 1, OP_SOLUTIONPOT])
                    return
            raise AssertionError("slot-1 template owed no pot to mutate")

        assert_equal(self.submit_sha256d_block(wrong_slot_pot), "solutionpot-coinbase-algo")

        def overpay(block):
            block.vtx[0].vout[0].nValue += 1

        assert_equal(self.submit_sha256d_block(overpay), "bad-cb-amount")

        # And the UNMUTATED block is accepted. Without this the two rejections above prove
        # nothing -- they would pass just as well if the builder were producing garbage. It
        # also independently exercises the pot obligation on a second slot, since this
        # block owes one and pays it.
        before = node.getblockcount()
        assert_equal(self.submit_sha256d_block(lambda block: None), None)
        assert_equal(node.getblockcount(), before + 1)
        # It withheld fees into a pot for ITS OWN slot, which is the obligation the two
        # mutations above violated in different ways.
        assert_greater_than(self.pot_value(self.coinbase_outs(), slot=SHA256D_SLOT), 0)
        assert_equal(self.pot_value(self.coinbase_outs(), slot=SLOT), 0)

        self.log.info("fall-through: a trapping solution leaves the block valid, and is mined")
        trap = self.solution_tx(bytes([TRAP_BYTE]) + b"\x00", payout_spk, Decimal("0.01"))
        self.broadcast(trap)
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        # The verifier trapped, so there is no valid solution: the no-solution branch,
        # which owes a pot rather than a payout.
        assert_equal(len(tmpl["coinbaserequired"]), 1)
        assert_equal(tmpl["coinbaserequired"][0]["scriptPubKey"][-2:], format(OP_SOLUTIONPOT, "02x"))
        self.generate(self.wallet, 1)
        block = node.getblock(node.getblockhash(node.getblockcount()), 1)
        assert trap.rehash() in block["tx"], "a rejected solution tx must still be mined for its fee"
        assert_greater_than(self.pot_value(self.coinbase_outs()), 0)

        self.log.info("first-wins: the chosen solution is ordered ahead of its rivals")
        # The trapping rival pays MORE, so declared feerate alone would put it first. The
        # miner must still present the one that verifies, and place it first.
        rival = self.solution_tx(bytes([TRAP_BYTE]) + b"\x01", payout_spk, Decimal("0.01"))
        good = self.solution_tx(b"\x09", payout_spk, Decimal("0.004"))
        self.broadcast(rival)
        self.broadcast(good)
        self.generate(self.wallet, 1)
        block = node.getblock(node.getblockhash(node.getblockcount()), 2)
        txids = [t["txid"] for t in block["tx"]]
        assert good.rehash() in txids, "the verifying solution was not mined"
        if rival.rehash() in txids:
            assert_greater_than(txids.index(rival.rehash()), txids.index(good.rehash()))
        outs = self.coinbase_outs()
        assert_equal(self.pot_value(outs), 0)
        assert_greater_than(sum(v for v, spk in outs if spk == payout_spk.hex()), 0)

        self.log.info("the pot covenant: consolidating two pots into one")
        # Two no-solution blocks, each withholding fees into its own pot output. A coinbase
        # cannot spend, so this is the only shape pots ever come in -- one per block --
        # which is why something has to collapse them.
        pots = []
        while len(pots) < 2:
            self.wallet.send_self_transfer(from_node=node, fee=Decimal("0.01"))
            self.generate(self.wallet, 1)
            found = self.pot_utxos(node.getblockcount())
            assert_equal(len(found), 1)
            pots.append(found[0])
        inputs = [{"txid": t, "vout": v} for t, v, _ in pots]
        total = sum(val for _, _, val in pots)

        # A pot lives in a COINBASE, so it is subject to coinbase maturity like any other
        # coinbase output -- a slot's withheld fees are locked for COINBASE_MATURITY blocks
        # after the block that withheld them, and no claim or consolidation can touch them
        # before that. Mine it out. These blocks carry no transactions, so F = 0 and they
        # withhold nothing, which is why they do not pile up further pots.
        self.log.info("maturing the pots (%d blocks)", COINBASE_MATURITY)
        target = node.getblockcount() + COINBASE_MATURITY
        while node.getblockcount() < target:
            self.generate(self.wallet, min(200, target - node.getblockcount()))

        built = node.createsolutionpotconsolidate(inputs)
        assert_equal(built["slot"], SLOT)
        assert_equal(int(round(built["amount"] * COIN)), total)

        # A consolidation cannot relay, and not because any rule forbids it: being exactly
        # value-preserving it has no fee to offer, so it cannot meet the minimum relay
        # feerate. (A CLAIM is different -- it relays, and its fee is the whole pot. See
        # the claim steps below.) So whoever mines a consolidation builds it.
        assert_raises_rpc_error(-26, "min relay fee not met",
                                node.sendrawtransaction, built["hex"], 0)

        # The covenant's rejections, BEFORE the good consolidation below -- these cases are
        # expected to fail, so they mine nothing and leave the two pots unspent, whereas a
        # successful consolidation consumes them and everything after would then fail on
        # missing inputs instead of the rule under test. They are consensus checks reached
        # only through a block, so TestBlockValidity inside generateblock reports them.
        self.log.info("the pot covenant: rejections")
        bad = CTransaction()
        bad.deserialize(BytesIO(bytes.fromhex(built["hex"])))
        # A single input is not a consolidation -- that shape is reserved for a claim.
        one = CTransaction()
        one.deserialize(BytesIO(bytes.fromhex(built["hex"])))
        one.vin = one.vin[:1]
        one.vout[0].nValue = pots[0][2]
        one.rehash()
        assert_raises_rpc_error(-25, "solutionpot-consolidate-count", node.generateblock,
                                self.wallet.get_address(), [one.serialize().hex()],
                                invalid_call=False)
        # Skimming value off a consolidation. Under-paying rather than over-paying: an
        # output ABOVE the inputs is caught by the generic bad-txns-in-belowout check long
        # before the covenant, whereas one satoshi BELOW is a well-formed transaction that
        # leaves that satoshi as fee -- which is precisely the leak of pot value to the
        # mining miner that the exact-sum rule exists to prevent.
        bad.vout[0].nValue = total - 1
        bad.rehash()
        assert_raises_rpc_error(-25, "solutionpot-consolidate-value", node.generateblock,
                                self.wallet.get_address(), [bad.serialize().hex()],
                                invalid_call=False)
        # Rolling the value into ANOTHER slot's pot, which would let one slot's missed
        # solutions subsidise a different slot.
        bad2 = CTransaction()
        bad2.deserialize(BytesIO(bytes.fromhex(built["hex"])))
        bad2.vout[0].scriptPubKey = bytes([OP_1 + SLOT + 1, OP_SOLUTIONPOT])
        bad2.rehash()
        assert_raises_rpc_error(-25, "solutionpot-consolidate-algo", node.generateblock,
                                self.wallet.get_address(), [bad2.serialize().hex()],
                                invalid_call=False)

        # generateblock bypasses the mempool. A zero-fee transaction leaves the block's
        # fee total untouched, so the coinbase it prices against an empty mempool is still
        # correct -- which is what makes consolidation testable this way and a claim not.
        self.log.info("the pot covenant: consolidating for real")
        node.generateblock(self.wallet.get_address(), [built["hex"]], invalid_call=False)
        # The rollover pot is in the consolidate tx, not the coinbase, so look there.
        block = node.getblock(node.getblockhash(node.getblockcount()), 2)
        want = format(OP_1 + SLOT, "02x") + format(OP_SOLUTIONPOT, "02x")
        rollover = [o for t in block["tx"][1:] for o in t["vout"]
                    if o["scriptPubKey"]["hex"] == want]
        assert_equal(len(rollover), 1)
        assert_equal(int(round(rollover[0]["value"] * COIN)), total)
        self.log.info("two pots worth %d sat merged into one", total)

        # The merged pot, for the claim below. It lives in the consolidate tx, so it is an
        # ordinary output rather than a coinbase one and needs no further maturity wait.
        merged_txid = block["tx"][1]["txid"]
        merged_vout = [n for n, o in enumerate(block["tx"][1]["vout"])
                       if o["scriptPubKey"]["hex"] == want][0]

        self.log.info("the pot covenant: a claim relays, and waits for a solution")
        claim = node.createsolutionpotclaim([{"txid": merged_txid, "vout": merged_vout}])
        assert_equal(claim["slot"], SLOT)
        assert_equal(int(round(claim["amount"] * COIN)), total)
        # A claim is an ordinary relayable transaction -- that is what lets anyone build
        # one and whichever miner holds a solution collect it, so no node has to hunt for
        # pots. maxfeerate off because its fee IS the whole pot.
        # Relaying it at all depends on the CLEANSTACK carve-out for covenant inputs; the
        # other half of that, that ordinary inputs keep CLEANSTACK, is in
        # feature_solutionpot.py (check_cleanstack_still_enforced).
        node.sendrawtransaction(claim["hex"], 0)
        assert raw_txid(claim["hex"]) in node.getrawmempool()

        # Its feerate dwarfs everything, so ordinary selection would take it first -- but
        # it is only valid in a block that carries a valid solution. The miner must
        # therefore leave it out while it has none, and keep producing blocks regardless.
        # If it did not, one relayed claim would stall this slot outright.
        before = node.getblockcount()
        self.generate(self.wallet, 1)
        assert_equal(node.getblockcount(), before + 1)
        mined = node.getblock(node.getblockhash(before + 1), 1)["tx"]
        assert raw_txid(claim["hex"]) not in mined, "a claim was mined with no solution"
        assert raw_txid(claim["hex"]) in node.getrawmempool()  # still pending, not dropped
        # include_mempool=False: the claim is sitting in the mempool spending this pot, so
        # the default view would report it gone. What matters is that the CHAIN still has
        # it -- the claim was kept out of the block, not mined.
        assert node.gettxout(merged_txid, merged_vout, False) is not None

        self.log.info("the pot covenant: claiming the pot alongside a solution")
        # Nothing about the claim changes -- only its block context does.
        self.broadcast(self.solution_tx(b"\x42", payout_spk, Decimal("0.004")))
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_equal(len(tmpl["coinbaserequired"]), 1)
        payout_sat = tmpl["coinbaserequired"][0]["value"]
        r = tmpl["coinbasevalue"] + payout_sat
        assert_equal(payout_sat, fp_mul(r, ALPHA_Q32))
        # The released pot is fee, so it is inside r. That is the whole design: the jackpot
        # reaches the miner through the ordinary reward split, with no new coinbase rule.
        assert_greater_than(r, total)

        self.generate(self.wallet, 1)
        mined = node.getblock(node.getblockhash(node.getblockcount()), 1)["tx"]
        assert raw_txid(claim["hex"]) in mined, "the claim was not mined with a solution"
        assert_equal(node.gettxout(merged_txid, merged_vout, False), None)  # pot spent for real
        outs = self.coinbase_outs()
        assert_equal(self.pot_value(outs), 0)  # a claiming block withholds nothing
        assert_equal(sum(v for v, spk in outs if spk == payout_spk.hex()), payout_sat)
        self.log.info("pot of %d sat released into the block's fees", total)

        self.log.info("reorg across the claim returns the pot")
        # The pot covenant keeps no side state -- its comments say so ("pure validation, so
        # DisconnectBlock needs nothing"), meaning everything it depends on lives in the
        # UTXO set. A reorg is the only thing that can check that claim.
        claim_block = node.getblockhash(node.getblockcount())
        node.invalidateblock(claim_block)
        assert node.gettxout(merged_txid, merged_vout, False) is not None, \
            "the pot did not come back after the claim was reorged out"
        # The claim itself is an ordinary relayable transaction, so it returns to the
        # mempool rather than being dropped -- which is also a check that it really is
        # acceptable there, the premise the whole delivery model rests on.
        assert raw_txid(claim["hex"]) in node.getrawmempool()
        node.reconsiderblock(claim_block)
        assert_equal(node.gettxout(merged_txid, merged_vout, False), None)

        self.log.info("dynamic-algo activation and reward rules OK")


# ---- Still not covered here ------------------------------------------------------------
#
# The NEGATIVE consensus cases -- a coinbase that omits the required pot or the alpha*r
# payout, or one that mints a pot for another slot -- need a block built by hand rather
# than by this node's own miner, and submitblock checks proof-of-work before it ever
# reaches the reward rules. The Python framework can only solve sha256d, so a hand-built
# Bitmark block has to be mined on slot 1 (SHA256D) with the algo encoded in nVersion.
# Doing that would let this test assert the rejections directly; it is the natural next
# step, and the reason those paths are currently only covered by construction (the miner
# prices from the same ComputeRewardSplit that consensus checks against).


if __name__ == '__main__':
    DynamicAlgoTest().main()
