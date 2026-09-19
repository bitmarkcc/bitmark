# Dynamic-algo execution & mining (design)

Status: DESIGN (2026-09-08). How an ACTIVATED dynamic algo is executed and enforced
in a block: the block format that carries the solution and the dynamic miner's
payout, the wasm execution contract, the reward split, the per-algo Reward Scaling
Factor (RSF), and the reserve-fee mechanism. Companion docs:
`pushcode-port-27xb.md` (push/store/assemble code) and `dynamic-algo-voting.md`
(which branch becomes the algo for a slot, and when).

Every rule added here is a **soft fork**: un-upgraded nodes keep accepting new-rule
blocks; upgraded nodes add restrictions and orphan violators. Where a choice would
have forced a hard fork, we took the UTXO-based path instead. The one place this
matters most is the reserve fees (see that section).

Constants used below:
- `NUM_ALGOS = 8` (Bitmark multi-PoW).
- `BLOCKS_PER_DAY = 720`, so `~90` blocks/day per algo (`720 / NUM_ALGOS`).
- `HASHRATE_CYCLE = 90` **algo-blocks** — one hashrate-measurement cycle for a
  single algo. `90 = 720 / NUM_ALGOS`, and `720` is also the coinbase-maturity depth,
  so a full hashrate cycle is as deep as a matured coinbase.
- `YEAR_BLOCKS = 720 * 365`; `TWO_YEARS = 720 * 365 * 2 = 525600` (also
  `MAX_PUSHCODE_LENGTH`).
- New opcodes (all `OP_NOPx`, i.e. no-ops to old nodes → soft-fork-safe):
  `OP_PUSHCODE = OP_NOP4 = 0xb3`, `OP_VOTE = OP_NOP5 = 0xb4`,
  `OP_SOLUTION = OP_NOP6 = 0xb5`, `OP_RESERVEFEE = OP_NOP7 = 0xb6`.

Throughout, "algo-blocks" means blocks *of one specific algo*, counted alone; each
algo produces ~90 of them per day.

---

## 1. Soft-fork layering

An activated dynamic-slot block still carries a valid BASE PoW on the slot's
primitive algo (scrypt / sha256d / … whichever of the 8). Old nodes verify that base
PoW and accept the block as usual. The dynamic requirements are ADDED on top and
enforced only by upgraded nodes:
- the coinbase commits the dynamic miner's payout,
- the solution is carried in coinbase `OP_SOLUTION` outputs,
- the coinbase reward split follows the algo's α/β,
- reserve-fee outputs obey their covenant.

The base PoW's nonce is ground over a block whose merkle root already commits to the
solution tx (or coinbase-embedded solution), the payout, the coinbase split, and any
reserve activity — nothing can be swapped post-hoc without redoing the PoW. No
separate commitment structure is needed.

Enforcement style mirrors PUSHCODE: the new opcodes are markers (`OP_NOPx`), and the
lifecycle rules live in `ConnectBlock` / a side database, NOT in the script
interpreter. Old nodes ignore the markers; upgraded nodes run the checks. This keeps
the interpreter simple and gives us block context (height, algo, RSF index) that a
pure script opcode wouldn't have.

---

## 2. Block format

Design goal: work SMOOTHLY with the existing 8-algo mining infrastructure, which
gets work via `getblocktemplate` (GBT). In GBT the pool builds its own coinbase from
`coinbasevalue` (max coinbase output value), `coinbaseaux` (scriptSig data) and any
node-dictated required outputs; the non-coinbase `transactions` list it takes as
given. Pools have NO general facility to add arbitrary coinbase outputs, and only
limited control of the coinbase scriptSig (extranonce + aux flags). So the design
keeps the coinbase almost exactly as today and pushes the variable/large data into an
ordinary non-coinbase transaction that rides the `transactions` list. See §6bis for
the full pool-integration story and its compatibility limits.

The three data items — payout, solution, and the dynamic payment — are placed as:

| item | where | why there |
|---|---|---|
| payout scriptPubKey | the **solution tx** (§2.1) | pools can't put it in the coinbase scriptSig cleanly |
| solution chunks | the **solution tx** (§2.2) | variable/large; rides the `transactions` list |
| `α·r` payment | ONE **coinbase output** (§2.3) | must come from subsidy+fees, which only the coinbase emits |

### 2.1 The solution transaction
The dynamic miner computes the solution and builds a single ordinary non-coinbase
transaction (they fund it with a small UTXO of their own — a tx cannot be inputless).
It carries both the payout commitment and the solution chunks, and the block's PoW
commits to it via the merkle root like any tx.

**Payout commitment.** The dynamic miner's payout scriptPubKey is declared in the
solution tx (e.g. as the `seq = 0` header of the solution stream, or a dedicated
marker output). It serves two roles:
1. **Seed binding.** `seed = Hash256(payout_scriptPubKey || prev_block_hash)`. The
   solution is bound to the payout, so no one can redirect the dynamic share by
   rewriting the payout — that changes the seed and the solution no longer verifies.
   (This holds regardless of *where* the payout is committed; a pool that rewrites it
   forfeits the solution and thus the `α·r` payment.)
2. **Payment target.** The coinbase must pay the dynamic share to this scriptPubKey
   (§2.3, §4).

**Solution chunks.** The solution bytes are split across outputs of the solution tx,
each:
```
OP_RETURN OP_SOLUTION <seq> <chunk>
```
- Self-marking, unspendable, 0-value, no UTXO.
- `<seq>` gives a total order: the verifier collects all `OP_SOLUTION` outputs IN THE
  BLOCK, requires `seq = 0..N-1` (contiguous, unique), concatenates → the block's
  solution bytes.
- Self-correcting: the assembled bytes feed `verify()`; a stray/wrong `OP_SOLUTION`
  output changes the bytes and `verify()` fails, so the miner is forced to include
  exactly the intended set.
- Chunk ≤ 520 bytes (`MAX_SCRIPT_ELEMENT_SIZE`). Consensus cap `MAX_SOLUTION_BYTES`
  on the per-block total bounds block size and verification cost.

**Delivery.** In the base model the dynamic miner hands the solution tx to the pool
out-of-band (dynamic miners sell solutions; pools include them and pay the bound
payout), so it need not be relayable. Optionally we can make solution txs relay across
the p2p network so any pool can pick them up — that needs standardness rules for
`OP_SOLUTION` (multiple OP_RETURNs allowed, `MAX_SOLUTION_BYTES`). Start out-of-band;
add relay later (§9).

### 2.2 Alternative: solution in the coinbase
The separate solution tx (§2.1) is the form that makes standard GBT pool integration
smooth — it is NOT a consensus requirement. Because the verifier scans the WHOLE block
for `OP_SOLUTION` outputs, the same chunks may instead be placed directly in the
**coinbase** outputs:
```
coinbase.vout += OP_RETURN OP_SOLUTION <seq> <chunk>   (one per chunk)
```
Both forms are consensus-equivalent: `seq = 0..N-1`, contiguous/unique, concatenated,
total ≤ `MAX_SOLUTION_BYTES`, and the assembled bytes feed `verify()` identically. The
payout may likewise be committed in the coinbase (scriptSig or a marker output) in this
form. A block MUST NOT mix the two — all `OP_SOLUTION` outputs for a block live either
in the coinbase or in exactly one solution tx (the whole-block scan tolerates either,
but keeping them together keeps the `seq` ordering unambiguous).

When to use the coinbase form:
- **Solo miners** building their own block/coinbase — no reason to spend a funding
  UTXO on a separate tx; just append the outputs to the coinbase they already build.
- **Pools running custom Bitmark-aware software** that already assembles the coinbase
  and can add these outputs directly — they may prefer the coinbase form and skip the
  separate tx and its GBT plumbing.

When to use the separate-tx form (§2.1): **stock/unmodified pool software** driven only
by GBT, where the coinbase is off-limits except for the one node-dictated `α·r` output
(§2.3, §6bis). This is the default recommended path for the existing 8-algo pools.

### 2.3 The dynamic payment — the one required coinbase output
The `α·r` payment to the dynamic miner is the ONLY item that must live in the
coinbase, because it is paid out of subsidy+fees which only the coinbase can emit. It
is a single output `(value = α·r, scriptPubKey = payout)`. The node computes `α·r` (it
runs `verify()` on the candidate solution to obtain α) and delivers it to the pool via
a new GBT field (§6bis); the pool appends this one output to the coinbase it already
builds, carving `α·r` out of `coinbasevalue`. This reuses the same GBT mechanism
segwit uses to inject its witness-commitment output — the mechanism only, no segwit is
involved.

### 2.4 Size ceiling
`MAX_BLOCK_WEIGHT = 4,000,000 / WITNESS_SCALE_FACTOR = 4` and no segwit, so effective
block size ≈ 1 MB and `weight = 4 * size`. If the block is otherwise empty the
solution tx can use almost all of it, so a single block's solution is ≤ ~1 MB.
Whatever an algo needs to validate ONE block must fit in that block.

### 2.5 Multi-block solutions
`verify()` input 1 is "the n previous slot blocks", so an algo may also read the
`OP_SOLUTION` outputs of prior slot-blocks (found by the same whole-block scan). A
running data stream (e.g. accumulating LLM LoRA deltas) SPANS multiple blocks: each
block contributes its chunk; `verify()` for the current block uses the window. `n` is
bounded by the pruned-node keep window (`MAX_PUSHCODE_LENGTH` + the per-slot floor,
see `pushcode-port-27xb.md`), so the whole stream is guaranteed on disk. Pure hash-PoW
algos (keccak/whirlpool) ignore the window and use only the current block's chunk (the
nonce).

---

## 3. Dynamic-algo I/O contract

```
int verify(prev_hash,                 // input 4: 32 bytes
           payout, payout_len,        // input 3
           nbits,                     // input 5: u32 compact target
           txs, txs_len,              // input 2: current block's non-coinbase txs
           last_n_blocks, last_n_len, // input 1: the n previous slot blocks
           solution, solution_len,    // the block's assembled OP_SOLUTION bytes
           out_ab)                    // OUT: 8 bytes = α (u32) || β (u32), LE
  -> 0 iff the solution is VALID (meets the per-slot difficulty), else non-zero.
```
`α, β` are written as two little-endian **`u32` in Q32 fixed point** — the stored
integer is `value · 2^32`, i.e. `α = out_ab[0..4] / 2^32`. The whole `u32` range maps
onto `[0, 1)`, so `0 ≤ α, β < 1` is automatic (no validity check, no NaN/Inf/negative
cases). The node's reward math is then pure integer (§4.4); the module does any
float→fixed scaling internally, where wasm's IEEE-754 `f32` is deterministic (validated
bit-identical cross-machine for the llm.c verifier) — but no float ever crosses the ABI
or enters the node's money path.

`α, β` are deterministic functions of the block CONTEXT (inputs 1,2,4,5), NOT of
`solution`, so they are defined even when the solution is absent/invalid (the node
calls `verify()` with an empty solution just to read `α, β` in the no-solution case).
`seed = Hash256(payout || prev_block_hash)`.

The reference algos `whirlpool_algo.c` / `keccak_algo.c` implement this signature,
writing `α = β = 0.5` (`0x80000000` in Q32) on a valid solution and `α = 0, β = 0.5` on
no valid solution — recovering the r/2 // r/4 split.

---

## 4. Reward split (α / β) — "middle option"

Let `r = subsidy + fees` be the FULL reward for the block (subsidy after Bitmark's
mPoW scaling, plus the fees the coinbase actually claims — i.e. total fees minus any
amounts diverted into reserve contracts this block, §6). Fees are inside `r` on
purpose: in the fee-dominated future (subsidy → 0) dynamic miners must still be paid,
which only works if they get a cut of fees.

`α, β` come from `verify()`; consensus REJECTS the block unless `0 ≤ α < 1` and
`0 ≤ β < 1`.

- **Valid solution present:**
  - dynamic miner (payout scriptPubKey): `α · r`
  - primitive miner: `(1 − α) · r`
  - emitted subsidy = full subsidy `S`.
  - The dynamic miner's share is protocol-set (`α·r`), NOT chosen by anyone: the
    dynamic miner only supplies the payout address, and the primitive miner (who builds
    the coinbase) MUST pay `≥ α·r` to it — a floor, enforced by consensus. Under-payment
    is disallowed, because if the primitive miner could pay less they always would, and
    the dynamic miner would have no reason to ever produce a solution. See §4.3.
- **No / invalid solution:**
  - dynamic miner: `0`
  - primitive miner: `β · (1 − α) · S  +  F`  (the **fee remainder is never burned** —
    the primitive miner keeps all fees `F`; only the *subsidy* is scaled by
    `β(1−α)`).
  - emitted subsidy = `β · (1 − α) · S`; the un-emitted subsidy `S − β(1−α)S` is
    **milestone-deferred** (Bitmark emission halves/quarters at cumulative-emission
    milestones, not heights), so it is emitted by later blocks, not destroyed.

Fixed `α = β = 1/2` recovers the original scheme (solution → S/2 dynamic + S/2
primitive; no solution → S/4 primitive), all with fees always fully to the primitive
miner.

### 4.1 Why this is soft-fork-safe
The coinbase only ever claims `≤ subsidy + fees`: the α/β split partitions `r`, and
the no-solution case claims *less*. Old nodes accept any coinbase claiming ≤ their
maximum. (The only thing that would claim MORE than `subsidy + fees` is releasing
previously-reserved value — handled as a UTXO spend in §6, not a coinbase over-claim.)

### 4.2 The inclusion incentive
The primitive miner CHOOSES whether to include the solution. With subsidy `S`,
available fees `F`, and opportunity cost `c` = the extra fees a ~1 MB solution
displaces (fees collectable *without* including it):
```
include  ⇔  (1−α)(S+F) > β(1−α)(S+F+c)  ⇔  c < (1−β)/β · (S+F)
```
`α` cancels — it sets the dynamic/primitive SPLIT but not the include decision. `β`
is the lever: `β→0` ⇒ include almost anything; `β = 1/2` ⇒ include iff `c < S+F`;
`β→1` ⇒ never include. The community-voted algo tunes `α, β` (two Q32 `u32` outputs) to
balance dynamic-miner pay against inclusion pressure. Note that large solutions have
large `c`, so LLM-scale payloads face pressure to keep per-block chunks small (the
multi-block spanning of §2.5 helps).

### 4.3 Payment floor — the dynamic miner cannot be cheated
Nobody *chooses* the dynamic miner's amount; the protocol sets it at `α·r` and the
primitive miner must honour it. Two consensus rules make this robust even though the
primitive miner builds the coinbase and receives the solution out-of-band first:

- **Floor, not ceiling.** The coinbase must pay `≥ α·r` to the payout scriptPubKey
  (`==` in practice, since a rational primitive miner never over-pays). Paying less is
  invalid. Without this floor the primitive miner would pay ~0 and the dynamic miner
  would never bother producing a solution.
- **Seed binding stops redirection.** `seed = Hash256(payout ‖ prev_hash)`, so a
  primitive miner who points the payment at their own address changes the seed, and the
  solution no longer verifies → not a valid solution-block.

So once the primitive miner holds the solution, their only valid moves are: pay the
protocol-set `α·r` to the bound payout (keeping `(1−α)·r + fees`), or don't use the
solution (falling back to `β·(1−α)·S + F`). They can neither steal the dynamic share
nor pay less than `α·r`. This is what makes the dynamic miner's incentive credible.

### 4.4 Satoshi arithmetic — deterministic, integer-only
`α, β` arrive as Q32 `u32` (§3), so `α_q, β_q ∈ [0, 2^32)` with `α = α_q / 2^32`. There
is NO float→integer decode on the node: the module already emitted integers (chosen
over an `f32` ABI precisely to keep the node's money path float-free and cheaper). All
reward math is then integer with a single fixed-point multiply-floor:
```
fp_mul(x, q) = floor( x · q / 2^32 )
```
computed with a WIDE intermediate — `x·q` can reach ~2^66 — via `arith_uint256`
(already in consensus, portable, avoids `__int128`): `(arith_uint256(x) * q) >> 32`,
take the low 64 bits.

With `r = subsidy + claimable_fees`, `S = subsidy`, `F = claimable_fees`:
- **Valid solution:**
  - `dyn = fp_mul(r, α_q)` — the dynamic miner's amount `= floor(α·r)`; the §4.3 floor
    is "coinbase pays `≥ dyn` to the payout".
  - `prim = r − dyn` — give the primitive the **remainder**, not an independently-floored
    `(1−α)·r`, so `dyn + prim = r` exactly (no rounding gap, never over-claims).
  - emitted subsidy = `S`.
- **No solution:**
  - `emitted_subsidy = fp_mul( fp_mul(S, 2^32 − α_q), β_q )` = `⌊β·(1−α)·S⌋`-ish.
  - coinbase claims `≤ emitted_subsidy + F`. Since `2^32 − α_q ≤ 2^32` and `β_q < 2^32`,
    each `fp_mul` caps the result `≤ S`, so the coinbase can never over-claim vs old
    nodes — soft-fork-safe (the tiny sub-satoshi rounding of `(1−α)` cannot break it).

Everything floors downward, uses the same `fp_mul` on every node, and is constructed so
the total is always `≤ r`. RESOLVED (was the last open reward-math item).

---

## 5. Reward Scaling Factor (RSF)

The RSF is a per-algo measure of how close an algo's hashrate is to its own recent
peak. It is the knob the reserve-fee mechanism (§6) uses to decide how much reserved
fee an algo's miners have earned back. Its purpose (per the 2018 design, bitcointalk
4998410) is **anti-collusion / 51%-resistance**: make suppressing an algo's hashrate
forfeit real revenue, so miners can't profitably drive out competition to weaken an
algo.

### 5.1 Definition (per algo, linear, in arrears)
For algo `a`, measured over `HASHRATE_CYCLE = 90` algo-`a`-blocks:
```
h^a(H) = work over the 90 algo-a-blocks ending at height H, divided by the elapsed
         time (medianTimePast of the last vs first of those blocks — MTP resists
         timestamp manipulation).
p^a(H) = max h^a over the trailing year (365 such 90-algo-block windows), INCLUDING
         the current window.
s^a(H) = h^a(H) / p^a(H).
```
Because `p^a` includes the current window, `h^a ≤ p^a` by construction, so
`s^a ∈ [0,1]` is the exact **linear, monotone-increasing** map onto `[0,1]` (0 at
zero hashrate, 1 at a fresh peak) — no clamp needed.

**In arrears by one cycle.** Any RSF value used by consensus at a block of height `t`
is evaluated at `H = t − HASHRATE_CYCLE` **algo-blocks** (i.e. skip back 90 blocks of
that algo). This makes the measurement window as buried as a matured coinbase (~720
total blocks), so it can't be wobbled by recent blocks or a shallow reorg, and
removes the incentive to grind fresh-tip timestamps.

Implementation nicety: maintain a per-height, per-algo RSF index so `s^a(H)` is an
O(1) lookup instead of re-walking ~365 windows. It is computable from **headers
alone** (nBits→work, timestamps→MTP, version→algo), so even a fully-pruned node can
recompute any historical RSF — important for §6's 2-year-old contracts.

Note: this RSF is distinct from Bitmark's existing per-algo subsidy scaling (SSF) in
mPoW; the RSF here governs only the reserve-fee release. It is "applied to fees" in
the opt-in sense of §6, not as a blanket subsidy scaling.

---

## 6. Reserve fees

An opt-in mechanism by which a user makes part of a transaction's fee
**hashrate-contingent**: released to an algo's miners as that algo's hashrate
recovers, refundable to the user if it doesn't. This is the on-chain realization of
the 2018 reserve-fee idea. **Soft fork, no UTXO-set bloat beyond transient reserve
outputs.**

Design decisions locked in discussion:
- **Option A**: each contract is tied to ONE algo, chosen by the user (wallet RPC
  defaults to a random 1..NUM_ALGOS). Only that algo's blocks may claim it, gated on
  that algo's RSF recovery. (Simplest UTXO/covenant; punishes per-algo suppression
  directly. Alternatives B/global-pool-self-gated and C/proportional-split were
  considered and rejected — see the discussion log.)
- **Proportional release with rollover**, anchored to the RSF at creation.
- **Height-anchored, not hash-anchored** (§6.4).
- **2-year refund DEADLINE** (not a timelock): the user may reclaim the un-recovered
  remainder within two years; after that any miner may sweep it (§6.3).

### 6.1 The output
```
output = ( V , "<algo> <H_orig> <refund_spk> OP_RESERVEFEE" )
```
- `V` — the reserved amount (satoshis). **The user chooses `V`**; it is diverted from
  the fee (the tx over-pays its fee by `V`). Diversion = the coinbase under-claims by
  `V`, which old nodes accept (they see `V` as unclaimed/donated fee) → soft-fork-safe.
- `algo ∈ 1..NUM_ALGOS` — user-chosen algo this contract rewards.
- `H_orig` — the creation height, carried purely for the 2-year refund deadline
  (§6.3). Validated `== actual creation height` once at birth, then preserved by the
  covenant across rollovers so miners can't reset the refund clock.
- `refund_spk` — where a refund is paid.
- `OP_RESERVEFEE = OP_NOP7` — a no-op to old nodes, so the output is anyone-can-spend
  under old rules; upgraded nodes enforce the covenant below in `ConnectBlock`.

### 6.2 Baseline & the free `s0` ratchet
The RSF baseline for a reserve output is `s0 = s^algo(coin_height − HASHRATE_CYCLE)`,
where `coin_height` is the output's OWN creation height (from the coins database).
Nothing about `s0` is stored — it's recomputed from the coin's height.

This gives the ratchet for free: a rollover output (§6.3) is created at the claim
height, so its `coin_height` IS the bumped baseline. Successive claims therefore
anchor to successively higher heights with no stored/mutated `s0`. (The stored
`H_orig` is only the refund clock, not the RSF baseline.)

### 6.3 Lifecycle

**Claim (keyless; any algo-`algo` block → miner).** When
`s_t = s^algo(t − HASHRATE_CYCLE) > s0`, a claim is a normal transaction, mined in an
algo-`algo` block, that spends the reserve UTXO and routes value as:
```
claimable = floor( V · (s_t − s0) / (1 − s0) )   // 0 if s_t ≤ s0 ; V if s_t = 1
```
- `claimable` is left unassigned → becomes the block fee (the miner's take).
- if `claimable < V`, the remainder `V − claimable` MUST reappear as a fresh reserve
  output `(V − claimable, "<algo> <H_orig> <refund_spk> OP_RESERVEFEE")` (same
  `algo`, same `H_orig`, same `refund_spk`; new `coin_height` ⇒ bumped baseline).
- `scriptSig = OP_0` (path selector 0) — **no signature**. Safe because the covenant
  proves the value can only become miner-fee + a same-terms rollover; the only party
  who profits is the block's miner, who includes the tx in their own block.
- Enforced (ConnectBlock): the spending block's algo `== algo`; `claimable` computed
  from the recomputed `s0` and `s_t`; the rollover output is exact.

Telescoping check: releasing at `s1` then `s2 (> s1 > s0)` leaves
`V·(1−s1)/(1−s0) · (1−s2)/(1−s1) = V·(1−s2)/(1−s0)`, i.e. release depends only on the
running max — so the ratchet is path-independent.

The `TWO_YEARS = 720·365·2` blocks from `H_orig` is a **refund DEADLINE, not a
timelock**: the user has two years to reclaim the un-recovered remainder; after that it
defaults to miners. So there are two more paths besides the claim above.

**Refund (signed; user; BEFORE 2 years).** While `spending_height − H_orig < TWO_YEARS`,
`refund_spk` may reclaim the current `V_remaining` to a normal spendable output.
- `scriptSig = <sig> <refund_pubkey> OP_1` (selector 1 + refund authorization).
- Enforced (ConnectBlock): `spending_height − H_orig < TWO_YEARS`; the full
  `V_remaining` paid to `refund_spk`; valid signature; and `s_t ≤ s0` (current RSF not
  above the ratchet baseline) so the user can only pull the **un-recovered** remainder,
  never money a recovering algo's miners have earned but not yet claimed.
- This is the user's "hashrate isn't coming back, give me my fee back" option, and the
  anti-suppression tool: an active user reclaims on suppression, denying the reserve to
  the miners who suppressed.

**Expiry sweep (keyless; ANY miner; AFTER 2 years).** Once
`spending_height − H_orig ≥ TWO_YEARS`, ANY block (any algo) may claim the FULL
`V_remaining` unconditionally — the same keyless claim path as above, but with
`claimable = V_remaining` and NO RSF gate and NO algo gate.
- `scriptSig = OP_0`.
- Enforced (ConnectBlock): `spending_height − H_orig ≥ TWO_YEARS`; full `V_remaining`
  becomes the block fee. (No `block algo == algo` check — deliberately.)
- Why ANY miner, not the contract's algo `a`: a remainder surviving to the 2-year mark
  means algo `a` did NOT recover (had it recovered, the proportional claim path would
  already have drained it). Routing that to algo-`a` miners would reward the very algo
  that stayed suppressed — backwards for an anti-suppression mechanism. Treating it as
  generic abandoned value claimable by any miner (Bitmark's "un-emitted value defaults
  to miners" default) avoids that, is simpler (drops the algo gate the recovery path
  needs), and lets the most active algos — which mine the most blocks — naturally grab
  the most sweeps, gently favouring healthy algos.
- Rationale for the sweep at all: a user who never reclaimed within two years forfeits,
  so abandoned contracts never linger as locked dust. Active users are unaffected —
  they had two years, and the suppression case is exactly when they'd reclaim.

Asymmetry: the miner paths (recovery claim, expiry sweep) are **keyless** (fully
constrained by the covenant); the refund path is **signed** (only the user, only within
the two-year window, only the un-recovered part).

### 6.4 Why height, not hash — and reorg safety
The RSF baseline anchors to the reserve output's OWN creation height, and a coin's
ancestry is pinned by the coin's existence:
- Recomputing `s0` reads a window that is entirely **ancestors of the output**. As
  long as the output is on the active chain, that window is fixed; a reorg deep enough
  to change it necessarily **orphans the output** (and any claim spending it). Baseline
  and output cannot diverge. The one-cycle-in-arrears rule (§5.1) buries the window
  ~720 blocks deep, strengthening this.
- A block **hash** would anchor to one specific block regardless of chain: if it were
  reorged off the output's chain the reference would **dangle**. Height-relative-to-the-
  output can't dangle. So height is strictly better here.

Attacks considered, none profitable:
1. *Reorg to lower `s0` and claim more* — must reorg the output's ancestor window,
   which orphans the contract and the claim; you'd re-mine days of blocks to steal one
   contract's `V`.
2. *Timestamp-faking hashrate* — MTP (median of 11, future-bounded) caps it.
3. *User choosing a favorable reference* — she can't; the baseline is her output's own
   height, and `H_orig` is validated `== creation height`, so she can neither lower
   `s0` nor move her refund clock. She only picks `algo`.
4. *Shallow reorg near the 2-year boundary* — shifts the deadline by a few blocks out
   of 525,600; noise.
Every "current" RSF (`s_t`) is computed from the claim/refund block's own ancestry and
validated in that block's context, so it is reorg-safe by construction.

### 6.5 State & bloat
Reserve outputs live in the UTXO set (that's what keeps it a soft fork — the value is
never destroyed-and-recreated, only spent). But they are **transient**: each claim
drains them and rolls a smaller remainder forward; a fully-recovered algo empties its
contracts, and a refund removes them. So the worst-case ~2× UTXO growth is rarely
approached and never permanent. No per-contract side database is required; the coins
DB plus the header-derived RSF index suffice.

---

## 6bis. GBT / pool integration & migration

The existing 8 sets of miners get work via `getblocktemplate`. This section states
exactly what changes for them and, honestly, what does NOT work with unmodified
software.

### 6bis.1 The new GBT field
When the node has a candidate solution for the next block of an active slot, it adds
one field to the GBT result:
```json
"dynamic": {
  "scriptPubKey": "76a914…88ac",   // the dynamic miner's payout spk
  "value": 625000000               // α·r in satoshis, computed by the node
}
```
and includes the solution tx in the `transactions` list. The node computed `value`
by running `verify()` on the candidate (so it knows α); the pool never touches wasm.
The pool builds its coinbase as usual and appends one output
`(value, scriptPubKey)` from this field, carving `α·r` out of `coinbasevalue`.

This is the **same GBT delivery mechanism segwit uses** for `default_witness_commitment`
— the node computes a required coinbase output and the pool pastes it in from a field.
NO segwit is involved here (segwit is inactive on Bitmark, `SegwitHeight = INT_MAX`);
we are reusing the mechanism, not segwit. The one structural difference: the segwit
commitment is a 0-value marker, whereas our output carries value (`α·r`) and pays a
real address — so it is a required *payment*, which is why the node must also tell the
pool the amount.

### 6bis.2 What this means for existing software — honestly
There is no magic: an unmodified pool ignores the `dynamic` field, so it will NOT add
the `α·r` output. Consequences:

- **Unmodified pool, no solution available.** GBT returns a normal template with a
  lower `coinbasevalue` (`β·(1−α)·S + F`, §4) and no `dynamic` field. The pool mines
  exactly as today and produces a **valid** block (just a smaller subsidy). The
  network is safe; nothing breaks. This is the common case for any block without a
  solution, so most mining looks exactly like today.
- **Unmodified pool + a solution exists.** The pool never learns to include the
  solution tx or add the output, so it simply keeps mining no-solution blocks. It
  forfeits the dynamic bonus but stays valid.
- **To actually earn the dynamic reward**, the pool must support the `dynamic` field.

So "backward compatible" here means **unupgraded pools keep producing valid blocks via
the no-solution path** — NOT "unupgraded pools automatically collect dynamic rewards."
Earning the reward requires an update. This is exactly the segwit history: pools had
to update once to read `default_witness_commitment`; it is "universally supported" now
only because everyone updated years ago, not because it was automatic.

### 6bis.3 Two migration paths
1. **Patch the pool software** to read `dynamic` and append the one output. Trivial
   code, but touches each pool's codebase.
2. **A proxy/shim** between the node and stock pool software that intercepts GBT and
   injects the dynamic output into the template (and/or assembles the coinbase). This
   is how merged-mining / auxpow integrations avoid modifying core pool software, and
   is likely the realistic adoption path since it works with unmodified pool binaries.

Custom Bitmark-aware pools (and solo miners) can instead use the **coinbase-embedded**
solution form (§2.2) and skip the separate tx and the `dynamic` field entirely.

### 6bis.4 Adoption incentive
Opt-in and gradual, but self-enforcing like segwit: a pool that updates captures value
it otherwise leaves on the table (the α/β economics of §4.2), so money pulls pools
along without any flag-day requirement.

---

## 7. ConnectBlock enforcement (putting it together)

For a block on slot/algo `a` at height `t` whose slot has an active algo (evaluated on
the parent chain per `dynamic-algo-voting.md`, so a block can't self-activate):

1. **Base PoW** verified as today (old-node path).
2. **Fees.** `total_fees = Σ tx fees`. `reserved = Σ V` of new `OP_RESERVEFEE`
   contracts created this block. `claimable_fees = total_fees − reserved`. Reserve
   *claims* (§6.3) appear as ordinary fees from their spending txs and are inside
   `total_fees`; the covenant checks below gate their validity.
3. **Solution & payout.** Scan the WHOLE block for `OP_SOLUTION` outputs (in the
   solution tx per §2.1, or the coinbase per §2.2), order by `seq` (0..N-1,
   contiguous/unique, total ≤ `MAX_SOLUTION_BYTES`), concatenate. Read the committed
   `payout_scriptPubKey` from the same source. (If no `OP_SOLUTION` outputs exist,
   there is no solution this block → go to the no-solution branch of step 6.)
4. **Execute.** Load the slot's materialized algo module; run
   `verify(prev_hash, payout, nbits, non-coinbase txs, last n slot blocks, solution,
   out_ab)` under the gas/memory limits (§8). A limit breach or module fault ⇒ invalid.
   Require `0 ≤ α < 1`, `0 ≤ β < 1`. For the no-solution branch, run `verify()` with an
   empty solution solely to read `α, β`.
5. **Reward split** (with `r = subsidy + claimable_fees`, integer α,β per §4.4):
   - `verify()==0`: the coinbase must contain the one required output paying `≥ α·r`
     to `payout_scriptPubKey` (§2.3); total coinbase value `≤ r`; emitted subsidy = `S`.
   - else: coinbase subsidy `≤ β·(1−α)·S` (fees still fully claimable); emitted subsidy
     = `β·(1−α)·S`; defer the rest via the milestone accounting.
6. **Reserve covenant.** For each spend of an `OP_RESERVEFEE` output, enforce §6.3 by
   path:
   - *recovery claim* (age `< TWO_YEARS`, keyless): block algo == contract algo,
     `s_t > s0`, correct `claimable`/rollover;
   - *refund* (age `< TWO_YEARS`, signed): `s_t ≤ s0`, full `V_remaining` to
     `refund_spk`, valid sig;
   - *expiry sweep* (age `≥ TWO_YEARS`, keyless): any algo, full `V_remaining` → block
     fee.
   For each new `OP_RESERVEFEE` output, enforce `H_orig == t` and well-formed fields.
7. **Milestone accounting** updated with the ACTUAL emitted subsidy (never counting
   deferred subsidy as emitted).

Determinism: everything is a function of the confirmed chain + the block. The
materialized algo, the gas instrumentation (§8), and the header-derived RSF index make
validation identical across nodes. Reorg safety comes from ordinary
`ConnectBlock`/`DisconnectBlock` symmetry (reserve outputs are just coins; the RSF
index rebuilds from headers).

---

## 8. Execution runtime (recap; full detail in the voting doc)

- Runtime: **wasm3** (pure C, no Rust), embedded in bitmarkd. Deterministic for
  integer algos; f32 is IEEE-deterministic.
- Memory bound: a linear-memory page cap enforced by the runtime.
- CPU bound: **gas by bytecode instrumentation** (a fixed cost table compiled into the
  module), not a runtime fuel counter, so the gas count is identical on every node.
  STILL UNCLEAR / may change — shared open item with the voting doc.
- The node marshals inputs above `__heap_base` and calls `verify()` with the offsets;
  reads the i32 result and the 8-byte `out_ab` (two Q32 `u32`, §3). `host.c` is the
  working prototype. No float crosses the ABI, so the node's money path is integer-only.
- Grinding resistance: the seed's payout half is miner-controlled, so an LLM algo's
  validation-set selection must itself be grinding-resistant; the prev-block-hash half
  is not grindable without redoing that block's PoW.

---

## 9. Open items / parameters

- `MAX_SOLUTION_BYTES` value; exact payout-commitment layout in the solution tx (or
  coinbase) and how the verifier locates it.
- `submitsolution`-style RPC for handing a solution tx to the node, and the node-side
  template policy that injects it + the `dynamic` GBT field (§6bis).
- Relay of solution txs: keep out-of-band, or add `OP_SOLUTION` relay standardness
  (multiple OP_RETURNs, `MAX_SOLUTION_BYTES`) so solutions propagate p2p (§2.1).
- Gas metering mechanism (shared with the voting doc).
- Materialized-algo store: format and where the ~8 activated modules live; re-vote
  swap-in.
- Per-height/per-algo RSF index: storage format and rebuild-on-reindex.
- Data availability of LLM validation examples: inline merkle-branch proofs carried in
  the `OP_SOLUTION` stream (fold the proof format in — see the voting doc).
- Reserve refund anti-race: the refund is gated on `s_t ≤ s0` so the user can only pull
  the un-recovered remainder. Confirm this gate is sufficient (vs. refunding only the
  instantaneously-un-recovered `V·(1−s_t)/(1−s0)` amount) — RESOLVED as the `s_t ≤ s0`
  gate for now; revisit if RSF churn strands honest refunds.
