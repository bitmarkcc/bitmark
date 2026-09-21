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
- `YEAR_BLOCKS = 720 * 365`. `TWO_YEARS` (the reserve-fee expiry) is the per-chain
  consensus param `nReserveFeeExpiry` = `720*365*2 = 525600` on main/test/signet
  (= `MAX_PUSHCODE_LENGTH`), and a small value on regtest (`720*14`) for testability.
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

With `r = subsidy + total_fees`, `S = subsidy`, `F = total_fees`:
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

The reserve-fee mechanism uses only the **current** RSF `s_t = s^a(claim_height −
HASHRATE_CYCLE)`, computed here. The **baseline** `s0` a contract is measured against is
NOT computed from the chain — it is a user-declared constant stored in the output (§6.1),
so `s0` needs no RSF lookup and is fixed for the life of the contract.

---

## 6. Reserve fees

An opt-in mechanism by which a user makes part of a transaction's value
**hashrate-contingent**: released to one algo's miners *while* that algo sustains
hashrate above a chosen threshold, and refundable to the user if it doesn't. On-chain
realization of the 2018 reserve-fee idea. **Soft fork**; the reserve lives in a
spendable covenant UTXO (never off-UTXO state), which is what makes releasing it later
— as an ordinary spend — soft-fork-safe.

Design (as settled in discussion):
- **Flow model, not ratchet.** Miners earn a *stream* while `s_t > s0` (sustained
  hashrate above the baseline), faster the higher `s_t` is — rather than a one-time
  payment for reaching new RSF peaks. The ratchet/peak model was dropped: it creeps the
  baseline toward the peak, herding miners into the `~0.975p–p` region where the SSF
  subsidy misbehaves and the payout formula (`1−s0 → 0`) is ill-conditioned. Flow keeps
  a fixed, moderate baseline and rewards *sustaining* hashrate, which better matches the
  anti-suppression goal. Rate constant `k = 1` (global).
- **One algo per contract** (`<algo>`), user-chosen. Only that algo's blocks may claim
  it — punishes per-algo suppression directly. (Alternatives: a global pool split
  across algos was considered and rejected — see the discussion log.)
- **Baseline `s0` is stored directly** as a user-declared threshold, NOT derived from a
  reference block — simpler covenant (no lookup) and predictable at build time. `s0`
  only affects the user's own contract economics, never security, so a user-set value
  is safe. No ceiling on `s0` is needed: the 2-byte Q16 encoding already keeps `s0 < 1`,
  so `denom = 2^32 − s0 ≥ 0x10000` (no `1−s0 → 0` division issue) — a high `s0` just makes
  a "demanding" contract that pays only near the peak, which is the user's own choice.
- **2-year clock from the output's own confirmation height** — no stored origin height
  (see §6.3); a flow-specific simplification.

### 6.1 The output
```
output = ( V , "<algo> <s0> <refund_pkh> OP_RESERVEFEE" )   // SPENDABLE, TxoutType::RESERVEFEE
```
- `V` — the reserved amount (satoshis). The user **funds this like any output** (from
  the tx's inputs). It is a real UTXO, *not* left as fee: value can only move by being
  spent, so a real output is what lets it later flow to miners (claim) or back to the
  user (refund) without looking like inflation to old nodes. Miners collect their share
  when a **claim tx leaves the released slice as fee**.
- `algo ∈ [0, NUM_ALGOS)` — the `Algo` enum value (SCRYPT=0 … CRYPTONIGHT=7) whose
  recovery pays this contract out (1-byte push / `OP_1..OP_16`, or `OP_0` for algo 0).
- `s0` — baseline RSF threshold, a **2-byte Q16** value (`s0 = u16 / 2^16`), scaled to
  Q32 for the arithmetic. The Q16 range already keeps `s0 < 1`; no extra ceiling.
- `refund_pkh` — 20-byte HASH160 that authorizes the user's refund.
- `OP_RESERVEFEE = OP_NOP7` — a defined no-op to the interpreter, so the output is
  anyone-can-spend at the script level; the covenant enforces all real rules in
  `ConnectBlock`.

The spend path is chosen by a **scriptSig selector**: `0` = claim, `1` = refund
(`<sig> <pubkey> 1`), `2` = sweep.

### 6.2 Release (flow, k = 1, one claim per period)
The current RSF `s_t = get_rsf(claim_block, algo)` is the RSF over the last
`HASHRATE_CYCLE` (`nSSF = 90`) algo-`algo` blocks before the claim — the just-ended
period (the claiming block is excluded from the window, so its miner can't nudge it);
`s0` is read straight from the output. While `s_t > s0`, the reserve pays out one release
per period:
```
claimable = min( V_rem , floor( V_rem · (s_t − s0)/(1 − s0) ) )
```
`s0` is **fixed** (no ratchet). A **90-algo-block maturity** on the reserve UTXO (a
rollover can't be re-claimed until `HASHRATE_CYCLE` more algo-`algo` blocks pass) enforces
at most one claim per period, so `V_rem` drains one period-fraction at a time and pauses
whenever `s_t ≤ s0`. Higher `s_t` ⇒ larger fraction ⇒ faster drain ("faster if higher").
(No per-block `Δ` multiplier — the maturity gives the period cadence; a multi-period
batching factor can be added later.)

### 6.3 Lifecycle (three paths — all release to FEE)

The spend path is selected by the **first push of the input's scriptSig**: `0` = claim,
`1` = refund, `2` = sweep. **All three send the reserve's released value to FEE** (the
block miner) — no path ever mints a spendable output from the reserve, so a reserve fee
stays a fee forever and never bloats the UTXO set. Per spending tx, the covenant requires
`txfee ≥ Σ(released value of every reserve input)`, so the released value genuinely
becomes fee (by fungibility, a fee at least that large means the spender paid it to the
miner regardless of internal routing).

**Claim — keyless; dedicated tx; algo-`algo` block; `s_t > s0`; mature.** A claim tx
spends EXACTLY ONE reserve UTXO (selector `0`) and has EXACTLY ONE output: the rollover
`(V_rem − claimable, same <algo> <s0> <refund_pkh>)` if `claimable < V_rem`, or a single
0-value `OP_RETURN` if `claimable == V_rem` (full drain). `fee = claimable → block miner`.
Enforced (ConnectBlock): block algo `== algo`; maturity (≥ `HASHRATE_CYCLE` algo-`algo`
blocks since coin_height); `s_t > s0`; correct `claimable` (§6.2); the single
rollover/`OP_RETURN` output. The dedicated one-in/one-out shape makes the rollover
unambiguous and forces `claimable → fee`.

**Refund — user-signed fee-redirect; `s_t ≤ s0`; before 2 years.** The user gets NO
spendable output; instead they spend the reserve UTXO as an input to a transaction of
their own, and its `V_rem` becomes that tx's **fee** — so the reserve funds a tx the user
was making anyway (any miner, on their own schedule) instead of the suppressed algo.
scriptSig = `<1> <sig> <pubkey>`. Enforced: `HASH160(pubkey) == refund_pkh`; a valid
`SIGHASH_ALL` signature (reuse `TransactionSignatureChecker`, scriptCode = the reserve
scriptPubKey — commits to the outputs, so no malleability); `s_t ≤ s0`; `age < TWO_YEARS`;
and the per-tx `txfee ≥ V_rem` rule. `refund_pkh` authorizes WHO may redirect (only the
user — a griefer can't dump the credit early); it is NOT a payout address. The suppressed
algo is denied the reserve either way; here the value stays in the mining economy (some
later, any-algo miner) and the user's benefit is fee-funding, not money back.

**Expiry sweep — keyless; ANY miner; age ≥ 2 years.** After
`age = claim_height − coin_height ≥ TWO_YEARS`, anyone may spend the reserve UTXO as a fee
input (selector `2`, no signature, no RSF/algo gate); `V_rem → fee` via the same per-tx
`txfee ≥ V_rem` rule. Because coin_height only advances via real claims (`s_t > s0`,
draining value), `age ≥ TWO_YEARS` implies the contract sat stuck below baseline for two
years, so the sweep only fires on genuinely abandoned contracts. Any algo — a
never-recovered contract shouldn't reward the algo that stayed suppressed.

**Creation.** A new `OP_RESERVEFEE` output (including a claim's rollover) is valid only
if `algo ∈ [0, NUM_ALGOS)` (the `Algo` enum value). `s0` needs no range check — the Q16
encoding already keeps it `< 1`.

**Why the 2-year clock needs no stored origin.** The clock runs from the *current*
output's coin_height. A miner cannot cheaply keep resetting it: advancing coin_height
requires a **claim**, which needs `s_t > s0` and **drains real value**. Once hashrate
falls below baseline, claims stop, coin_height freezes, and the clock runs. (Under the
abandoned ratchet model a sliver-claim could reset the clock for free — which is why
that model needed a stored origin height; flow doesn't.)

### 6.4 Reorg safety
`s0`, `algo`, `refund_pkh` are constants in the output — trivially reorg-stable. The
only chain-derived quantity, the current RSF `s_t`, is computed **in arrears** (§5.1)
from the claiming block's own ancestry and validated in that block's context, so it is
reorg-safe by construction; `Δ` and `age` are likewise functions of the output's own
coin_height and the claiming height. MTP (median-of-11, future-bounded) caps
timestamp-faking of the hashrate measurement.

### 6.5 State & bloat
Reserve outputs live in the UTXO set (that's what keeps this a soft fork — value is only
ever spent, never destroyed-and-recreated). They are **transient**: claims drain them
and roll a smaller remainder forward, recovery empties them, a refund/sweep removes
them, and only one live reserve UTXO exists per contract at a time. No side database —
the coins DB plus the header-derived RSF index (§5) suffice.

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
2. **Fees.** `total_fees = Σ tx fees`, and the coinbase may claim all of them.
   Creating a reserve output does NOT reduce fees — `V` is a normal output the user
   funds from their own inputs (§6.1), not a fee diversion. Reserve *claims* (§6.3)
   appear as ordinary fees from their spending txs (the released slice left unassigned)
   and are already inside `total_fees`; the covenant checks in step 6 gate their
   validity.
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
5. **Reward split** (with `r = subsidy + total_fees`, integer α,β per §4.4):
   - `verify()==0`: the coinbase must contain the one required output paying `≥ α·r`
     to `payout_scriptPubKey` (§2.3); total coinbase value `≤ r`; emitted subsidy = `S`.
   - else: coinbase subsidy `≤ β·(1−α)·S` (fees still fully claimable); emitted subsidy
     = `β·(1−α)·S`; defer the rest via the milestone accounting.
6. **Reserve covenant** (all release paths send value to FEE). For each spend of an
   `OP_RESERVEFEE` output, dispatch on the scriptSig selector and enforce §6.3
   (`age = t − coin_height`):
   - *claim* (selector 0, keyless): dedicated 1-in/1-out tx, block algo == contract
     `algo`, mature (≥ `HASHRATE_CYCLE` algo-blocks), `s_t > s0`, correct flow
     `claimable > 0` (§6.2), the single `<algo> <s0> <refund_pkh>` rollover output
     (`= V_rem − claimable`); `fee == claimable` by the 1-in/1-out shape;
   - *refund* (selector 1, `<sig> <pubkey>`): `HASH160(pubkey) == refund_pkh`, valid
     `SIGHASH_ALL` sig (reuse `TransactionSignatureChecker`), `s_t ≤ s0`,
     `age < TWO_YEARS`; `V_rem` counted into the tx's required fee;
   - *expiry sweep* (selector 2, keyless): `age ≥ TWO_YEARS` (no algo/RSF gate); `V_rem`
     counted into the tx's required fee.
   Then require `txfee ≥ Σ V_rem` over all refund/sweep reserve inputs (so their value
   is fee). For each NEW `OP_RESERVEFEE` output enforce `algo ∈ [0, NUM_ALGOS)`; `s0`
   needs no check (Q16 keeps it `< 1`). Gated on `DynamicForkActive`; pure validation, so
   `DisconnectBlock` needs nothing.
7. **Milestone accounting** updated with the ACTUAL emitted subsidy (never counting
   deferred subsidy as emitted).

Determinism: everything is a function of the confirmed chain + the block. The
materialized algo, the gas instrumentation (§8), and the header-derived RSF index make
validation identical across nodes. Reorg safety comes from ordinary
`ConnectBlock`/`DisconnectBlock` symmetry (reserve outputs are just coins; the RSF
index rebuilds from headers).

---

## 8. Execution runtime

### 8.1 Engine selection (evaluated 2026-09-21)

Requirement: run the LLM proof-of-useful-work verifier fast enough for the 2-minute
block interval (`nPowTargetSpacing = 120 s`), **deterministically**, on a multi-arch
node (x86-64, x86-32, ARM64, ARMv7, possibly more). Measured the settled trunk
verifier (C=768, L=12, NH=12, E=64, ~496M params) full eval on this host:

| engine / mode | model build | forward | total | runtime lang |
|---|---|---|---|---|
| wasm3 (interpreter) | 167.7 s | 65.6 s | 233 s | C, no SIMD |
| WAMR fast-interpreter | 220.0 s | 68.2 s | 288 s | C, no SIMD |
| wasmtime (JIT, SIMD) | 6.08 s | 1.72 s | 7.8 s | Rust |
| **WAMR AOT (SIMD)** | **2.24 s** | **1.56 s** | **3.8 s** | **C runtime** |

- **Decision: WAMR AOT** (wasm-micro-runtime, Bytecode Alliance; **pinned to commit
  `b70d708`**). The latest release tag `WAMR-2.4.5` does NOT build here: `wamrc` fails
  against LLVM 21 (`LLVMOrcThreadSafeContextGetContext` removed) and its SIMD `iwasm`
  fetches `simde` over the network at cmake time. `b70d708` (chronologically newer
  than the 2.4.5 tag; version.h still says 2.4.3) carries the LLVM-21 fix and builds
  cleanly against system LLVM 21 with no network fetch, so we pin the commit hash
  until a release supports LLVM 21. It is the only
  option that hits the ~1 s-class forward target while keeping the node **pure C**:
  the LLVM compiler lives only in the offline `wamrc` tool, not in bitmarkd. An
  approved algo's `.wasm` is AOT-compiled to `.aot` once (at governance/activation);
  the small C runtime just loads and runs it.
- **wasm3 is rejected** for the LLM verifier: ~60x slower than native and no SIMD
  (cannot even compile the v128 module -- "compiling function underran the stack").
  A single verify is ~4 min, ~2x the block interval, before 8-way parallelism.
- All four engines produced the **bit-identical** loss `7.835143` / `0x40fab97e`.

### 8.2 Determinism (verified 2026-09-21)

- IEEE-754 f32 add/sub/mul/div/sqrt are correctly rounded, hence bit-identical on
  every compliant target.
- `wamrc`/LLVM does **not** contract `mul+add` into FMA: `+fma` and `-fma` builds
  give identical output. **Strict IEEE (no fast-math, no contraction) is a required
  `wamrc` invariant** and is the default.
- Output is invariant to optimization level (`-O0` == `-O3`) and to a fixed target.
- Transcendentals (`expf`/`tanhf` in gelu/softmax) are compiled **into** the
  freestanding `.wasm` from wasi-libc -- not called from host libm -- so identical
  bytecode yields identical results on every architecture. (Reinforces the
  freestanding, import-free module requirement.)

### 8.3 AOT target = a fixed per-arch baseline (CONSENSUS parameter)

Compiling with `-mcpu=native` is forbidden: a node lacking a feature **crashes**
(observed: an `+avx2` `.aot` gets SIGILL on a non-AVX2 host) or could diverge. Each
node compiles the canonical `.wasm` with the **same pinned, conservative per-arch
target + strict IEEE**, so results are bit-identical:

- **x86-64:** `x86-64-v2` (SSE4.2). Verified bit-identical to scalar and to the
  interpreters.
- **x86-32 (i686):** MUST use SSE2 float math (`-mfpmath=sse`), never x87 -- x87's
  80-bit extended precision would diverge from every other target. Require SSE2
  (universal on post-2004 x86).
- **ARM64 (aarch64):** `armv8-a` + NEON/ASIMD -- IEEE-754 incl. denormals; matches x86.
- **ARMv7: UNRESOLVED HAZARD.** ARMv7 NEON float flushes denormals to zero (not fully
  IEEE), so v128 float lowered to raw NEON could diverge on denormal inputs. Scalar
  VFP is IEEE. Options: (a) ARMv7 nodes run the **scalar** (non-SIMD) module, (b) the
  engine lowers v128 float to IEEE-correct code (scalar VFP, or NEON with FPCR
  denormals enabled if the core supports it). **Needs verification on real ARMv7
  hardware before ARMv7 can be a dynamic-algo validator.**

These target flags are consensus parameters.

### 8.4 Toolchain & node-hardware reality

- AOT needs LLVM per build-host (via `wamrc`), either compiled locally at activation
  or distributed as per-arch `.aot`. LLVM on small ARM devices is heavy.
- The LLM verifier needs ~2 GiB RAM + ~seconds of native compute per verify, so
  small ARMv7 / low-RAM devices likely **cannot** be dynamic-algo validators; they
  may run pruned/SPV or validate only the primitive PoW. Governance/scaling item.

### 8.5 Memory & stack bounds

- **2 GiB linear-memory cap per verifier instance** (settled in `~/git/llm.c`
  `doc/btm-proof-of-useful-work.md`: 8-way parallel verification fits 16 GB commodity
  RAM; 2 GiB sits under wasm32 dlmalloc's ~2 GiB single-allocation ceiling; the E=64
  trunk is 1.76 GB of params). A consensus constant; enforce via WAMR's max-memory
  setting (the analog of wasm3's `d_m3MaxLinearMemoryPages = 32768`).
- The wasm3 interpreter operand-stack constant (`WASM_STACK_BYTES = 1 MiB`) is moot
  under AOT (native call stack + WAMR aux stack); WAMR's aux-stack size becomes the
  analogous fixed bound.

### 8.6 CPU bound (gas)

- Under AOT there is no interpreter loop to patch, so gas metering is **wasm
  instrumentation before AOT-compile**: inject a per-basic-block weighted gas
  decrement + underflow trap into the `.wasm`, then `wamrc` compiles the checks to
  native -- so metering runs at native speed (the earlier "instrumentation is slow"
  objection was interpreter-specific and dissolves under AOT).
- Gas is a deterministic weighted op count; over-budget traps => the solution is
  invalid, identically on every node. Budget = a top-down ceiling derived from block
  time (a consensus constant), not fitted to any one algo.
- No general upper bound on arbitrary-algo gas is computable (halting problem); the
  gas cap itself is the enforced bound. Data-oblivious algos (NN forward passes have
  input-independent control flow) have ~constant gas across inputs, so one
  measurement bounds them -- **data-obliviousness is the property checked at
  OP_PUSHCODE approval**, not exhaustive input measurement.

### 8.7 ABI (unchanged)

- The node marshals inputs above `__heap_base` and calls `verify()` with the offsets;
  reads the i32 result and the 8-byte `out_ab` (two Q32 `u32`, §3). No float crosses
  the ABI, so the money path is integer-only. `host.c` was the wasm3-era prototype;
  the WAMR bridge replaces it.
- Grinding resistance: the seed's payout half is miner-controlled, so an LLM algo's
  validation-set selection must itself be grinding-resistant; the prev-block-hash half
  is not grindable without redoing that block's PoW.

### 8.8 Bounding AOT compilation (deterministic, without a governance dependency)

`wamrc` compile time/memory can blow up on adversarial `.wasm` (LLVM passes are
superlinear in some per-function metrics, and for arbitrary input the cost is not
statically predictable). Compilation is rare -- once per algo activation (~8 algos,
with a long governance lead time before the algo is active) -- but it must be bounded
**without relying on social vetting as the security root** (that would undercut
trustlessness). Governance and the activation lead time are defense-in-depth, not the
guarantee.

- **Per-function structural caps (consensus, static):** cap the *per-function* metrics
  that drive superlinear passes -- instruction count, basic-block count, operand/SSA +
  phi count, loop-nesting depth, locals -- plus module-level function/table/global/byte
  caps. Bounding each function's compile makes total compile ~linear in module size.
  The deterministic consensus rule is simply "the `.wasm` passes the caps," computed
  identically by every node.
- **Pinned bounded opt pipeline:** fix `wamrc`'s opt level / pass set (not `-O3`) so
  worst-case per-function cost is bounded in the capped metrics. A consensus parameter,
  pinned together with the exact WAMR/LLVM version (commit `b70d708`) -- a compiler
  upgrade could change complexity, so the version is part of the safety argument.
- **Adversarial fuzzing of `wamrc`:** fuzz modules sitting at the caps for compile-time
  or memory blow-up; any pass superlinear in an uncapped metric => add that metric.
  Turns "we hope it's bounded" into evidence.
- **No split risk:** given the caps bound the envelope, adequate hardware always
  compiles an accepted module; a node that cannot is below the hardware floor (§8.4) --
  a local provisioning fact, not a consensus disagreement. Compile *time* need not be
  deterministic; only the cap pass/fail and the execution *result* are consensus.
- **Honest residual:** LLVM has no formal per-pass complexity guarantee, so this is
  empirical hardening (caps + pinned pipeline + fuzzing + pinned compiler version), not
  a proof -- the same standard by which the chain trusts its signature-verification and
  script-parsing code.
- **Fallback lever (evaluated 2026-09-21 -- NOT currently viable):** WAMR **Fast JIT**
  (pure C, bounded ~linear compile) was the hoped-for stronger compile-bound story, but
  measured on the trunk verifier it (a) does not support SIMD (`SIMD + FAST_JIT` is an
  unsupported build combo) and (b) crashes with "out of bounds memory access" ~26 s in,
  during the model build's large `memory.grow`, at the same point regardless of
  `--stack-size` -- a Fast-JIT codegen/robustness limitation (AOT and both interpreters
  run the same module correctly). So Fast JIT is not a drop-in fallback today; the
  compile bound must be solved on the **LLVM-AOT path** (per-function caps + pinned
  pipeline + fuzzing above). Reviving it would need upstream Fast-JIT fixes + SIMD, or
  a different bounded compiler (Cranelift/wasmtime is the Rust analog other wasm chains
  use for exactly this bounded-compile reason).

---

## 9. Open items / parameters

- `MAX_SOLUTION_BYTES` value; exact payout-commitment layout in the solution tx (or
  coinbase) and how the verifier locates it.
- `submitsolution`-style RPC for handing a solution tx to the node, and the node-side
  template policy that injects it + the `dynamic` GBT field (§6bis).
- Relay of solution txs: keep out-of-band, or add `OP_SOLUTION` relay standardness
  (multiple OP_RETURNs, `MAX_SOLUTION_BYTES`) so solutions propagate p2p (§2.1).
- Gas metering: mechanism settled (per-basic-block wasm instrumentation compiled to
  native under AOT, §8.6); still open: the weighted cost table and the block-time-
  derived budget constant.
- Materialized-algo store: format and where the ~8 activated modules live; re-vote
  swap-in.
- Per-height/per-algo RSF index: storage format and rebuild-on-reindex.
- **ARMv7 SIMD determinism** (§8.3): verify on real hardware whether v128 float can be
  made IEEE-correct (denormals), or mandate the scalar module on ARMv7.
- **AOT toolchain / packaging** (§8.4): compile `.wasm`->`.aot` locally per node via
  `wamrc` at activation, or distribute per-arch `.aot`; LLVM availability per arch.
- **Pinned per-arch AOT target flags** as consensus parameters (§8.3); WAMR max-memory
  setting for the 2 GiB cap (§8.5) and WAMR aux-stack size.
- Node hardware floor for dynamic-algo validation vs. primitive-only/pruned nodes (§8.4).
- WAMR vendoring: pinned to commit `b70d708` (see §8.1); replace `src/wasm3/`, rewrite
  the execution bridge (`wasmexec.{h,cpp}`) against WAMR's AOT API, and add the offline
  `wamrc` AOT-compile step with the pinned per-arch target flags.
- **Structural caps** (§8.8): the exact per-function + module-level metrics and their
  values (consensus); the pinned `wamrc` opt pipeline; a `wamrc` fuzzing harness to
  validate the compile bound.
- **Fast JIT fallback** (§8.8): benchmark WAMR Fast JIT runtime speed on the LLM
  verifier to quantify the AOT-vs-bounded-compile tradeoff.
- Data availability of LLM validation examples: inline merkle-branch proofs carried in
  the `OP_SOLUTION` stream (fold the proof format in — see the voting doc).
- Reserve flow rate `k` (=1 for now; the future `<ctype>` field would let contracts pick
  other release rules). No `s0` ceiling — the Q16 encoding keeps `s0 < 1`.
- Reserve refund sighash: reuses `TransactionSignatureChecker` with `SIGHASH_ALL` and
  the reserve scriptPubKey as scriptCode (SIGHASH_ALL covers outputs → no malleability).
  IMPLEMENTED in 6.6; keep an eye on the sighash convention if segwit/taproot ever
  activate on Bitmark.
