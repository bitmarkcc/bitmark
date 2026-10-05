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

**Payout commitment.** The dynamic miner's payout scriptPubKey is the **`seq = 0`
chunk** of the solution stream; the solution bytes fed to `verify()` are the
concatenation of `seq = 1..N-1`. (One uniform rule for both the solution-tx and
coinbase forms — no separate marker output — and a scriptPubKey easily fits one
`≤ 520 B` chunk.) It serves two roles:
1. **Seed binding.** `seed = Hash256(payout_scriptPubKey || anchor_hash)`, where
   `anchor_hash` is the hash of the previous block **of this block's own mPoW slot**
   (§2.1bis), not the immediate parent. The solution is bound to the payout, so no
   one can redirect the dynamic share by rewriting the payout — that changes the seed
   and the solution no longer verifies. (This holds regardless of *where* the payout
   is committed; a pool that rewrites it forfeits the solution and thus the `α·r`
   payment.)
2. **Payment target.** The coinbase must pay the dynamic share to this scriptPubKey
   (§2.3, §4).

**Solution chunks.** The solution bytes are split across outputs of the solution tx,
each:
```
OP_RETURN OP_SOLUTION <seq> <chunk>
```
- Self-marking, unspendable, 0-value, no UTXO.
- `<seq>` gives a total order: the verifier collects the `OP_SOLUTION` outputs of ONE
  transaction — the first in block order that has any (§7 step 3) — requires
  `seq = 0..N-1` (contiguous, unique), and concatenates → the block's solution bytes.
  A block may contain further solution-bearing txs; they are ignored outright, never
  parsed and never verified, which is what keeps a block's verification cost at one
  `verify()` run however many are present (§2.1quater).
- Self-correcting, and strictly so BECAUSE the scope is one tx: the chunk set is fixed
  by a single signed transaction, so no third party can alter what `verify()` is fed.
  A stray or wrong `OP_SOLUTION` output inside that tx changes the bytes and `verify()`
  fails, so its author is forced to carry exactly the intended set — and a rival tx
  elsewhere in the block cannot interfere with it at all.
- Chunk ≤ 520 bytes (`MAX_SCRIPT_ELEMENT_SIZE`). There is NO consensus cap on the
  per-block total: block weight already bounds the size and the gas limits (§8.6,
  §8.7) already bound the verification cost, so a separate one would be redundant
  (§9). Relay is capped separately as POLICY (`MAX_SOLUTION_TX_WEIGHT` and
  `MAX_SOLUTION_TX_INPUTS`, §2.1ter); a miner may include a solution tx that exceeds
  those and simply did not propagate.

**Delivery.** The primary model is ordinary **mempool relay**: the dynamic miner funds
the solution tx with a small input, leaves a relay fee, and broadcasts it p2p like any
transaction; it propagates to every pool, and whichever pool mines it includes it and
pays the bound payout. This is safe *because of seed binding* — the payout scriptPubKey
is committed inside the solution and `seed = Hash256(payout ‖ anchor_hash)`, so whoever
mines the tx MUST pay `α·r` to the dynamic miner's committed address (rewriting it
changes the seed and the solution no longer verifies). So the author is paid regardless
of who mines it, which makes relay permissionless — no private sale needed, and no
front-running risk. The relay fee lands in `nFees` and the coinbase claims it.

Enabling this is purely **policy/mempool work, not consensus** (§9): relax standardness
so a tx may carry multiple `OP_RETURN OP_SOLUTION` outputs, and add a per-tx relay-size
cap (a policy limit, distinct from any consensus rule). Out-of-band hand-off (a dynamic
miner selling a solution directly to a pool, or `submitsolution`) remains possible as a
fallback but is no longer the assumed path. Either way, **consensus is identical**:
`ConnectBlock` reads the solution from the first solution-bearing tx (§7 step 3) and does
not care how it arrived.

What makes permissionless relay safe to *receive* is that a solution tx can never make a
block invalid. Whatever it contains — a solution that does not verify, one aimed at
another slot, outright garbage, or a rival alongside the real one — the worst outcome is
that the block has no valid solution and takes the no-solution branch (§7 steps 3–4). So
accepting, relaying or even mining one adds **no** invalidity an attacker can exploit:
the mempool cannot be turned into a minefield for miners who have not implemented
solution selection.

That is narrower than "nothing can go wrong". A pool mining a slot with an active algo
still owes the coinbase outputs that slot requires on *every* block, solution or not
(§6bis.2) — an obligation it has regardless of what is in the mempool. The point here is
only that no solution tx can *add* to it. §2.1quater covers what that leaves open.

### 2.1bis The anchor: why the seed binds to the previous SLOT block
`anchor_hash` is the hash of the previous block of **this block's own mPoW slot**, not
the immediate parent. `GetPrevAlgoBlockIndex` is exactly that walk.

**Why.** The seed is what a solution is bound to, so it determines how long a miner
has to produce one. Binding to the immediate parent gives a 120 s window — the global
block interval. With 8 algos, a slot produces a block roughly every **16 minutes**, so
binding to the previous slot block gives a solution that long to be computed and
relayed. For a real PoUW algo this is the difference between feasible and not: the
llm.c demonstrator targets ~16 min of miner GPU per block, which simply cannot fit in
a 120 s window.

**Why it is replay-safe.** The obvious worry is that a seed fixed for ~16 minutes
makes one solution valid in every block of that window, letting one unit of work
collect `α·r` eight times (a fresh funding input makes it a different tx, so
double-spend protection does not help). It cannot, because the branch verified for a
block is the one active for **that block's own slot**: a slot-*k* solution presented in
any other slot's block is verified against a different module and fails. And between
two slot-*k* blocks there is exactly one "next slot-*k* block". One anchor, one
payable block.

**Existence.** A same-slot predecessor always exists wherever this is evaluated:
`nVersion < 4` is invalid once DERSIG is active, so testnet's rolling `OnFork()` gate
can never lapse and mainnet/regtest gate on height; and `DynamicForkActive` needs
94-of-125 per algo across *all* 8 algos, so every slot has ≥ 94 on-fork blocks before
any branch can be active. The implementation asserts this rather than substituting
another hash, since a different anchor would be a silent divergence from this rule.

**Cost.** The payout half of the seed is miner-chosen, so a longer-lived seed means
more time to grind payout addresses looking for a favourable one (§8.7). This does not
introduce the problem — an algo's validation-set selection must be grinding-resistant
regardless — but it widens the window roughly 8×, which raises the bar on that
requirement.

### 2.1ter Relay policy for a solution transaction
Making mempool relay (§2.1) actually work needs standardness to accommodate a
transaction unlike any ordinary one: very large, with almost no inputs. Three pieces,
all **policy, never consensus**:

- **Multiple `OP_RETURN`s.** A solution spans many `OP_SOLUTION` outputs, so they are
  deliberately not counted toward the single-`OP_RETURN` limit, and are dust-exempt
  like `NULL_DATA` (`policy.cpp`).
- **A raised weight cap.** `MAX_STANDARD_TX_WEIGHT` is 400000 weight — only 100 kB
  without segwit — which would keep any real solution off the p2p network entirely. A
  solution-carrying tx instead relays up to `MAX_SOLUTION_TX_WEIGHT` (3900000 weight,
  ~975 kB), leaving room for the coinbase alongside it.
- **An input cap.** The raise is safe only because of *why* the original limit exists:
  sighash cost is `O(ninputs · txsize)`, so the danger is large AND input-heavy. A
  solution tx is the opposite, so the cap is paired with `MAX_SOLUTION_TX_INPUTS` (8).
  The product then stays an order of magnitude below what an ordinary standard tx can
  already demand — ~7.8 MB hashed against ~67 MB for a 675-input 100 kB tx — so this
  *lowers* the worst case rather than raising it. Eight rather than the one a solution
  tx strictly needs, because funding ~975 kB costs a real fee (~975k sat at 1 sat/B),
  possibly assembled from several UTXOs.

- **A cap on how many may be queued** (optional). Solution txs are the one class of
  transaction a node may want to bound by *count* as well as by feerate, because the
  mempool cannot tell a real one from garbage without running the verifier. A single
  global `MAX_SOLUTION_TXS` (say 8), evicting the lowest declared feerate, bounds how
  many rivals can compete for a miner's per-epoch verification budget (§2.1quater). It
  is NOT itself a CPU bound — that budget is — so the exact value is not
  safety-critical.

Being policy, a miner may include a solution tx that breaches these; it simply will
not have propagated. Consensus bounds a solution only by block weight and the gas
limits.

### 2.1quater Rival solution transactions
Permissionless relay (§2.1) means anyone can put a solution tx in the mempool, so a
miner may face several — two honest dynamic miners, or one honest miner and an attacker.
Only one can be the block's solution (§7 step 3), so the miner must choose.

**Why a solution cannot be checked on arrival.** The obvious design — verify a solution
tx when it enters the mempool, drop it if it fails — does not survive the cost. One
`verify()` is up to **~38 s of reference-core CPU** (§8.6), and the algos this mechanism
exists for are *data-oblivious*: input-independent control flow is exactly the property
that lets one measurement bound their gas counts (§8.6), so **garbage costs the same as
a real solution**. There is no fast rejection path, and a transaction that is never
mined never pays its fee, so verifying unmined transactions would hand anyone an
unpriced way to spend every node's CPU.

So nothing speculative is verified. Three rules make selection work anyway.

**1. A candidate must be verified to be included, so the budget is per EPOCH.** A
template cannot dodge the verdict of whatever solution it carries: pricing the
no-solution branch while carrying a valid solution creates a pot output consensus
rejects, and pricing the solution branch without one omits the required `α·r`. So
including a candidate costs a run. What *can* be decoupled is runs from template
rebuilds — the rebuild rate is set by how often pools poll (every 5 s, or every call for
a pool rotating algos) and has nothing to do with what a run costs, so it must not be
the budget. The budget is **candidate runs per slot per anchor epoch** (~16 min,
§2.1bis), set by an explicit node option with a small default and raisable by a pool
with CPU to spare:

| per slot being mined, per anchor epoch | runs |
| --- | --- |
| empty-solution α₀, β₀ | 1, memoized for the epoch |
| candidates tried | ≤ `budget` |
| every later template rebuild (~190 of them) | **0** — all cache hits |

Worst case `(1 + budget)` runs per slot per epoch, independent of polling. At the ~38 s
worst case with `budget = 1` that is ~76 s per 16 min, ~8% of a core per slot; at the LLM
trunk's real ~1.5 s it is negligible. The single α₀/β₀ run is irreducible — it is the same
work consensus does to validate one block of that slot.

This holds because `nbits` is part of the memoization key (§8.9) and the per-algo retarget
is epoch-stable: everything `DarkGravityWave` feeds into the target comes from the slot's
OWN chain — the 25-block difficulty average, those blocks' median times, and the
run-length terms, none of which a block of another algo at the tip disturbs. The one
parent-dependent term, `time_since_last_algo` (`pow.cpp`), is inert below 9600 s, i.e.
until the slot has gone 160 minutes — 10× its target interval — without a block.

That also answers the question `nbits` raises for a *solution*, not just for the cache:
since the target does not move within an epoch, a solution stays valid for the whole
~16-minute window §2.1bis promises. When the 160-minute starvation retarget does fire it
moves the target **easier** (`nActualTimespan` is scaled up, so the target grows), and
work already done still satisfies an easier target. The sharp edge is that crossing the
threshold also switches the base from the 25-block average to the algo's last `nBits`,
which is *harder* if that algo's difficulty had been rising — rising difficulty plus 160
minutes of starvation is nearly self-contradictory, but it is not impossible, so a
dynamic miner aiming at the current target has no absolute guarantee across that one
transition.

**2. Memoize `verify()` by CONTENT (§8.9).** The cache is what keeps the budget from
being spent re-deciding something already decided, and it must be keyed on
`(branch, algo, anchor, nbits, payout, solution)` — never on the txid, because **txids
are malleable**: the same garbage solution can be rewrapped under a new txid for free (a
different funding input, a 1-satoshi change to an output, reordered outputs), and a
txid-keyed cache would hand every copy a fresh ~38 s run. Content-keying collapses them
all onto one entry.

Note what this does *not* claim. Flipping one byte of the solution produces a genuinely
new key, and that is free for an attacker too, so the number of distinct keys is
unbounded. The cache is not the bound — rule 1's per-epoch budget is. Content-keying
simply ensures each unit of that budget goes to a *new* question.

**3. Mine the losers anyway, and collect their fees.** A candidate that fails to verify
is still an ordinary fee-paying transaction, and since it cannot invalidate a block
(§2.1 "Delivery") there is no reason to leave it out: including it is better than not by
exactly its fee. It must simply be ordered *after* the chosen solution tx, so consensus
ignores it (§7 step 3). This is what makes ordering candidates by declared feerate sound
— the fee of a losing candidate is collected rather than forgone, so a high declared fee
is a real bid and not a free bluff.

The one ordering constraint: if a known-bad solution tx were an *ancestor* of the chosen
candidate it would have to be placed first, making it the block's solution source. In
that case the miner drops the chosen candidate instead.

**The economics, for an attacker publishing solutions that do not verify.** With
`T = β(1−α)` (§4.4), a miner keeps `(1−α)·r` with a valid solution and only `T·r`
without:

| what they do | their cost | the network's cost |
| --- | --- | --- |
| queue garbage in the mempool | a funded UTXO per distinct txid, plus mempool admission | one verifier run per txid, **once, ever** |
| it gets mined after the chosen solution tx | **the fee they declared, actually paid** | nothing — ignored unparsed (§7 step 3) |
| it gets mined as the block's solution source | **the fee they declared, actually paid** | nothing; block still valid, and that pool keeps `T·r` rather than `(1−α)·r` |

Denying one block's `α·r` means outranking the real solution on declared feerate across
`budget + 1` transactions *and* having them mined — so the attacker pays a fee above the
real solution tx's on each one, while the dynamic miner has to outbid on only one. The
contest is asymmetric in the defender's favour and priced by the ordinary fee market.
The last row is self-policing too: a pool that lets garbage sort ahead of the real
solution pays for that mistake out of its own reward, not the chain's.

`submitsolution` (§9) remains available for a dynamic miner who would rather not pay
relay fees at all, or wants a private arrangement with a pool — but it is a convenience,
not a defence.

### 2.2 Alternative: solution in the coinbase
The separate solution tx (§2.1) is the form that makes standard GBT pool integration
smooth — it is NOT a consensus requirement. Because the verifier scans the WHOLE block
for `OP_SOLUTION` outputs, the same chunks may instead be placed directly in the
**coinbase** outputs:
```
coinbase.vout += OP_RETURN OP_SOLUTION <seq> <chunk>   (one per chunk)
```
Both forms are consensus-equivalent: `seq = 0..N-1`, contiguous/unique, concatenated,
and the assembled bytes feed `verify()` identically. The
payout may likewise be committed in the coinbase (scriptSig or a marker output) in this
form. Mixing the two is not *invalid*, but it is pointless: the coinbase is tx 0, so
whenever it carries any `OP_SOLUTION` output it is the block's solution source and a
separate solution tx in the same block is ignored (§7 step 3). A miner choosing this
form should therefore put the whole stream in the coinbase.

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
An algo may read the FULL BLOCK DATA of its own slot's previous blocks, and so the
`OP_SOLUTION` outputs in them (found by the same first-solution-bearing-tx rule as §7
step 3 — an algo walking its own history should apply that rule, not collect every
`OP_SOLUTION` output it sees, or it will read chunks that block's consensus ignored). A running data
stream (e.g. accumulating LLM LoRA deltas) SPANS multiple blocks: each block
contributes its chunk; `verify()` for the current block uses the window. Those blocks
are fetched on demand through the `chain.*` imports (§3.1), not passed as a buffer.
`n` is `MIN_SLOT_BLOCKS_ON_DISK` = 32850 (~1 year of one slot), which is exactly what
the per-slot prune floor guarantees is retained (`pushcode-port-27xb.md`), so the
whole window is on disk on every node. Pure hash-PoW algos (keccak/whirlpool) ignore
the window entirely and use only the current block's chunk (the nonce).

The window is **reachable, not traversable in one call**: the per-call I/O budgets
(§8.7) are far below 32850 blocks, because reading the whole window every block would
be minutes of disk I/O. An algo whose state is the fold of all history (the llm.c
LoRA chain is one) therefore cannot re-derive that state inside `verify()`; it must
receive it pre-folded — via on-chain weight-state checkpoint epochs, or node-held
state. That is a separate mechanism, still open, and the accessor ABI forecloses
neither.

---

## 3. Dynamic-algo I/O contract

```
int verify(anchor_hash,            // 32 bytes: the previous block of THIS SLOT (§2.1bis)
           payout, payout_len,     // the dynamic miner's payout scriptPubKey
           nbits,                  // u32 compact target
           solution, solution_len, // the block's assembled OP_SOLUTION bytes
           out_ab)                 // OUT: 8 bytes = α (u32) || β (u32), LE
  -> 0 iff the solution is VALID (meets the per-slot difficulty), else non-zero.
```

The slot's previous blocks are reached through IMPORTS rather than an argument
(§3.1). Every argument above is therefore fixed before the block is built:
`anchor_hash` and `nbits` come from the parent chain, `payout` and `solution` are the
dynamic miner's own. A solution stays valid no matter what the pool later does with
the block's transaction set — which is what makes mempool relay (§2.1) work at all.

**Why the block's own transactions are NOT an input.** An earlier draft passed the
current block's non-coinbase txs. That is circular: the solution lives in a tx
*inside* the block, so the tx set would determine the solution and the solution
would be part of the tx set. Even excluding the solution tx itself, a pool adding or
dropping any other tx would silently invalidate a solution the dynamic miner had
already produced — and the dynamic miner does not control the final block. Nothing
was load-bearing about tx binding: `seed = Hash256(payout || anchor_hash)`
already prevents redirecting a solution to another payout or replaying it onto a
different parent.

### 3.1 Chain access (imports)
A multi-block algo needs earlier `OP_SOLUTION` chunks (§2.5). Those are **not**
marshaled in: the window is up to `MIN_SLOT_BLOCKS_ON_DISK` = 32850 blocks (~1 year
of one slot), far too much to copy per call. The module imports two accessors and
pulls only what it needs:

```
chain.slot_block_count() -> i32
    Addressable window size: min(the slot's blocks back to the Multi-PoW fork,
    MIN_SLOT_BLOCKS_ON_DISK). A function of the CHAIN, never of local disk state —
    the per-slot prune floor guarantees the whole window is retained, so a pruned
    and an archival node return the same number. It reaches 32850 about a year
    after the fork; before that it is the smaller true count. Free (no read).

chain.slot_block(index, ptr, cap) -> i32
    Writes the serialized block at `index` (0 = newest, i.e. the parent-most recent
    slot block) to `ptr`, returning its size. Negative means nothing was written:
      -1  no such block (index >= slot_block_count())
      -3  cap smaller than the block's size (the read still happened, so it is
          still charged; pass >= MAX_BLOCK_SERIALIZED_SIZE to never see this)
    A destination outside the module's own memory TRAPS instead of returning a
    code, exactly as an out-of-bounds i32.store would -- the engine's bounds check
    raises the exception itself, and the bounds depend only on the module's own
    declared memory, so this stays deterministic.
```

Block bytes use the **`TX_NO_WITNESS` serialization**, and that is part of the ABI:
it is the one unconditional framing. `TX_WITH_WITNESS` emits the extended
marker/flag format only when a tx actually carries witness data, so the shape of the
bytes would depend on block content; mainnet and testnet pin `SegwitHeight` to
`INT_MAX` so segwit never activates, but the machinery is still present and
regtest/signet can enable it. A consensus input that α/β depend on must not be able
to change framing. This also matches the txid/merkle-root basis rather than wtxid.

Fetches are metered by their own budgets (§8.7), because a fetch costs the module
one guest instruction but costs the node a real disk read. A block inside the window
that a node cannot read is a LOCAL fault (corruption, a prune lock that did not
hold), never block invalidity: the node raises a fatal error rather than rejecting
the block, since rejecting would fork it off the chain.
`α, β` are written as two little-endian **`u32` in Q32 fixed point** — the stored
integer is `value · 2^32`, i.e. `α = out_ab[0..4] / 2^32`. The whole `u32` range maps
onto `[0, 1)`, so `0 ≤ α, β < 1` is automatic (no validity check, no NaN/Inf/negative
cases). The node's reward math is then pure integer (§4.4); the module does any
float→fixed scaling internally, where wasm's IEEE-754 `f32` is deterministic (validated
bit-identical cross-machine for the llm.c verifier) — but no float ever crosses the ABI
or enters the node's money path.

`seed = Hash256(payout || anchor_hash)`.

**`α, β` MAY depend on the solution.** An earlier draft required them to be functions
of the block context alone. That constraint was stronger than necessary and is lifted:
`solution` is an input, α/β are outputs, and an algo is free to make the split depend
on the work supplied — e.g. paying more for a LoRA delta that improves the loss more.
Whether α is a constant or solution-dependent is left to each algo's architects.

The one hard requirement is that **α and β must be defined for an EMPTY solution**,
because the node calls `verify()` with no solution purely to read them for the
no-solution branch (`β·(1−α)·r`, §4). An algo that varies α must therefore still
return a sensible baseline in that case. Soft-fork safety is unaffected either way:
Q32 encoding guarantees `α < 1`, so `α·r ≤ r` always.

A solution-dependent α does carry an incentive cost worth stating. A pool keeps
`r − α·r`, so it prefers the *lowest* α among valid candidates. If an algo pays more
for better work, pools will systematically include the weakest solution that still
clears the difficulty threshold. The threshold remains the real floor on quality; the
gradient above it points the wrong way. An algo wanting to reward quality above the
floor should be designed with that in mind (or keep α context-only, which makes pools
indifferent). This is also why the node's template builder cannot simply pick the
highest-feerate solution once α varies — selection becomes a revenue decision (§6bis).

The reference algos in `contrib/dynamicalgo/` (`keccak_algo.c`, `whirlpool_algo.c`)
implement this signature, writing `α = β = 0.5` (`0x80000000` in Q32) on a valid
solution and `α = 0, β = 0.5` on no valid solution — recovering the r/2 // r/4 split.
Both are pure hash-PoW: stateless, importing nothing. That directory also holds
`chain_probe.c`, a fixture driving every `chain.*` accessor and both I/O budgets, and
two harnesses that run a module through the node's own `RunAlgoVerify` and through the
full `.wasm` → `wamrc` → `.aot` → execute pipeline. See its README for the build and
for guidance on writing an algo.

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
- **No / invalid solution:** (write `T = β(1−α)` throughout)
  - dynamic miner: `0`
  - primitive miner: `T · r` — `β(1−α)` scales the WHOLE reward, fees included, not
    the subsidy alone.
  - emitted subsidy = `T · S`; the un-emitted `S − T·S` is **milestone-deferred**
    (Bitmark emission halves/quarters at cumulative-emission milestones, not heights),
    so later blocks emit it rather than it being destroyed.
  - withheld fees `(1 − T) · F` are paid by this block's coinbase into its slot's
    **solution pot** (§4.5) — a spendable per-slot output that a later
    solution-bearing block of the same slot releases back into `F`. So the **fee
    remainder is still never burned**: it is deferred, exactly like the subsidy, just
    by a different mechanism.
  - the coinbase therefore claims `T·S + F` in total (`T·r` to itself, `(1−T)·F` to
    the pot), which is `≤ S + F` because `T ≤ 1` — §4.1's soft-fork argument is
    untouched.

**Why the fees are scaled too, and not just the subsidy.** An earlier version scaled
only the subsidy, leaving the primitive miner all of `F`. That inverts the inclusion
incentive as the subsidy decays: including a solution pays `(1−α)(S+F)` against
`β(1−α)S + F` for skipping it, so inclusion requires `S/F > α/((1−α)(1−β))` — at
`α = β = ½`, only while `S > 2F`. In the fee-dominated future a rational pool would
*never* include a solution, defeating the very reason fees are inside `r`. Scaling all
of `r` restores it (§4.2) and makes `α` cancel out of the decision again.

Fixed `α = β = 1/2` gives `T = 1/4`: solution → `r/2` dynamic + `r/2` primitive; no
solution → `r/4` to the primitive miner, `3F/4` to the pot, `3S/4` deferred.

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
include  ⇔  (1−α)(S+F+P) > β(1−α)(S+F+c)  ⇔  c < (1−β)/β · (S+F)  +  P/β
```
where `P` is the slot's solution pot (§4.5), released into `F` by the including block.
`α` cancels — it sets the dynamic/primitive SPLIT but not the include decision. `β`
is the lever: `β→0` ⇒ include almost anything; `β = 1/2` ⇒ include iff `c < S+F+2P`;
`β→1` ⇒ never include.

The `P/β` term is what makes the incentive **self-correcting**: every block a slot goes
without a solution adds `(1−T)·F` to its pot, so the threshold rises until inclusion is
worth it again, however small the subsidy has become. Parameter tuning sets the
baseline; the pot handles the tail. The community-voted algo tunes `α, β` (two Q32 `u32` outputs) to
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
- **Seed binding stops redirection.** `seed = Hash256(payout ‖ anchor_hash)`, so a
  primitive miner who points the payment at their own address changes the seed, and the
  solution no longer verifies → not a valid solution-block.

So once the primitive miner holds the solution, their only valid moves are: pay the
protocol-set `α·r` to the bound payout (keeping `(1−α)·r + fees`), or don't use the
solution (falling back to `β·(1−α)·r`, §4). They can neither steal the dynamic share
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
- **No solution** (`T = β(1−α)`, applied to `r` as a whole — §4):
  - `keep = fp_mul( fp_mul(r, 2^32 − α_q), β_q )` = `⌊T·r⌋`, the primitive miner's share.
  - `emitted_subsidy = fp_mul( fp_mul(S, 2^32 − α_q), β_q )` = `⌊T·S⌋`; the rest of `S`
    is milestone-deferred.
  - `to_pot = F − (keep − emitted_subsidy)` — the withheld fee part, derived as a
    **remainder** rather than an independently-floored `(1−T)·F`, so that
    `keep + to_pot = emitted_subsidy + F` exactly and no satoshi is lost to double
    flooring. This is the value the required `OP_SOLUTIONPOT` output must carry (§4.5).
  - coinbase total claim `= keep + to_pot = emitted_subsidy + F ≤ S + F`. Since
    `2^32 − α_q ≤ 2^32` and `β_q < 2^32`, each `fp_mul` caps its result, so the coinbase
    can never over-claim versus old nodes — soft-fork-safe (the sub-satoshi rounding of
    `(1−α)` cannot break it).

Everything floors downward, uses the same `fp_mul` on every node, and is constructed so
the total is always `≤ r`. RESOLVED (was the last open reward-math item).

**Negative subsidy (SSF near-peak region).** Bitmark's SSF can drive the scaled subsidy
`S` **below zero** in a narrow region (hashrate above ~97.6% of peak) — a pre-existing
property of `GetBlockSubsidy` that consensus must preserve (correcting it would be a hard
fork). The split handles this soft-fork-safely, *without* touching `GetBlockSubsidy` or the
primitive coinbase check:
- **Valid solution:** the split keys off `r = S + F`, not `S`. When fees cover the
  shortfall (`r > 0`) the dynamic miner still earns `α·r` — the reward simply comes from
  fees — and the ceiling is `r = S + F` (exactly the old-node ceiling). If `r ≤ 0` nothing
  is owed and the block fails the existing `> S+F` coinbase check anyway.
- **No solution:** only the SUBSIDY must escape scaling here. `T·S` would move a
  negative `S` *up* toward zero (`T·(−100) = −25`), pushing the ceiling above `S+F` and
  breaking soft-fork safety, so a negative `S` is emitted unchanged. Withholding
  **fees**, however, violates neither requirement, so it still happens: with
  `emitted = S` and `keep = T·r`, the pot takes `r − T·r` and the total is exactly
  `S + F` — the old-node ceiling. The negative-`S` region is a high-hashrate region,
  precisely where the inclusion incentive should stay intact rather than switch off.
  Only two constraints are actually load-bearing, and they bind different terms:
  `emitted_subsidy ≤ S` and `total coinbase ≤ S + F`.

So one formula covers both signs, with no special case for the pot:
```
emitted = (S ≥ 0) ? T(S) : S
total   = emitted + F
keep    = T(r)
pot     = total − keep        # ≈ (1−T)·F for S ≥ 0, ≈ (1−T)·r for S < 0
```
`pot ≥ 0` holds regardless of flooring because `fp_mul` is **Lipschitz-≤1** in `x`
(adding `d` raises the floor by at most `d`), and composing two such maps preserves it,
so `T(S+F) − T(S) ≤ F`.
`fp_mul` is thus only ever given non-negative inputs, and `max_coinbase_value ≤ S+F` holds
in every region. Enforced in `dynamicalgo/reward.cpp` (`ComputeRewardSplit`).

### 4.5 The solution pot — where withheld fees go
`(1 − T)·F` withheld from a no-solution block (§4) has to go *somewhere*. Unlike the
subsidy it cannot simply be left unminted: fees already exist, having been removed from
the UTXO set by the transactions that paid them, so an unclaimed fee is **destroyed**.
Deferring it therefore needs a place to sit.

It cannot be a consensus *counter* that later raises the coinbase ceiling to
`S + F + P`: old nodes cap the coinbase at `S + F` and would reject such a block — a
hard fork. §4.1 already states the rule this follows: releasing previously-withheld
value must be a **UTXO spend**, never a coinbase over-claim. So the pot is a real
spendable output.

```
output = ( V , "<algo+1> OP_SOLUTIONPOT" )  // SPENDABLE, TxoutType::SOLUTIONPOT
```
- `V` — accumulated withheld fees for this slot.
- `algo ∈ [0, NUM_ALGOS)` — the slot whose solutions this pot funds. A slot's missed
  solutions must not subsidise a different slot, so the pot is per-slot, as the
  reserve-fee contract is (§6.1).
- **Stored as `algo + 1`**, i.e. `OP_1..OP_8`, and that is required rather than
  cosmetic. The algo push is the LAST item this scriptPubKey leaves on the stack, and a
  spend only succeeds if the final stack top is true — so a 0-based encoding puts an
  empty push (`OP_0`) there for slot 0, `CastToBool` reads it as false, and **every
  slot-0 pot is permanently unspendable** while slots 1–7 work. Found by trying to build
  a claim; invisible until then, since creating pots looks perfectly healthy. Build and
  read the script only through `SolutionPotScript` / `SolutionPotAlgo`
  (`script/solver.h`), which own the conversion and reject out-of-range encodings.
  `OP_RESERVEFEE` needs no such trick — its script ends with the 20-byte `refund_pkh`,
  which is always truthy — so the two covenants encode the slot differently, on purpose.
- `OP_SOLUTIONPOT = OP_NOP8` (`0xb7`) — a defined no-op, so the output is
  anyone-can-spend *at the script level*; every real rule lives in the `ConnectBlock`
  covenant. This is deliberately the same shape as `OP_RESERVEFEE` (§6.1).

It borrows the three invariants that make the reserve-fee contract safe:
1. **Release is to FEE only.** No spend path ever mints a spendable output from the pot
   (other than a rollover of the pot itself), so potted value stays fee-destined and
   never bloats the UTXO set.
2. **Per-tx enforcement** `txfee ≥ Σ(released value of every pot input)`, so the
   released value genuinely reaches the block's miner.
3. **Script-level anyone-can-spend, covenant-gated**, so old nodes see an ordinary
   spendable output and the rules are enforced only by upgraded nodes.

It is a SEPARATE output type rather than a fourth `OP_RESERVEFEE` selector, because two
of that contract's paths would be actively wrong here: `refund` has no legitimate
recipient for protocol-funded value, and `sweep` pays *any* algo's miner after two
years, which would let a rival slot drain slot `k`'s pot.

#### Creation
A pot output is valid only as:
- the **required coinbase output** of a no-solution block on a slot with an active algo,
  carrying exactly `(1 − T)·F` with that block's own `algo`; or
- the **rollover** of a consolidate spend (below).

Nothing else may create one, which keeps the value in a pot exactly equal to the fees
actually withheld.

#### The readiness marker — a voluntary pool-capability signal
The pot output is REQUIRED once a slot has an active algo, and only the **pool** can
build it, because only the pool builds the coinbase. That is a genuine migration
hazard: a pool running old coinbase code against an upgraded node would produce invalid
blocks the moment its slot activated.

Block `nVersion` cannot signal this. GBT hands the pool a `version` field which it
copies into the header without having to understand it, so a v5 block proves only that
the NODE is upgraded — the pool's coinbase builder could be years old. The signal must
be something only upgraded pool software can produce, which means it has to live in the
coinbase.

So the capability is made its own proof. A pool may voluntarily add one coinbase output:

```
( 0 , "OP_RETURN OP_SOLUTIONPOT" )       // readiness marker, unspendable
```

delivered through the same GBT field mechanism as the real required outputs. A pool
that emits it has demonstrably got the "append the coinbase output GBT gave me" code
path — the same path that will later carry the pot output and the `α·r` payment. It
cannot be faked by passing a template field through, because the pool has to construct
the output. `OP_RETURN`-prefixed so it is provably unspendable and creates no UTXO; a
0-value *spendable* pot would linger forever, since the claim path releases to fee and
nobody spends an input to collect nothing.

The two shapes are deliberately distinguishable — the marker is a 0-value unspendable
`OP_RETURN OP_SOLUTIONPOT`, the real pot is a valued spendable `<algo> OP_SOLUTIONPOT`
— so a pool cannot satisfy the required-pot rule with a marker.

**The marker is INFORMATIONAL, not a consensus gate.** It deliberately does not gate
activation. Readiness is not a predicate: a supermajority of markers would not prove
the remainder is safe, nor its absence prove activation unwise, and a hard threshold
could let one large pool hold a slot hostage by simply declining to emit it. Instead the
markers are *evidence voters consult* when deciding whether to approve an algo for a
slot (doc/dynamic-algo-voting.md). Governance already judges whether an algo is worth
running; whether its slot's miners are ready is the same kind of judgement. Consequently
this adds no new activation consensus — the conditions remain the vote winner, the fee
floor, assemblability and the minimum fee history.

Staging, then: the fork activates on the existing per-algo v5 gate (node readiness);
pools voluntarily emit markers; voters weigh marker coverage per slot when approving an
algo; and once approved, the pot output and the `α·r` payment become mandatory for that
slot. A slot with no active algo is wholly unaffected — no pot, no payout,
`coinbasevalue = S + F`, exactly as today — so the blast radius is only the slots
governance has chosen to activate, and the largest-hashpower slot can stay algo-free
indefinitely at zero cost to its miners.

#### Spend paths (first push of the input's scriptSig selects)
- **`0` = claim-on-solution** — keyless, any miner. Requires: the spending block's algo
  `== algo`, and that block contains a **valid** solution for its slot (`verify() == 0`
  over real `OP_SOLUTION` outputs, §7). Releases `V` in full — the pot is a jackpot,
  not a trickle — leaving it as fee, so it enters `F` for that block and `r = S + F`
  grows with no new coinbase rule anywhere. A claim tx spends pot inputs only and has a
  single 0-value `OP_RETURN` output.
- **`1` = consolidate** — keyless, anyone, no block-context gate. Spends ≥ 2 pot outputs
  of the SAME `algo` and creates exactly one pot output of that `algo` whose value is
  the sum of the inputs, with **zero fee**. Value-preserving, so invariant 1's per-tx
  fee rule does not apply to this path.

Consolidate exists because a coinbase cannot spend inputs, so creation necessarily adds
one output per no-solution block. Without it a long dry spell would accumulate one UTXO
per block. Anyone may consolidate, and miners are motivated to, since it makes their own
eventual claim cheaper. The pot thus settles toward one UTXO per slot.

#### Invariants
- A block cannot both create and claim a pot for its slot: creation requires no valid
  solution, claiming requires one.
- A slot with no active algo neither creates nor claims; its coinbase keeps the
  pre-dynamic `S + F` (§4 applies only when a branch is active).
- Every coinbase still claims `≤ S + F`, so §4.1 holds unchanged.
- Claim ordering: `ConnectBlock` must settle the block's solution validity (§7 step 4)
  before validating a pot claim, since the claim's gate is that verdict.

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

- **Any pool, slot with NO active algo.** Nothing changes at all: no pot, no required
  payout, `coinbasevalue = S + F`. Mining is bit-for-bit as it is today. This covers
  every slot governance has not activated — including, by intention, the
  largest-hashpower one for as long as desired (§4.5).
- **Unmodified pool, slot WITH an active algo.** This is the case that is *not*
  backward compatible, and earlier drafts of this section wrongly claimed it was. The
  no-solution branch now REQUIRES a `<algo> OP_SOLUTIONPOT` coinbase output carrying
  the withheld fees (§4, §4.5), and only the pool can add it. An unmodified pool omits
  it and its blocks are **invalid**. Lowering `coinbasevalue` is not enough to steer it,
  because the obligation is an extra output, not merely a smaller claim.
- **Unmodified pool + a solution exists.** Likewise invalid rather than merely
  unrewarded: the `α·r` output is required, not optional. Note the cause, though — it is
  the missing coinbase output, never the solution tx. A solution tx can never itself
  invalidate a block (§2.1 "Delivery"), so a pool on an active slot is in the same
  position whether or not one is in the mempool: it owes the outputs either way.
- **To mine a slot with an active algo at all**, the pool must read the GBT fields and
  append the outputs they carry.

So "backward compatible" here means **a slot without an active algo is untouched** —
NOT "unupgraded pools keep working everywhere." Once a slot is activated, its miners
must have updated. That is why activation is gated socially on the §4.5 readiness
markers: voters can see, per slot and on chain, which miners have demonstrated the
capability before approving an algo for it. It remains a miner-activated soft fork in
the usual sense — a minority that never upgraded will produce invalid blocks after
activation, with revenue loss as the forcing function — but the marker makes that
minority visible *before* the decision rather than after.

The mechanism itself is still exactly segwit's: the node computes required coinbase
outputs and the pool pastes them in from a template field. Pools had to update once for
`default_witness_commitment` too; it is "universally supported" now only because
everyone updated years ago, not because it was automatic. This is exactly the segwit history: pools had
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
3. **Solution & payout.** Find the FIRST transaction in block order carrying any
   `OP_SOLUTION` output — the coinbase (§2.2) or a solution tx (§2.1). That ONE tx is
   the block's solution source; every later solution-bearing tx is ignored entirely,
   never parsed and never verified (§2.1quater). Within it, order its `OP_SOLUTION`
   outputs by `seq` (0..N-1, contiguous/unique): the `seq = 0` chunk is the committed
   `payout_scriptPubKey`, and `seq = 1..N-1` concatenated is the solution. If no tx
   carries one — **or that tx's set is malformed**, i.e. a `seq` that is non-minimal,
   negative, out of range or duplicated — the block simply **has no solution** and
   takes the no-solution branch of step 5. It is never *invalid* for this.
4. **Execute.** Load the slot's materialized algo module; run
   `verify(anchor_hash, payout, nbits, solution, out_ab)` under the gas/memory/I-O
   limits (§8), with the slot's previous blocks served through the `chain.*` imports
   (§3.1). Three outcomes, and only one of them is an error:
   - **returns 0** ⇒ valid solution; `α, β` come from `out_ab`. One run.
   - **returns non-zero** ⇒ no valid solution, and `α, β` are still in `out_ab` because
     the run completed. One run.
   - **faults, or breaches a gas/memory/I-O limit** ⇒ no valid solution — *not* an invalid
     block (§2.1quater) — but a trap may never have written `out_ab`, so `α, β` come from
     a SECOND run with an empty solution. The only path costing two runs, and the second
     is normally a memoized hit (§8.9). Pricing a fault identically to a plain
     no-solution block is deliberate: the attacker picks the solution bytes, hence whether
     the module faults, so any harsher treatment would let one garbage tx mined ahead of
     the real solution cut what that block pays its miner.
   - **a slot block consensus says must be retained cannot be read HERE** ⇒ a LOCAL
     fault ⇒ fatal error, never invalidity (§3.1).

   A block with no solution at all is priced from that same empty-solution run, which is
   how `α, β` are obtained when there is nothing to verify (§3; the empty case is the one
   input an algo's ABI must define). Getting the full per-block budget for it is wasteful
   and is an open improvement — see §9, which also records the requirement that algos
   answer it cheaply. If the algo faults even on the empty solution it cannot state its
   own `α, β`; take both as **zero**. That is deterministic, keeps the ceiling at or below
   the old-node one, and leaves the slot's blocks valid but paying nobody — which no one
   will mine and voters can de-activate — rather than invalidating every block of the
   slot. Unlike the fault case above, this input is not attacker-supplied, so zero cannot
   be provoked.

   `0 ≤ α < 1` and `0 ≤ β < 1` are automatic from the Q32 encoding (§3): nothing to
   check. Note the asymmetry with `OP_PUSHCODE`, whose grammar errors *do* invalidate a
   block (see the voting doc): pushcode bytes become consensus state every node must
   build identically, whereas solution bytes are only an input to a payment decision, so
   the worst a bad one can do is forfeit the payment.
5. **Reward split** (with `r = subsidy + total_fees`, `T = β(1−α)`, integer α,β per
   §4.4). `total_fees` already includes any solution pot released by this block, since a
   pot claim leaves its value as fee (§4.5):
   - valid solution (step 4, first outcome): the coinbase must contain the one required
     output paying `≥ α·r`
     to `payout_scriptPubKey` (§2.3); total coinbase value `≤ r`; emitted subsidy = `S`.
   - otherwise: the coinbase keeps `≤ T·r` for itself and must pay exactly `(1 − T)·F` into a
     `<algo> OP_SOLUTIONPOT` output for its own slot (§4.5); total coinbase value
     `≤ T·S + F`, hence `≤ S + F`; emitted subsidy = `T·S`, with the rest deferred via
     the milestone accounting.
5bis. **Solution-pot covenant** (§4.5), gated on the slot having an active algo. For each
   spend of an `OP_SOLUTIONPOT` output, dispatch on the scriptSig selector:
   - *claim-on-solution* (selector 0, keyless): block algo == the output's `algo`, AND
     this block has a valid solution per step 4 — so this is evaluated AFTER step 4,
     whose verdict is the gate. The tx spends pot inputs only, has a single 0-value
     `OP_RETURN` output, and `txfee ≥ Σ V` makes the whole pot fee.
   - *consolidate* (selector 1, keyless): ≥ 2 pot inputs all of the same `algo`, exactly
     one output, itself a pot of that `algo` with value `== Σ inputs`, and zero fee.
     Value-preserving, so the fee rule above does not apply to it.
   For each NEW `OP_SOLUTIONPOT` output: `algo ∈ [0, NUM_ALGOS)`, and it is either the
   required coinbase output of step 5's no-solution branch (value exactly `(1−T)·F`,
   matching the block's own algo) or a consolidate rollover. Nothing else may create
   one. Pure validation, so `DisconnectBlock` needs nothing.
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

### 8.4 Toolchain & node-hardware floor

- AOT needs LLVM per build-host (via `wamrc`), either compiled locally at activation
  or distributed as per-arch `.aot`. LLVM on small ARM devices is heavy.
- **Hardware floor (a node requirement, NOT a consensus rule):** a block carries only
  ONE dynamic-algo solution, so a validator doing **serial** verification (one verify
  at a time) needs only **~4 GB RAM** (2 GiB for the algo + node caches + OS) and
  **>= ~10 GB/s memory bandwidth**, plus a modern multi-GHz core. One verify's worst
  case is ~tens of seconds -- well inside the 120 s block interval -- so a 4 GB serial
  node keeps up in steady state. The gas limits (§8.6) are *chosen* so a floor-
  conformant node validates within the interval. Bandwidth cannot be a consensus
  parameter (consensus can't measure hardware); it only informs the limit choice.
- **~16 GB is optional, for 8-way parallel verification** -- a throughput optimization
  for initial block download (validating thousands of past blocks across cores). Not
  required; a serial node just syncs slower. Parallel verification is also where the
  process-global allocator ceiling would need scaling to N x 16 MiB (§8.5); serial
  verification (the 4 GB case) sidesteps that.
- **A below-floor node does not split the chain.** It still computes the *identical*
  validity result (gas counts + trap decision are deterministic) -- it is merely
  *slower*, and if too slow it lags block production, exactly like an under-provisioned
  Bitcoin node. So hardware variation is a liveness/participation issue, never a
  consensus fork. Small ARMv7 / low-RAM devices that cannot meet the floor may run
  pruned/SPV or validate only the primitive PoW.

### 8.5 Memory bounds (~2 GiB per verifier)

Per-verifier resident memory is bounded at **~2 GiB** across WAMR's two allocation
paths, plus a small input-sized app heap (implemented in
`src/dynamicalgo/wasmexec.cpp`):

- **Linear memory** (guest params/activations/heap; `mmap`'d, hardware-bounds-
  checked, enforced per-instance): `max_memory_pages = 32512` = **2032 MiB
  (1.984375 GiB)**, via `wasm_runtime_instantiate_ex`. WAMR only *lowers* a module's
  declared max (`wasm_runtime_get_max_mem` returns `min(module max, 32512)`), so the
  cap is a CEILING -- it can never stop a large algo from running, it only bounds one.
  *Verified*: a module that grows memory reaches exactly 32512 pages before
  `memory.grow` begins failing. A module that never grows keeps its own (smaller)
  recorded max and WAMR logs a benign "cannot override max memory" -- raising a
  ceiling is meaningless for a module that will not use it.
- **The host-managed app heap sits INSIDE linear memory, in addition to that cap.**
  `wasmexec.cpp` sizes it `inputs_total + 64 KiB`, so a verifier instance peaks at
  32512 pages plus the heap: *measured* 32514 pages (2032.125 MiB) for a small
  solution, and ~17 pages (~1.06 MiB) for a 1 MB one, since `inputs_total` includes
  the payout and solution lengths.
- **WAMR runtime allocations** (instance structs, tables, exec-env operand stack;
  via `runtime_malloc`): a **custom allocator** installed at `wasm_runtime_full_init`
  (`Alloc_With_Allocator`) enforcing a **16 MiB ceiling** -- it returns NULL past the
  ceiling, so a runaway `table.grow` (tables live here, *outside* the linear cap)
  fails deterministically instead of OOMing the node, closing the table-space channel.
- So the total is **2032 MiB + the app heap + 16 MiB ≈ 2049 MiB** worst case, i.e.
  2 GiB plus the heap -- not the exact 2048 MiB this section previously claimed. The
  module's own ceiling is deliberately kept FIXED at 32512 pages rather than reduced
  by the heap, because the heap's size depends on the block's solution length and a
  consensus memory limit must not vary with block content. Determinism is unaffected:
  every node grants the same 32512 growable pages for the same block, so
  `memory.grow` fails at the identical point everywhere. Only the node's own RSS
  varies by up to ~1 MiB, which is not an observable the module can branch on.

Notes:
- `WASM_STACK_BYTES = 1 MiB` is the exec-env operand-stack size (consensus constant:
  too small traps a legit module). It is drawn *from* the 16 MiB ceiling, not added.
- The guest module's own `malloc` (dlmalloc compiled into the `.wasm`) operates
  inside linear memory and never touches the custom allocator.
- The AOT native code is `mmap`'d executable on its own path -- outside the 2 GiB
  (small, identical on every node).
- Basis (`~/git/llm.c` `doc/btm-proof-of-useful-work.md`): 8-way parallel
  verification fits ~16 GB commodity RAM; 2 GiB sits under wasm32 dlmalloc's ~2 GiB
  single-allocation ceiling; E=64 is the largest wasm32-safe MoE config.
- **Measured**: the trunk grows linear memory to **31,163 pages (1.902 GiB)**,
  ~84 MiB (4.3%) under the 32512 cap -- deliberately tight (E=64 ≈ 2 GiB). Note the
  trunk *does* grow memory, so it keeps a large declared max and the 32512 ceiling
  applies to it normally.
- An algo that wants more than its initial memory must of course emit `memory.grow`
  (any module with a real allocator does); a module compiled to never grow is held
  at its own recorded max, which is its own choice, not a limit imposed here.
- **Caveat**: the custom allocator is process-global, so the 16 MiB ceiling bounds
  concurrent instances collectively -- strictly per-instance only for one verify at a
  time; N-way parallel scales it to N x 16 MiB (linear stays per-instance).
- **Cold-materialization cost**: first-touch faulting the ~2 GiB working set costs
  ~1 s (kernel page-zeroing ~2 GB/s) -- not a wasm op, so it escapes gas metering; it
  is bounded (<= ~1 s by the 2 GiB cap) and carried as a fixed term (§8.6).

### 8.6 CPU bound (per-class gas)

Metering is **wasm instrumentation before AOT-compile**: the offline tool
(`src/dynamicalgo/gasinstrument.cpp`) injects, per basic block, calls to imported
host functions that charge that block's work; `wamrc` then compiles the checks to
native, so metering runs at native speed. The runtime (`wasmexec.cpp`) supplies the
host functions, accumulates **per-class counters**, and traps the instant any class
exceeds its limit -- deterministically (costs come from the deterministic bytecode;
the trap decision is a pure function of them). *Enforcement across per-class counters
is designed here; the runtime currently ships a single combined `usegas` counter --
the per-class split is the next implementation step.*

**Opcode classes** -- 15 "count" classes (charged 1/execution, members share ~equal
per-op *worst-case* time) + a combined bulk-bytes class (charged N = runtime size).
Exact opcode->class map in `gasinstrument.cpp`. Per-op ns are native latency-basis
(conservative: latency >= throughput; MEM/SIMD_MEM/VAR are L1-warm). Note the old
"NOP" was split three ways by worst-case cost -- see the NOP/ICONST/VAR note below:

| class | members (summary) | ns/op |
|---|---|---:|
| NOP | nop, drop, block/loop/end, ref.* (structural, no instruction) | **0** |
| ICONST | i32/i64.const (register `mov` worst case) | 0.25 |
| VAR | local.get/set/tee, f32/f64.const (spilled slot / const-pool load) | 1.0 |
| BRANCH | br, br_if, br_table, return, select, if, else | 0.3 |
| CALL | call, call_indirect | 1.5 |
| INT | i32/i64 add/sub/logic/shift/cmp/clz/ctz/popcnt/wrap/extend | 0.33 |
| IMUL | i32/i64 mul | 1.0 |
| IDIV | i32/i64 div/rem | 7.2 |
| FADD | f32/f64 add/sub/mul/neg/abs/min/max/copysign/cmp | 1.0 |
| FDIV | f32/f64 div, sqrt | 5.0 |
| FCVT | ceil/floor/trunc/nearest, convert/promote/demote | 1.5 |
| MEM | scalar loads/stores, global.get/set, memory.size, table.get/set | 1.6 (L1) |
| SIMD | v128 arith/logic/cmp/splat/lane | 0.93 |
| SIMD_DIV | v128 div/sqrt | 3.7 |
| SIMD_MEM | v128 loads/stores/lane | 0.94 (L1) |
| BULK | memory/table fill+copy+init+grow, by N bytes | ~0.5/byte (cold) |

- **NOP/ICONST/VAR** were one class until measured worst cases forced the split:
  structural NOP emits *no* instruction (exactly 0, so its limit is a pure count cap);
  `i32/i64.const` folds to an immediate or, worst case, a register `mov` (~0.25 ns);
  `local.*`/`f-const` fold to a register / hoisted const but, worst case, become an
  L1 stack-slot or const-pool load (~1 ns). `if`/`else` moved to BRANCH (a branch),
  `global.*`/`memory.size` to MEM (a memory access) -- so no cost hides in "NOP".
- table bulk ops are allowed: *space* bounded by the 2 GiB total cap (§8.5), *time*
  by the combined BULK byte budget.

**Measured trunk profile (one full eval)** + per-class limits. Rule:
`limit = max(2 x count, count-for-a-0.5 s slice)`, so every class gets >= 0.5 s of
headroom and the compute-dominant classes (which the LLM genuinely needs) are pinned
by 2xcount. Safe because the algo is data-oblivious => counts are fixed per input.

| class | executions | limit | max time |
|---|---:|---:|---:|
| VAR | 8,380,928,112 | 16 B | 16.0 s |
| SIMD_MEM | 2,262,561,184 | 5 B | 4.70 s |
| SIMD | 2,306,983,477 | 5 B | 4.65 s |
| INT | 3,708,852,924 | 8 B | 2.64 s |
| ICONST | 3,277,654,242 | 8 B | 2.00 s |
| IMUL | 4,697,157 | 512 M | 0.51 s |
| FADD | 153,250,325 | 512 M | 0.51 s |
| MEM | 69,938,770 | 320 M | 0.51 s |
| FDIV | 4,734,311 | 100 M | 0.50 s |
| BRANCH | 616,660,453 | 1.6 B | 0.48 s |
| CALL | 7,187,197 | 320 M | 0.48 s |
| FCVT | 5,065,092 | 320 M | 0.48 s |
| SIMD_DIV | 262,912 | 128 M | 0.47 s |
| IDIV | 8,913 | 64 M | 0.46 s |
| NOP | 85,557,450 | 16 B | 0 |
| BULK (bytes) | fill 4.7 MB, copy 629 KB, grow 2.04 GB | **8 GiB combined** | ~2 s |

- Implied worst-case verify (limits x times) ≈ **~35 s compute + ~2 s BULK + ~1 s
  cold materialization ≈ ~38 s** on a reference core (conservative -- latency-basis
  and adversarial spill assumed; the LLM's real forward is ~1.5 s). On 4x-slower
  hardware ~150 s -- so the reference-core figure has ~3x margin under the 120 s
  interval, and the hardware floor (§8.4) is set so conformant nodes stay under it.
- **VAR dominates the worst case (16 s)** -- the LLM's stack-machine verbosity emits
  8.4 B local/const ops that cost ~0 in practice (register-resident) but ~1 ns if an
  adversary forces spills; we bound the adversarial case. The next tier is the
  genuine compute (SIMD_MEM/SIMD/INT ≈ 12 s). Rare/cheap classes sit at their 0.5 s
  slice; a loose limit stays safe iff `limit x ns/op` is a small budget slice.
- No general upper bound on arbitrary-algo gas is computable (halting problem); the
  per-class limits *are* the enforced bound. **Data-obliviousness** (input-independent
  control flow, true of NN forward passes) is the property checked at OP_PUSHCODE
  approval so one measurement bounds the counts.
- **Cache-miss worst case (memory classes).** The `MEM`/`SIMD_MEM` per-op times above
  are L1-warm; a cache-hostile module could miss to DRAM (~100 ns latency each). This
  does *not* blow up unboundedly: (1) it is bounded by the op-count *limit*, and (2)
  miss *throughput* is bandwidth-limited (misses overlap ~10-20 deep), so worst-case
  memory time = `(SIMD_MEM + MEM limits) x 64 B (cache line) / min-bandwidth` ≈
  `5.3 B x 64 B / 10 GB/s ≈ 34 s` -- not `count x 100 ns`. That fits the 120 s
  interval. The LLM itself measured 0.66 ns/load amortized (forward 1.5 s / 2.26 B
  loads), proving its access is cache-friendly. The `min-bandwidth` here is the §8.4
  hardware floor, not a consensus value: gas op-counts + limits are the consensus
  bound; wall-time is hardware-dependent and only guaranteed to fit for floor-
  conformant nodes.

- **Metering overhead (on top of the per-op tables).** Gas is charged per basic
  block, so a run makes one `usegas` host call per opcode class present per
  block-entry executed. That call cost (~a few ns each) is *not* in the per-op tables
  above, but it is bounded: total block-entries <= the back-edge/branch budget
  (`BRANCH` limit 1.6 B, one per loop iteration) plus function entries (`CALL` limit
  320 M), and each entry emits a small constant number of charge-calls -- so metering
  adds an `O(BRANCH + CALL)`-bounded overhead (order ~10 s at the limits, ~a few 100 ms
  for the real trunk, whose blocks are large). It scales with node speed like any
  other compute and is covered by the §8.4 floor. The charge-calls are also why NOP's
  16 B limit is only a backstop: a pure-NOP loop is bound first by its back-edge
  (`BRANCH`), not by the NOP count.

All class definitions, limits, per-op costs, and the 8 GiB combined BULK budget are
consensus parameters, pinned with the instrumenter + WAMR version. Implemented in
`src/dynamicalgo/gasclasses.h` (the shared taxonomy + limits), `gasinstrument.cpp`
(offline per-class instrumentation), and `wasmexec.cpp` (runtime per-class
enforcement + trap). Instrumenter output verified to type-check and compile (wamrc /
wasmtime) on the trunk, MoE, and non-SIMD verifiers; measured trunk counts all sit
under their limits (binding class VAR at ~52% of budget, combined BULK ≈ 2.05 GB of
8 GiB).

### 8.7 Chain-access I/O bound, and ABI notes

The `chain.slot_block()` accessor (§3.1) needs budgets of its own, because **neither
the gas classes nor the memory cap bound disk reads**:

- A fetch costs the module ONE `call` instruction but costs the node a block read.
  The `GC_CALL` budget is 320,000,000, so charging one CALL per fetch would permit
  ~320M reads — tens of terabytes.
- Memory does not bound it either: a module can fetch every block into the *same*
  buffer, so its footprint stays flat while I/O runs unbounded.
- Reusing the 8 GiB `BULK` budget would at least bound it, but a disk byte costs
  ~100× a `memory.fill` byte, so they cannot share a limit, and 8 GiB of reads is
  ~82 s on a spinning disk — more than doubling the §8.6 worst case.

So two dedicated consensus budgets, per `verify()` call, bounding different things:

| Budget | Limit | Bounds | Worst case |
|---|---|---|---|
| `GAS_IO_CALLS_LIMIT` | 1024 fetches | fixed per-fetch overhead (index walk, seek, deserialize) that even a tiny block pays — i.e. IOPS | ~7 s at ~150 IOPS (HDD); negligible on SSD |
| `GAS_IO_BYTES_LIMIT` | 256 MiB | transfer volume | ~2.5 s at ~100 MB/s (HDD); ~0.5 s on SSD |

They cross over usefully: 1024 × `MAX_BLOCK_SERIALIZED_SIZE` far exceeds the byte
cap, so BYTES binds for large blocks and CALLS binds for small ones. Combined worst
case ≈ 10 s of I/O next to ≈ 38 s of compute — same order, not dominating. Exceeding
either traps exactly like a count-class overrun. The call is charged BEFORE the
lookup, so an out-of-range probe is not free.

These caps deliberately do **not** permit folding the whole 32850-block window in one
call (see §2.5): that would be minutes of I/O per block on any budget worth having.

ABI notes:

- The node marshals inputs above `__heap_base` and calls `verify()` with the offsets;
  reads the i32 result and the 8-byte `out_ab` (two Q32 `u32`, §3). No float crosses
  the ABI, so the money path is integer-only. `host.c` was the wasm3-era prototype;
  the WAMR bridge replaces it.
- The module is freestanding apart from the host functions it may import:
  `metering.usegas` (§8.6) and `chain.slot_block_count` / `chain.slot_block` (§3.1).
  Guest code cannot charge the host-side budgets: `usegas` ignores any class id at or
  above `GC_USEGAS_MAX`, which is where the I/O class ids live.
- Grinding resistance: the seed's payout half is miner-controlled, so an LLM algo's
  validation-set selection must itself be grinding-resistant; the prev-block-hash half
  is not grindable without redoing that block's PoW.

### 8.8 Bounding AOT compilation

> **STATUS: deferred (decided 2026-09-24).** The deterministic static caps below
> are the intended long-term design but are **not being built now**. Rationale: an
> algo with pathological compile cost is very unlikely to pass governance, and even
> if one did, the dynamic solution is *optional per block* -- miners simply mine
> **primitive** (non-dynamic) blocks for that slot until a replacement algo is voted
> in, so a bad algo degrades the dynamic slot rather than halting the chain. This
> consciously makes **governance vetting + the activation lead time the security root
> for compile cost, for now** (a reversal of the "don't rely on social vetting"
> stance below, taken deliberately as a prioritization call).
>
> **Residual risk being accepted:** the primitive-block fallback fully covers a
> merely *slow* algo (nodes lag at activation then catch up -- the §8.4 hardware-floor
> case, no fork). The one case it does *not* cover is an algo that **compiles on some
> nodes but OOMs / never finishes on others** while a miner produces a dynamic block
> against it -- that is a fast/slow validity split, not just degraded service.
> Governance review + lead time is what carries this risk until the caps below are
> implemented. Execution-time gas (§8.6) is unaffected and remains enforced.

**Measured anchors (trunk / MoE verifiers, 2026-09-24).** Per-function maxima over
the real verifiers, to anchor future caps (legit algos need very little; caps get
generous headroom + `wamrc` fuzzing at the caps to fix the safe ceiling). Tool:
walks the code section with the instrumenter's opcode decoder. Notably clang emits
**only empty (`0x40`) block types** (0 non-empty across the module), so conditionals
lower to `br_if`/`select` (max `if` = 0) and the operand-stack depth below is exact,
not estimated.

| per-function metric | trunk (SIMD) | MoE | drives (LLVM/wamrc) |
|---|---:|---:|---|
| instructions | 4,449 | 4,449 | SSA values, most passes |
| body bytes | 8,839 | 8,839 | decode + overall |
| ctrl structures (block+loop+if) | 263 | 263 | ~basic-block count |
| blocks / loops | 211 / 52 | 211 / 52 | CFG size, loop passes |
| branches (br/br_if/br_table) | 381 | 381 | CFG edges |
| calls | 63 | 63 | inlining / callgraph |
| scalar mem ops | 416 | 416 | mem/alias analysis |
| params + locals | 125 | 101 | register pressure |
| control-nesting depth | 35 | 35 | dominator-tree depth |
| loop-nesting depth | 5 | 5 | nested-loop passes |
| operand-stack depth (exact) | 42 | 27 | intra-expr live temps |
| br_table fan-out | 57 | 57 | jump-table CFG edges |

Module-level (trunk SIMD): 196 defined functions, 1 table, 2 globals, 1 memory,
2 data + 1 elem segment, ~86 KB code. All values are tiny for LLVM, so the caps,
when built, can sit far above the trunk and still never bother a legitimate algo.

**Intended approach when revisited** -- deterministic caps, no governance dependency:

`wamrc` compile time/memory can blow up on adversarial `.wasm` (LLVM passes are
superlinear in some per-function metrics, and for arbitrary input the cost is not
statically predictable). Compilation is rare -- once per algo activation (~8 algos,
with a long governance lead time before the algo is active) -- but the goal is to
bound it **without relying on social vetting as the security root** (that would
undercut trustlessness). Governance and the activation lead time are defense-in-depth,
not the guarantee.

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

### 8.9 Memoizing `verify()` — required, not an optimization
`verify()` is a pure function of a small, fully enumerable set of inputs, and one call
costs up to ~38 s (§8.6). Its results must therefore be cached, and this is a
**requirement for an expensive algo to be mineable at all** rather than a performance
nicety. Two independent reasons:

- **Template construction.** `getblocktemplate` rebuilds a template on every new tip, at
  most every 5 s when the mempool changes, **and on every change of the requested algo**
  (`rpc/mining.cpp`) — and the cache holds exactly one template, so a pool rotating
  through 8 algos rebuilds on every single call. Each rebuild runs `verify()` twice: once
  in `ResolveAlgoReward` to price the coinbase, once more inside `TestBlockValidity`. At
  the LLM trunk's real ~1.5 s that is ~3 s of CPU *per call per algo*; at the gas limits
  it is ~76 s, i.e. no template can be produced at all. This is a latent property of the
  current code, not something solution selection introduces.
- **Solution selection** (§2.1quater) depends on a rejected candidate staying rejected
  for free, which is exactly a cache hit — and on that holding for every malleated copy
  of the same solution, which is why the key below is content and not a txid.

**The key must be the complete input set**, or the cache can return a verdict for a
different computation:

```
key = Hash(branch ‖ algo ‖ anchor ‖ nbits ‖ payout ‖ solution)
val = { ok, solution_valid, alpha_q32, beta_q32 }
```

`branch` fixes the module, and `anchor`, `nbits`, `payout` and `solution` are verify()'s
literal arguments (§3). The slot-block window served through the `chain.*` imports (§3.1)
is **not** a further input: for any parent between two blocks of the slot, the newest
same-algo block at or below it *is* the anchor, so `(branch, algo, anchor)` fixes both
the window and `slot_block_count()`. A reorg below the anchor changes the anchor hash,
since a block hash commits to its ancestors. Nothing outside the key can change the
result.

This sits on the consensus path, so it takes the same care as Core's script execution
cache (`InitScriptExecutionCache`): a fixed memory bound set at startup, and a cuckoo
cache or equivalent so eviction is O(1) and the size is a hard limit rather than a hope.
Being a pure-function cache it can never change a verdict — only skip recomputing one —
so unlike the activation store it carries no divergence risk if it is cold, dropped or
sized differently from node to node.

Consequences once it is in place: every template rebuilt against the same tip does
**zero** verifier runs; a block that arrives after we templated against the same solution
validates without running the module; and the no-solution branch's second run (§7 step 4)
is a hit rather than a recomputation.

`nbits` is in the key because `verify()` takes it, and that costs nothing in practice: the
per-algo retarget is epoch-stable (§2.1quater), so entries for a slot survive until that
slot produces a block — which starts a new epoch and a new anchor anyway.

A failed run is cached exactly like a successful one — "this does not verify" is as much a
function of the inputs as "it does", and it is the answer an attacker would most like to
make a node recompute. `chain_unavailable` is the sole exclusion.

---

## 9. Open items / parameters

- **SSF over-payment fix (bundle into the dynamic-algo activation soft fork).** The
  legacy `GetBlockSubsidy` truncates the SSF penalty via `convert_to<uint32_t>()`, so
  near an algo's hashrate peak the scaled subsidy comes out ABOVE the value the formula
  intends. It is bounded `≤ baseSubsidy` (so NOT an inflation/supply bug -- the emission
  cap holds), but it over-pays vs the formula in that region. This is soft-fork-fixable
  (a *tightening*): add `GetBlockSubsidyCorrected()` computing the penalty in wide
  integers, and from the fork's activation height enforce
  `coinbase ≤ nFees + min(S_buggy, S_correct)`; feed that same corrected/`min` `S` into
  `ComputeRewardSplit` (one-line change at the ConnectBlock call site) so the ceiling and
  `α·r` agree. NOT in scope: the near-peak NEGATIVE region is the formula's own behavior
  and clamping it up to 0 is a *raise* = hard fork; leave it (the dynamic split already
  handles negative `S` safely, §4.4). Priority: finish the dynamic-algo mechanism first.
- Solution assembly: RESOLVED -- no consensus `MAX_SOLUTION_BYTES` (block weight + gas
  bound it, §2.1); payout scriptPubKey is the `seq=0` chunk, solution is `seq=1..N-1`
  (§2.1); assembled by `dynamicalgo::ExtractBlockSolution`.
- `submitsolution`-style RPC for handing a solution tx to the node, bypassing mempool
  ranking (§2.1quater). A convenience, not a defence.
- Relay of solution txs (policy, not consensus): **implemented** — `OP_SOLUTION`
  standardness (multiple `OP_RETURN`s, dust-exempt) + `MAX_SOLUTION_TX_WEIGHT` /
  `MAX_SOLUTION_TX_INPUTS` (§2.1ter). Still optional: a global `MAX_SOLUTION_TXS` queue
  cap.
- **Solution selection from the mempool (§2.1quater): IMPLEMENTED.**
  `BlockAssembler::SelectSolution` / `AddSolutionPackage` (`node/miner.cpp`), the
  per-epoch budget in `dynamicalgo::CandidateBudget` behind `-maxsolutionverify`, the
  first-wins read in `dynamicalgo::ExtractBlockSolution`, and the fall-through in
  `Chainstate::ResolveAlgoReward`. The `α·r` coinbase output joins the pot output in
  `vRequiredCoinbaseOutputs`, so GBT's `coinbaserequired` carries it to pools unchanged.
  What the spec work settled:
  - a solution can never invalidate a block — malformed chunk sets, a verifier fault,
    out-of-gas and rival solution txs all fall through to the no-solution branch (§7
    steps 3–4), so the mempool is not a minefield for pools that have not implemented
    selection, and a miner's mistake costs part of one reward rather than the block;
  - the block's solution is the FIRST solution-bearing tx in block order; later ones are
    ignored unparsed, which is what holds block verification at one `verify()` run (§7
    step 3);
  - losing candidates are mined anyway for their fees, placed after the chosen one —
    which is what makes ordering by declared feerate sound rather than a free bluff;
  - the verification budget is **candidate runs per slot per anchor epoch**, never per
    template rebuild (§2.1quater rule 1). Needs a node option and a default.
  - *Open:* the `-maxsolutionverify` default (1) and the optional `MAX_SOLUTION_TXS`
    queue cap (not implemented) want a second look once a real algo's measured verify
    time is known, since ~38 s is the adversarial bound and the LLM trunk's real forward
    is ~1.5 s. Also untested end-to-end: no test activates an algo yet, so the selection
    path has only unit coverage of its parts
    (`feature_solutionpot.py` Layer B is where this gets exercised).
- **Nothing uses the 720-block activation notice.** The delay exists so miners can
  prepare: once a window closes, the winner and the height are settled and `getalgovote`
  reports `winner`, `activation_block` and `enforced_from`. But the node itself does not
  act on it — `ModuleStore::GetOrCompile` materializes a branch on FIRST USE, so the AOT
  compile lands on whichever template or block first needs it, i.e. exactly at
  `enforced_from`. With compile time still unbounded (§8.8) that is the worst possible
  moment for it. It should pre-compile during the delay instead: on each new tip, if a
  slot has a settled winner that is assemblable and not yet materialized, compile it in
  the background. Cheap to do, and it turns §8.8's compile-bound problem from a
  block-validation risk into a day's advance work.
  One wrinkle to respect: assemblability is only final AT the activation height, because
  pushcode allows forward references, so a branch that cannot be assembled when the
  window closes may become assemblable during the delay. Pre-compilation must therefore
  re-check rather than conclude once.
- **A stricter gas budget for the EMPTY solution (future improvement, but state the ABI
  requirement now).** `verify()` is called with an empty solution purely to read α and β
  (§7 step 4) — there is nothing to verify, so an algo should be able to answer from its
  parameters without touching its model. Today that call gets the full per-block budget,
  so the no-solution branch, and the second run on the fall-through, can each cost up to
  ~38 s (§8.6) for work that produces two 32-bit numbers. A separate, much smaller limit
  for `solution_len == 0` would make a no-solution block nearly free to validate, cut the
  miner's per-epoch α₀/β₀ cost to almost nothing (§2.1quater), and shrink what an
  attacker gets out of a faulting solution. The condition is unambiguous — exactly
  `solution_len == 0`, so a 1-byte solution still buys the full budget and there is no
  cliff to game.
  **Do not wait to state the requirement, though:** algo authors must know that the
  empty-solution path has to be cheap, because adding the limit after algos exist would
  invalidate any that fold their model to answer it. The approval process (§8.6
  data-obliviousness check) is the natural place to measure it. The limit value itself,
  and whether it is one number or a per-class scaling of the main table, is open.
- **`verify()` memoization (§8.9): REQUIRED, NOT YET IMPLEMENTED.** Discovered while
  specifying selection: `getblocktemplate` rebuilds a template every 5 s (and on every
  algo change, with a one-entry cache), and each rebuild runs `verify()` twice, so an
  activated expensive algo is unmineable without this — a latent problem in the current
  code, independent of selection. Content-addressed key, fixed memory bound, cuckoo
  cache like `InitScriptExecutionCache`. Pure-function cache, so no divergence risk.
- Gas metering (§8.6): **implemented.** Mechanism + 15 count classes + combined BULK
  budget + measured trunk profile + per-class limits + per-op times calibrated, and
  per-class enforcement wired end-to-end: shared taxonomy/limits in
  `src/dynamicalgo/gasclasses.h`, per-class + bulk-N-via-scratch-global charges in
  `gasinstrument.cpp`, per-class counters + limits + 8 GiB BULK budget + per-class
  trap in `wasmexec.cpp`. Instrumenter output verified to type-check/compile on the
  trunk, MoE, and non-SIMD verifiers; trunk counts all sit under the limits.
- Verifier ABI (§3, §3.1): **resolved and implemented.** `verify()` takes
  `anchor_hash, payout, nbits, solution, out_ab`. The seed anchors to the previous
  block of the block's own SLOT, not the immediate parent (§2.1bis), so a solution
  lives ~16 min instead of 120 s — replay-safe because the branch verified is the
  block's own slot's, giving exactly one payable block per anchor. α and β MAY depend
  on the solution (left to each algo's architects); only the empty-solution case must
  be defined, and a varying α means pools prefer the lowest one (§3). The block's own
  txs are NOT an input (circular — §3); the slot's previous blocks are reached through the
  `chain.slot_block_count` / `chain.slot_block` imports over a 32850-block window,
  framed `TX_NO_WITNESS`, metered by the §8.7 I/O budgets, with an unreadable
  in-window block escalating to a fatal error rather than invalidating the block.
  Node side: `SlotBlockSource` (`dynamicalgo/wasmexec.h`) + `ChainSlotBlockSource`
  (`validation.cpp`).
- **Stateful-algo history delivery (OPEN, and the successor to the ABI work).** The
  I/O budgets make the slot window reachable but not traversable in one call (§2.5),
  so an algo whose state is the fold of all history — the llm.c LoRA chain — cannot
  re-derive it inside `verify()`. Options: on-chain weight-state checkpoint epochs
  (`llm.c doc/btm-proof-of-useful-work.md`, "checkpoint epochs"), or node-held state
  passed to `verify()` (that doc's "resident state in an embedded node"). The
  resident-RAM variant costs ~1.76 GB per stateful slot, ~14 GB if all 8 slots run
  one, so the disk-backed form (a memoization like `llmc/btmcache.h`, loaded per
  call) is the one to pursue. The accessor ABI forecloses neither.
- **Solution pot (§4.5): SPECIFIED, NOT YET IMPLEMENTED.** This is now the blocker for
  the miner-side work: it changes what the coinbase may claim, so the template builder
  (phase 6.7b) cannot be written against the old rule. Needs:
  - `OP_SOLUTIONPOT` (`OP_NOP8`, `0xb7`) and a `TxoutType::SOLUTIONPOT` matcher that
    distinguishes the valued spendable pot from the 0-value unspendable readiness
    marker;
  - the required coinbase pot output in the no-solution branch, and the `α·r` output in
    the solution branch, both delivered to pools as GBT fields (§6bis);
  - the claim-on-solution and consolidate covenant paths (`ConnectBlock` step 5bis),
    noting the ordering constraint: a claim is gated on the block's solution verdict,
    so it must be validated after step 4;
  - `ComputeRewardSplit` reworked so `β(1−α)` scales `r` rather than `S`, returning the
    pot amount as a REMAINDER (§4.4) so no satoshi is lost to double flooring;
  - the readiness marker itself, plus an RPC surfacing per-slot marker coverage so
    voters can weigh it (`getalgovote` is the natural home — see the voting doc). This
    is the piece that replaces a consensus readiness gate, so it is a deliverable, not
    a nicety: without it the marker exists but nobody can see it.
- **Also now known to be broken until that lands:** `node/miner.cpp` sets
  `coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(...)` unconditionally, i.e. the
  full `S + F`. On a slot with an active algo that exceeds the ceiling in the
  no-solution case and omits the required `α·r` payout in the solution case, so the
  miner would build invalid blocks. Latent today only because no test activates an algo
  (activation needs OP_VOTE plus the 720-block delay), leaving `branch` always nullopt.
  The fix shares one code path with `CheckDynamicAlgoReward` so the template cannot
  drift from consensus.
- Materialized-algo store: format and where the ~8 activated modules live; re-vote
  swap-in.
- Per-height/per-algo RSF index: storage format and rebuild-on-reindex.
- **ARMv7 SIMD determinism** (§8.3): verify on real hardware whether v128 float can be
  made IEEE-correct (denormals), or mandate the scalar module on ARMv7.
- **AOT toolchain / packaging** (§8.4): compile `.wasm`->`.aot` locally per node via
  `wamrc` at activation, or distribute per-arch `.aot`; LLVM availability per arch.
- **Pinned per-arch AOT target flags** as consensus parameters (§8.3). *Done:* the
  2 GiB memory split (`max_memory_pages = 32512` + 16 MiB custom-allocator ceiling)
  and `WASM_STACK_BYTES = 1 MiB` are implemented in the bridge (§8.5).
- Node hardware floor for dynamic-algo validation vs. primitive-only/pruned nodes (§8.4).
- WAMR vendoring: *done* -- pinned to commit `b70d708`, vendored to `src/wamr/`, bridge
  rewritten against WAMR's AOT API (§8.1). *Still open:* the offline `wamrc`
  AOT-compile step with pinned per-arch target flags at algo activation.
- **Structural caps / compile-time bound** (§8.8): **deferred (2026-09-24).** Relying
  on governance vetting + activation lead time + the primitive-block fallback for now
  (see §8.8 STATUS). Trunk/MoE per-function metrics measured and recorded as future
  anchors. Still to build when revisited: exact consensus cap values, the pinned
  `wamrc` opt pipeline, and a `wamrc` fuzzing harness.
- **Fast JIT fallback** (§8.8): *evaluated -- not viable* (no SIMD; crashes on the
  trunk). Compile-bound rests on the LLVM-AOT path (structural caps).
- Data availability of LLM validation examples: inline merkle-branch proofs carried in
  the `OP_SOLUTION` stream (fold the proof format in — see the voting doc).
- Reserve flow rate `k` (=1 for now; the future `<ctype>` field would let contracts pick
  other release rules). No `s0` ceiling — the Q16 encoding keeps `s0 < 1`.
- Reserve refund sighash: reuses `TransactionSignatureChecker` with `SIGHASH_ALL` and
  the reserve scriptPubKey as scriptCode (SIGHASH_ALL covers outputs → no malleability).
  IMPLEMENTED in 6.6; keep an eye on the sighash convention if segwit/taproot ever
  activate on Bitmark.
