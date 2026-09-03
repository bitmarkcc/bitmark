# Dynamic-algo voting & activation (design)

Status: DESIGN (2026-08-23). Selects which assembled OP_PUSHCODE branch becomes
the dynamic PoW algo for a given mPoW slot. Companion docs: pushcode-port-27xb.md
(how code is pushed/stored/assembled) and (TODO) dynamic-algo-mining.md (execution,
reward split, enforcement). This note covers ONLY vote encoding + tally + activation.

## Soft-fork model

Everything here is soft-fork-safe: votes are OP_RETURN outputs (unspendable,
ignored by old nodes) and stake is an ordinary CSV-timelocked output (old nodes
accept it). Activation only adds requirements new nodes enforce; old nodes keep
accepting the base-PoW blocks. No hard fork.

## Slots

A "slot" is one of the 8 existing mPoW algo slots (scrypt / sha256d / argon2 /
x17 / yescrypt / equihash / ...). A slot is either primitive-only (no dynamic algo
voted in -> mined exactly as today) or dynamic (an algo has been activated for it).
Slots are numbered by the existing Algo enum. A slot can be re-voted to a new algo
later; "the algo for slot S at height h" is a deterministic function of the chain
(below).

## OP_VOTE encoding

Votes are PER-OUTPUT, not per-transaction (REVISED 2026-08-30): a vote is fully
specified by a single output, so one transaction -- e.g. a COINJOIN -- can carry
any number of independent votes (fee or stake, different branches/slots, different
people) mixed with ordinary outputs. There is NO "one vote per tx" rule. A vote's
weight comes from that output alone. OP_VOTE = OP_NOP5 (0xb4) is the marker opcode;
branch_hash = the content hash (PushCodeHash) of the algo branch being voted for
(need not be assemblable yet); slot = the target mPoW slot.

Two output types, two constituencies:

### FEE_VOTE (the "user"/fee-payer constituency) -- unspendable
    OP_RETURN OP_VOTE <branch_hash:32> <slot>          (TxoutType::FEE_VOTE)
    weight = tx_fee / num_outputs
tx_fee = sum(inputs) - sum(outputs), divided by num_outputs so a coinjoin's shared
fee is not over-credited; each FEE_VOTE output in the tx gets that share. Computing
it needs the spent-input values (block undo data; no -txindex required). Under
OP_RETURN the output is unspendable and OP_VOTE is never executed.

### STAKE_VOTE (the "investor"/stake constituency) -- spendable after the lock
    <lock> OP_CHECKSEQUENCEVERIFY OP_DROP OP_VOTE <branch:32> OP_DROP <slot> OP_DROP <payout>
                                                       (TxoutType::STAKE_VOTE)
    weight = the output's value, counted only when lock >= VOTING_PERIOD (5760)
Self-describing and spendable: `<lock> OP_CSV OP_DROP` is the relative timelock;
OP_VOTE marks it as a vote; branch and slot are pushed-and-dropped so they are
readable in the scriptPubKey without affecting the spend; `<payout>` (a standard
script) receives the coins back after the lock. So the voter's stake is LOCKED
(BIP68) for >= VOTING_PERIOD from confirmation -- real opportunity cost, Sybil
resistance -- but recoverable, unlike a burn. The CSV/branch/slot are visible in
the scriptPubKey (NOT behind P2SH) so the tally reads them at creation time.

Why not the OP_VOTE opcode inside a spendable script by default: OP_NOP5 is a
discouraged upgradable NOP (policy), so a spend would be non-standard. Fixed by
giving OP_VOTE a DEFINED-no-op case in the interpreter (removed from the
discouraged set) -- a pure policy relaxation (consensus already treats OP_NOP5 as a
no-op), which permanently claims OP_NOP5 as OP_VOTE (no future upgrade of it).

Standardness: FEE_VOTE and STAKE_VOTE are recognized by Solver (MatchFeeVote /
MatchStakeVote) and made relay-standard in policy (STAKE_VOTE only if its embedded
payout is itself a standard type). So votes relay/mine without -acceptnonstdtxn.

CSV ACTIVATION (2026-08-27): CSV (BIP68/112/113) is NOT active on Bitmark
mainnet/testnet as shipped (CSVHeight = INT_MAX) -- OP_CHECKSEQUENCEVERIFY would be
a no-op and the stake would not actually lock. So CSV is ACTIVATED as part of THIS
dynamic-algo soft fork, gated on the SAME miner-signalled base-version-5
supermajority that already enables OP_PUSHCODE (no hardcoded height). Wiring
(validation.cpp, via a shared DynamicForkActive helper): OR the pushcode-
supermajority into the SCRIPT_VERIFY_CHECKSEQUENCEVERIFY / BIP112 gate
(GetBlockScriptFlags), the BIP68 LOCKTIME_VERIFY_SEQUENCE gate (ConnectBlock), and
the BIP113 MTP gate (ContextualCheckBlock). So CSV, OP_PUSHCODE and OP_VOTE all go
live together at the same height. (CLTV/BIP65 is already active; it was the
absolute-timelock fallback if CSV were not bundled -- CSV is preferred as the
relative lock is automatic from confirmation.)

## Window, denominators, thresholds

- VOTING_PERIOD = 720 * 8 = 5760 blocks (~8 days at 720 blocks/day). Sliding
  window: it may start at any height.
- Tally for a window ending at height E and slot S: over all vote OUTPUTS confirmed
  in [E - 5759, E] targeting slot S,
    F(H)  = sum of fee_weight   of FEE_VOTE outputs for branch H
    K(H)  = sum of stake_weight of STAKE_VOTE outputs for branch H
    Ftot  = sum over all H of F(H)      (total fee-weight cast for slot S)
    Ktot  = sum over all H of K(H)      (total stake cast for slot S)
- Supermajority + fee floor: branch H QUALIFIES at window-end E iff
    F(H) >= 0.75 * Ftot   AND   K(H) >= 0.75 * Ktot   AND   Ftot >= fee_floor(E)
  Because 2 * 0.75 > 1, at most one H can hold >=75% of Ftot (and of Ktot), so the
  qualifying branch is unique. The 75% denominators are "of votes cast for the
  slot"; the fee floor adds an ABSOLUTE participation requirement so a slot cannot
  be captured by tiny turnout.

### Fee participation floor (added 2026-09-02)
    year_fees  = total tx fees over the 720*365 = 262800 blocks ending at the block
                 right before the voting window (i.e. ending at f - 1)
    fee_floor  = 0.0625 * (year_fees / 365 * 8)     [ = year_fees / 730 ]
i.e. 6.25% of an AVERAGE 5760-block window's fees measured over the trailing year.
So the fee-weight cast for the slot (Ftot) must be at least ~1/16 of a typical
window's total fees. Consensus should track year_fees as a running sum (like the
money supply), not recompute 262800 blocks each time.

## Activation (ANCHORED window; revised 2026-09-03)

The voting window is a FIXED sequence of VOTING_PERIOD blocks ANCHORED to a vote,
not a rolling window -- this is what gives the full-period delay (activation ~=
first_vote + VOTING_PERIOD + 720) without a sustained rule.

NOT sustained: a "must qualify in every window across the period" rule is cheaply
VETOABLE -- a miner gets a block's fees back, so it can inject a large self-paid
counter-fee-vote for free; under a sustained rule a single such block anywhere in
the period breaks the continuity and vetoes indefinitely. So qualification is a
SINGLE tally over the anchored window, backed by the 6.25% fee floor (participation)
and the 75%-of-stake requirement (real locked coins, not free). (The fee side is
inherently miner-gameable via free fees; the stake side is the real Sybil protection.)

Definitions (slot S):
- An ANCHORED WINDOW is a sequence [f, f + VOTING_PERIOD - 1] whose FIRST block f
  carries a vote for slot S and some branch b.
- b WINS the window iff, tallying vote outputs confirmed in the window:
    F(b) >= 0.75*Ftot  AND  K(b) >= 0.75*Ktot  AND  Ftot > 0  AND  Ktot > 0  AND
    Ftot >= fee_floor  (fee_floor computed from the year ending at f-1).
- The active algo for slot S = the branch b of the LATEST anchored window (largest
  f, searched over the last MAX_PUSHCODE_DEPTH blocks) that b wins AND whose first
  block f carries a vote for b. Its ACTIVATION BLOCK (the first height b is used as
  slot S's dynamic algo) is:
    activation = (f + VOTING_PERIOD - 1) + ACTIVATION_DELAY + 1
  i.e. the window's last block + 720 + 1.
- ACTIVATION_DELAY = 720 blocks after the window, during which VOTES DO NOT MATTER
  (a reorg buffer and lead time for nodes/miners to prepare). A later anchored win
  (re-vote) supersedes the earlier active algo. If none, the slot keeps its current
  algo (primitive-only if never activated).
- Requiring block f to carry a vote for the winner b anchors the window to where b's
  voting is actually happening (it cannot be positioned over unrelated blocks), and
  makes activation land a full period + delay after voting begins.
- At activation, H must ASSEMBLE (getpushcode == complete) and pass the resource
  limits; else the activation is void and the slot keeps its previous algo. [OPEN:
  treat a non-assemblable/over-limit winner as "did not qualify".]

## Reorg / determinism

The active algo is a pure function of the confirmed chain, so a reorg recomputes
it. The 720-block delay makes shallow reorgs harmless. A reorg deeper than the
window + 720 could retroactively change a slot's active algo; bounded by the base
PoW, same class as any deep-reorg risk. A consensus implementation must track
incrementally (per-slot: running window tallies as f advances, and year_fees as a
running sum) rather than the O(votes * window) rescans the informational RPC does.

## Informational RPC (non-consensus, first deliverable)

    getalgovote <slot> ( height )
Search the last MAX_PUSHCODE_DEPTH blocks (as of `height`, default tip) for the
latest anchored winning window and return:
    {
      "slot": n,
      "search": { "from": lo, "to": E },
      "window": { "from": f, "to": f+VOTING_PERIOD-1 } | null,  // reported window
      "fee_total": <units>, "stake_total": <amount>,
      "fee_floor": <units>, "fee_floor_met": bool,
      "candidates": [ { "branch","fee_weight","fee_pct","stake_weight","stake_pct",
                        "assemblable" } ... ],           // for the reported window
      "winner": "<hash>" | null,                          // latest anchored win
      "activation_block": (f+VOTING_PERIOD-1) + 720 + 1 | null
    }
The reported window is the winning one, else the latest vote-anchored complete
window (for diagnostics). Needs spent-input values for fees (reads CBlockUndo);
recognizes the FEE_VOTE / STAKE_VOTE templates via Solver; pure read-only, so it
prototypes the rules on testnet before any of this is consensus. Cost: it scans up
to MAX_PUSHCODE_DEPTH blocks -- fine on a short testnet, but consensus must track
incrementally. A later `getalgoslots` can summarize all 8 slots.

## Dynamic-algo I/O contract (summary; full spec in the execution doc)

Recorded here for design continuity; enforcement lives in dynamic-algo-mining.md.
A dynamic algo is a deterministic function evaluated by every validating node:

  inputs:
    1. the n previous blocks FOR THIS SLOT (n = replay/history depth, below)
    2. the current block's NON-COINBASE transactions
    3. the payout scriptPubKey (the dynamic miner's r/2 payee)
    4. the hash of the immediately-previous block on the CHAIN (any slot) -- the
       fresh, hard-to-grind half of the seed (a miner cannot influence it without
       redoing that block's PoW)
    5. the current block's nBits -- the difficulty/threshold the algo compares
       against (for the LLM case, mapped to the max-loss bound)
  output:
    a single integer return value; 0 == success (the solution meets the current
    per-slot difficulty), non-zero == failure -> the block's dynamic solution is
    invalid.

Build order / no circularity: the solution depends on the non-coinbase txs (not
the coinbase); the coinbase commits to the solution and payout; the merkle root
covers both. So: fix non-coinbase txs -> dynamic miner solves -> embed solution +
payout in coinbase -> merkle root -> primitive miner grinds the base PoW. The
solution therefore also BINDS the tx set (a primitive miner cannot swap txs after
solving). Input (3) is how the algo consumes the Hash256(payout || prev_hash)
seed, making the solution non-transferable. The seed is
Hash256(payout_scriptPubKey || input4), i.e. bound to both the payout (input 3)
and the immediately-previous chain block hash (input 4).

Difficulty as a loss bound (LLM case): "success" means the provided LoRA delta
drives validation loss below the current MAX-LOSS threshold, which IS the per-slot
difficulty (the mPoW nBits analogue, retargeted). So the existing per-slot
difficulty retarget carries over, reinterpreting the target as a loss bound rather
than a hash bound. The validation set is selected from the seed
Hash256(payout || input4); that selection must be grinding-resistant since the
miner controls the payout half of the seed (input 4 is not grindable without
redoing the previous block's PoW).

History depth n (DECIDED 2026-08-24): n = the number of the slot's blocks that lie
within the last MAX_PUSHCODE_LENGTH chain blocks (i.e. within the pruned-node keep
window). This needs NO delta checkpoints: every delta required to reconstruct the
current model is exactly the set the prune lock already guarantees on disk, so
cold reconstruction always succeeds. Consequences:
  - The model is a SLIDING WINDOW: model = base_weights + sum(deltas in the last
    MAX_PUSHCODE_LENGTH blocks). Deltas older than ~2 years drop off ("forgetting").
    This is a modeling choice, not a consensus issue, and is self-healing: a
    dropped delta that still mattered pushes loss back above threshold, so miners
    must re-learn it to keep mining.
  - n is deterministic per chain (same slot-block set for every node) and varies
    block to block; in steady state n ~= MAX_PUSHCODE_LENGTH / 8 ~= 65700 slot
    blocks, far above the DGW window (see below).
  - Cost: applying r=4 int8 LoRA deltas is cheap vs. the single validation forward
    pass, but ~65700 applies is a real one-time COLD-START cost. Steady state uses
    the resident weight state (~2 GB/instance) and applies only the new delta; a
    cold node (fresh sync / deep reorg within the window) replays from base once.

Difficulty is PASSED DIRECTLY as input 5 (nBits), NOT rederived (decided
2026-08-29): Bitmark retargets each slot with Dark Gravity Wave over the last ~25
slot blocks AND a "resurrector" that uses the timestamp of the LAST chain block
(any slot, the most recent time reference) to measure how long the slot has been
dormant and drop difficulty accordingly. Rederiving nBits inside the algo would
force every dynamic algo to re-implement that cross-slot resurrector timing in
untrusted wasm -- duplicated consensus difficulty logic with divergence risk. So
the node passes the block's already-computed nBits directly; the algo maps it to
its threshold (for LLM, nBits -> max-loss bound by a fixed monotonic function).
This is safe from grinding: nBits is consensus-validated for the block
independently (a wrong nBits makes the block invalid), so the algo can trust it.
(This supersedes the earlier "derive via DGW" note and closes the difficulty gap.)

Per-slot prune floor (sluggish slots): n = slot-blocks-in-MAX_PUSHCODE_LENGTH can
be very small if a slot is barely mined. So keep, per slot, at least the last
90*365 = 32850 slot-blocks (90 blocks/day/slot * 365 = ~1 year per slot). This
guarantees a minimum of on-disk slot history for the algo's replay input (input 1),
even for a sluggish slot -- a sensible ~1-year floor. (The DGW-window justification
is now moot since nBits is passed directly as input 5, not rederived; and the
365-day subsidy peak-hashrate uses the block INDEX, not on-disk data, so it does
not itself drive this keep -- the on-disk keep exists for the algo's model-history
replay.) Composition: overall prune floor = min(tip - MAX_PUSHCODE_LENGTH,
min over slots of each slot's 32850th-newest-block height). Cost: a genuinely
sluggish slot pulls the floor far down (keeps a long chain span) -- bounded by
actual block production, rare, accepted. n for the model = the slot blocks from
this floor to tip (so n >= 32850 always).
  IMPLEMENTED (2026-08-26): MIN_SLOT_BLOCKS_ON_DISK = 90*365 in pushcodedb.h;
  FlushStateToDisk folds it into the existing "pushcode" prune lock -- one
  backward pass from the tip counts each mPoW slot's own blocks (pindex->GetAlgo,
  NUM_ALGOS=8) and lowers keep_from to the height where every slot has reached the
  target (or the earliest fork block, for slots short of it). Normally
  MAX_PUSHCODE_LENGTH dominates; this only extends the window for a sluggish slot.
  Cost: the pass is bounded by chain length in the pathological all-sluggish case;
  a cache/incremental refresh is a possible later optimization.

Base weights & algo code -- RE-PUSH THE WINNER ON-CHAIN (preferred): base_weights
and the algo code live in the pushcode BRANCH (pushed once at activation), which
ages out of the keep window after MAX_PUSHCODE_LENGTH blocks and would become
unassemblable. Fix: when an algo wins, RE-COMMIT it via a fresh set of PUSHCODE
transactions, keeping a recent on-chain copy inside the rolling keep window. This
is consensus-clean -- any node, including one that pruned and re-synced later, can
re-assemble the algo from chain (unlike caching assembled bytes locally, which only
helps nodes online at activation). Because entries dedup by content hash, re-push
does not change PushCodeHash; but the code DB currently keeps canonical code_pos =
lowest height (the old, possibly-pruned copy), so assembly must be changed to
prefer a recent, ON-DISK copy of a hash when one exists. (Optional: nodes may also
cache the assembled module locally for execution speed -- an optimization, not the
availability guarantee.)

Dataset commitment (LLM): the training/validation dataset MUST be committed or
"loss below threshold" is meaningless (a miner could evaluate on a fake/favorable
set). The dataset is committed as a MERKLE ROOT in the algo's PUSHCODE definition
(the branch); the algo MAY permit appending new dataset commitments during training
(extending the branch under the algo's own rules).

Data availability solved by inline MERKLE BRANCH PROOFS (no off-chain fetch): the
verifier never needs the whole dataset, only the seed-selected validation subset.
The seed (Hash256(payout || input4)) picks which examples (indices); the dynamic
miner carries, IN the block solution, each selected example plus its merkle branch
proof against the committed root. Verification uses only on-hand data: the committed
root (on-chain, in the algo def), the seed (derivable), and the examples+proofs (in
the solution). It checks each proof against the root (example is genuinely in the
committed set, unmodified), then evaluates loss on exactly those examples. The party
claiming the solution supplies the evidence, so there is no "data unavailable" case.
This is also why the seed must be grinding-resistant (a fixed favorable subset must
not be choosable). Cost: the solution carries k examples + k proofs (~log2(N)*32
bytes each), bounded by the per-block validation-set size -- a size/security knob,
not an availability risk.

Open gaps to close in the execution doc:
  - Define the nBits -> max-loss threshold mapping (monotonic; and the bootstrap
    initial difficulty for the first < 25 slot blocks).
  - code_pos canonical selection change: prefer a recent, on-disk copy of a
    re-pushed algo hash (so re-push keeps it assemblable).
  - Per-block validation-set size k (the size/security knob for the inline
    example+proof payload).
  (RESOLVED: seed prev-hash = input 4 (immediately-previous chain block hash);
   n = slot blocks kept on disk, >= 32850 via the per-slot prune floor (no delta
   checkpoints); difficulty derived from input 1 via DGW; algo code kept available
   by re-pushing the winner on-chain; dataset committed as a merkle root in the
   algo definition; data availability solved by inline merkle branch proofs.)

## Execution runtime & ABI (decided/prototyped 2026-08-29)

Runtime: wasm3 (pure C, no Rust dependency -- matches bitmarkd's C/C++ build),
chosen over wasmtime specifically to avoid a Rust toolchain in the consensus
build. Determinism is fine: dynamic algos are integer-only (the reference
Whirlpool algo is), so no float-nondeterminism concerns. A prototype C host
(wasm3: m3_ParseModule/LoadModule/FindFunction/Call) has been validated to run
the reference module and produce results BIT-IDENTICAL to native, confirming the
runtime + ABI end to end. (WAMR is the likely upgrade later for AOT speed / richer
sandboxing; the ABI and gas approach are runtime-independent, so swapping is a
non-consensus change.)

Host <-> module ABI (as prototyped): the algo is a wasm module exporting `verify`
plus its linear `memory` and `__heap_base`. Pointer inputs are BYTE OFFSETS into
the module's exported linear memory: the host writes each input array into memory
starting at __heap_base (free space above the module's static data + stack), then
calls verify passing those offsets plus lengths/nBits as i32 values, and reads the
i32 return (0 = success). Reference signature (input order fixed 2026-08-29):
  verify(prev_hash, payout, payout_len, nbits, txs, txs_len,
         last_n_blocks, last_n_len, nonce, nonce_len) -> i32
For the Whirlpool reference algo: preimage = prev_hash || payout || nonce; target =
nBits decoded as the Bitcoin compact form; success iff the TOP 256 bits of the
512-bit Whirlpool digest <= target. (txs / last_n_blocks are accepted but unused by
this hash algo.)

Resource limits:
- Memory: a cap on linear-memory pages, enforced by the runtime at instantiation
  (wasm3 supports this directly) -- simple, no instrumentation.
- CPU: GAS METERING BY BYTECODE INSTRUMENTATION, replacing wasmtime's built-in
  fuel (which we lose by not using wasmtime). The module is rewritten before
  execution to decrement an in-module gas counter at each basic block against a
  fixed consensus cost table and trap at zero, so the count is identical on every
  node regardless of runtime -- arguably more consensus-safe than trusting an
  engine's internal fuel. Likely applied at ALGO ACTIVATION (instrument the
  materialized winning module once), so the pushed module stays clean and the
  transform is consensus-controlled, not author-controlled.
  STILL UNCLEAR / SUBJECT TO CHANGE: the exact mechanism is not settled -- the cost
  table, where/when instrumentation runs (activation vs. required in the pushed
  module), how a no-Rust C toolchain performs the transform, and whether a
  different bound is used instead. Treat this as a design sketch, not a final rule.

## Cross-refs (not in this note)

- Reward split & enforcement (dynamic-algo-mining.md): base PoW (old nodes) + a
  committed dynamic solution (new nodes); per-slot mapping (mining primitive slot
  k needs slot k's solution); reward r -> {self r, buy r/2 + r/2, skip r/4}.
  The un-emitted 3r/4 on a solution-less block is NOT burned: Bitmark's per-algo
  emission halves/quarters at cumulative-emission MILESTONES (not block height), so
  coins not emitted simply stay in the budget and are emitted by later blocks --
  emission stretches in time, the supply cap is preserved, and the reward rolls
  forward to future solution-providing miners. Solution seeded by
  Hash256(payout_scriptPubKey || prev_block_hash) to bind it to the dynamic
  miner's payout (non-transferable); coinbase must pay that scriptPubKey r/2.
- Resource limits & determinism (execution): see "Execution runtime & ABI" above
  -- CPU via gas-by-instrumentation (NOT wasmtime fuel, since the runtime is now
  wasm3), memory via a linear-memory page cap; validation-set selection must be
  grinding-resistant since the miner controls part of the seed (the payout
  scriptPubKey).

## Open items to confirm

- Stake-output template exact opcodes (bare CSV+payout as above?) and making it
  relay-standard.
- Fee source for the RPC: read block undo data vs. require -txindex.
- "Void winner" handling when the winning branch is not assemblable / over-limit
  (proposed: treat as no winner for that window).
- Whether a vote may target a slot that is currently primitive vs. already dynamic
  (both allowed; re-voting supersedes).
