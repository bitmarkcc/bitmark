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

Mirror the PUSHCODE pattern. A vote is an unspendable OP_RETURN output:

    OP_RETURN OP_VOTE <branch_hash:32> <slot:1..>

- OP_VOTE = a NOP opcode used as the 2-byte magic (OP_RETURN OP_VOTE), so the
  Solver classifies it as TxoutType::VOTE and it is never confused with nulldata.
- branch_hash = the content hash (PushCodeHash) of the algo branch tip being
  voted for. Need not be assemblable/complete yet (it becomes relevant only if it
  wins and, at activation, must assemble + pass resource limits).
- slot = the target mPoW slot (small int).
- Exactly ONE OP_VOTE output per tx (a tx with 0 or >1 is not a vote). Coinbase
  txs cannot vote (no real inputs / negative fee).

## Vote weights

A voting tx contributes to TWO independent tallies for its (slot, branch_hash):

### Fee weight (the "user"/fee-payer constituency)
    fee_weight(tx) = tx_fee / num_outputs
tx_fee = sum(input values) - sum(output values). Divided by the number of outputs
so a coinjoin's shared fee is not over-credited to one embedded vote; a dedicated
voter uses a minimal-output tx (vote + change => fee/2). Computing this needs the
spent-input values (block undo data / txindex).

### Stake weight (the "investor"/stake constituency)
    stake_weight(tx) = sum of the tx's STAKE OUTPUTS
A STAKE OUTPUT is an output whose scriptPubKey is the self-describing template

    <lock:CScriptNum> OP_CHECKSEQUENCEVERIFY OP_DROP <payout scriptPubKey>

with a RELATIVE timelock lock >= VOTING_PERIOD (5760). The CSV must be visible in
the scriptPubKey (NOT hidden behind P2SH/P2WSH) so the tally reads the lock at
creation time without waiting for the spend. This template is made relay-standard
(as PUSHCODE was). The coins are thereby locked >= VOTING_PERIOD blocks from
confirmation, so they cannot re-vote within any window that includes this vote,
and locking imposes a real opportunity cost (Sybil resistance for stake).

CSV ACTIVATION (2026-08-27): CSV (BIP68/112/113) is NOT active on Bitmark
mainnet/testnet as shipped (CSVHeight = INT_MAX) -- OP_CHECKSEQUENCEVERIFY would be
a no-op and the coins would not actually lock. So CSV is ACTIVATED as part of THIS
dynamic-algo soft fork, gated on the SAME miner-signalled base-version-5
supermajority that already enables OP_PUSHCODE (no hardcoded height). Wiring: OR
the pushcode-supermajority condition into the SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
(BIP112) gate in GetBlockScriptFlags, and into the BIP68 sequence-lock / BIP113 MTP
gates. CLTV (BIP65) is already active and was the fallback if CSV were not bundled
(absolute L with the tally checking L - B >= VOTING_PERIOD); CSV is preferred as it
makes the relative lock automatic from confirmation. Since CSV shares the PUSHCODE
gate, it becomes active at the same height PUSHCODE did.

Only outputs in a tx that ALSO carries an OP_VOTE, and that match the stake
template, count as stake.

## Window, denominators, thresholds

- VOTING_PERIOD = 720 * 8 = 5760 blocks (~8 days at 720 blocks/day). Sliding
  window: it may start at any height.
- Tally for a window ending at height E and slot S: over all voting txs confirmed
  in [E - 5759, E] targeting slot S,
    F(H)  = sum of fee_weight   of votes for branch H
    K(H)  = sum of stake_weight of votes for branch H
    Ftot  = sum over all H of F(H)      (total fee-weight cast for slot S)
    Ktot  = sum over all H of K(H)      (total stake cast for slot S)
- Supermajority: branch H wins the window iff
    F(H) >= 0.75 * Ftot   AND   K(H) >= 0.75 * Ktot
  Because 2 * 0.75 > 1, at most one H can hold >=75% of Ftot (and of Ktot), so the
  winner is unique; if no H clears BOTH, there is no winner for this window.
  (Denominators are "of votes cast for the slot", not of the whole fee/coin base.)

## Activation

- ACTIVATION_DELAY = 720 blocks.
- Define win(E, S) = the branch H that wins the window ending at E for slot S, or
  none.
- The active algo for slot S at height h:
    active(S, h) = win(E*, S), where E* is the greatest height <= h - ACTIVATION_DELAY
                   with win(E*, S) != none; if no such E*, slot S is primitive-only.
  i.e. the most-recent supermajority at least 720 blocks in the past takes effect;
  a later supermajority (re-vote) supersedes an earlier one. The delay is a buffer
  so a short reorg cannot retroactively change the algo a just-mined block used.
- At the moment a slot first activates (or re-activates to) branch H, H must
  ASSEMBLE (getpushcode == complete) and pass the resource limits (fuel / memory
  pages -- see execution doc). If it does not, the activation is void and the slot
  keeps its previous algo (or stays primitive-only). [OPEN: exact "void" semantics
  -- treat a non-assemblable/over-limit winner as "no winner" for that window.]

## Reorg / determinism

active(S, h) is a pure function of the confirmed chain up to h, so a reorg simply
recomputes it. The 720-block delay makes shallow reorgs harmless. A reorg deeper
than 720 could change a slot's active algo retroactively and invalidate affected
blocks' dynamic solutions; this is bounded by the base PoW securing the chain and
is the same class of risk as any deep-reorg consensus change. Implementations
should compute active(S, h) incrementally (track per-slot current winner) rather
than rescanning 5760 blocks each block.

## Informational RPC (non-consensus, first deliverable)

    getalgovote <slot> ( height )
Tally the window ending at `height` (default: tip) for `slot` and return:
    {
      "slot": n,
      "window": { "from": h1, "to": h2 },
      "fee_total": <fee-weight units>,
      "stake_total": <amount>,
      "candidates": [
        { "branch": "<hash>", "fee_weight": x, "fee_pct": p,
          "stake_weight": y, "stake_pct": q, "assemblable": bool } ...
      ],
      "winner": "<hash>" | null,           // clears both 75% thresholds
      "active": "<hash>" | null,           // active(slot, height) incl. 720 delay
      "would_activate_at": h | null
    }
Implementation notes: needs spent-input values for fees (read CBlockUndo, or
require -txindex); recognizes the OP_VOTE and stake-output templates; pure
read-only, so it can prototype the rules on testnet before any of this is
consensus. A later `listalgovotes`/`getalgoslots` can summarize all 8 slots.

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
    (also required, see gaps: the current block header / difficulty target, so
     the algo has the threshold to compare against)
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

Difficulty is DERIVED, not a separate input: Bitmark retargets each slot with Dark
Gravity Wave over the last ~25 slot blocks. Since input (1) contains n slot blocks
with n >= 25 in steady state, the algo recomputes the current block's nBits itself
via the same DGW formula, then maps nBits -> max-loss threshold by a fixed
monotonic function (harder difficulty -> tighter loss bound). The retarget dynamics
are unchanged; only the target->loss mapping is new. Bootstrap: for the first < 25
slot blocks after activation, use an initial difficulty. (This closes the earlier
"difficulty must be a separate input" gap -- it is derivable from input 1.)

Per-slot prune floor (sluggish slots): n = slot-blocks-in-MAX_PUSHCODE_LENGTH can
fall below the DGW window (25) if a slot is barely mined. So keep, per slot, at
least the last 90*365 = 32850 slot-blocks (90 blocks/day/slot * 365 = ~1 year per
slot). This guarantees (a) n >= 32850 >> 25 so DGW always has its window whatever
the slot speed, and (b) the 365-day peak-hashrate history the subsidy-scaling
factor needs. Composition: overall prune floor = min(tip - MAX_PUSHCODE_LENGTH,
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
- Resource limits & determinism (execution): fuel (deterministic instruction
  count) and max linear-memory pages, enforced per execution; validation-set
  selection must be grinding-resistant since the miner controls part of the seed
  (the payout scriptPubKey).

## Open items to confirm

- Stake-output template exact opcodes (bare CSV+payout as above?) and making it
  relay-standard.
- Fee source for the RPC: read block undo data vs. require -txindex.
- "Void winner" handling when the winning branch is not assemblable / over-limit
  (proposed: treat as no winner for that window).
- Whether a vote may target a slot that is currently primitive vs. already dynamic
  (both allowed; re-voting supersedes).
