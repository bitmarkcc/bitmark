# Porting OP_PUSHCODE from dev2024 to 27.xb

Plan written 2026-07-19 (Claude-Fable session; companion to llm.c's
doc/btm-proof-of-useful-work.md). dev2024 is the old 0.9.x-lineage codebase;
27.xb is the from-scratch rewrite on Bitcoin Core 27.x. This is a manual port,
not a merge: ~2,000 insertions across 23 files on dev2024, re-homed into the
modern source layout.

## Opcode relocation: DECIDED (2026-07-19)

dev2024 used OP_PUSHCODE = 0xb2 (= OP_NOP3), which was free in the 0.9.x
lineage but is consumed by BIP112 OP_CHECKSEQUENCEVERIFY in Core 27.x.
**OP_PUSHCODE = OP_NOP4 = 0xb3** on 27.xb (user-confirmed; no test network
ever mined 0xb2-PUSHCODE blocks, so nothing is orphaned). dev2024-era test
vectors/scripts encode the old byte and must be regenerated during the port.

## File mapping (dev2024 -> 27.xb)

| dev2024 | What it does | 27.xb home |
|---|---|---|
| script.h opcode enum | OP_PUSHCODE def | `src/script/script.h` (OP_NOP4 slot) |
| script.h/cpp `TX_PUSHCODE`, mTemplates, OP_PC_PARAMS | output classification + template matching | `src/script/solver.{h,cpp}` (TxoutType enum + Solver()); param extraction helpers likely a new `src/script/pushcode.{h,cpp}` |
| script.cpp EvalScript OP_NOP3 case | execution semantics under SCRIPT_VERIFY_PUSHCODE | `src/script/interpreter.cpp` (the CSV/NOP dispatch block) + flag in `src/script/interpreter.h`; new SCRIPT_ERR_* in `script_error.{h,cpp}` |
| main.cpp fork activation (height check) | consensus activation | **DECIDED (2026-07-19): miner-signaled supermajority, no hardcoded heights.** Bump the base block version; PUSHCODE rules activate for a block when >= 750 of the previous 1000 blocks have base version >= N (optional second threshold 950/1000 to reject old-version blocks). Core 27.x REMOVED IsSuperMajority() (~0.14), so reintroduce it in `validation.cpp` (walk pindex->pprev counting qualifying versions; consult from GetBlockScriptFlags), thresholds in `consensus/params.h` + chainparams (750/1000 main, small e.g. 51/100 regtest for functional tests). **CAUTION: Bitmark's nVersion carries mPoW algo bits** -- the comparison must mask to the base version per 27.xb's header encoding (check pureheader/CBlockHeader before writing it), or blocks would be counted differently per mining algo |
| main.cpp/h MAX_CODE_RELAY, standardness | relay policy | `src/policy/policy.{h,cpp}` (IsStandard / TxoutType acceptance), `MAX_CODE_RELAY` beside MAX_OP_RETURN_RELAY (note 27.xb already customized that -- see commit c8566ff) |
| main.cpp code assembly/processing (multi-output, part replacement) | reconstructing pushed code from tx outputs | `src/validation.cpp` (block connect path) or better: a dedicated `src/index/codeindex.{h,cpp}` modeled on `src/index/txindex` -- keeps consensus untouched until execution activates |
| txdb.{h,cpp} code storage | persisting assembled code blobs | the codeindex above (own LevelDB, BaseIndex framework) rather than hacking txdb -- cleaner reorg handling for free |
| core.h CGOutPoint<BITS> generalized outpoint, valtype | referencing code parts by hash | `src/primitives/` addition or fold into pushcode.h; re-express with modern serialize.h (IMPLEMENT_SERIALIZE is gone; use SERIALIZE_METHODS) |
| rpcrawtransaction.cpp (397 lines) | createrawtransaction pushcode outputs, decoding | `src/rpc/rawtransaction.cpp` + `src/rpc/rawtransaction_util.cpp`; arg tables in `src/rpc/client.cpp` |
| rpcmisc.cpp | query pushcode state | `src/rpc/node.cpp` or new `src/rpc/pushcode.cpp` |
| wallet.{h,cpp} (172 lines) | wallet-built pushcode txs | `src/wallet/` is heavily refactored; DEFER -- raw-transaction RPC path first, wallet sugar later |
| test/transaction_tests.cpp, fork_tests/pushcode.sh | tests | unit: `src/test/script_tests.cpp` & `transaction_tests.cpp`; the shell fork test becomes a **functional test** `test/functional/feature_pushcode.py` (the framework 27.xb inherits is far better suited to activation tests than the old shell scripts) |

## Design change: content-hash references (decided 2026-07-19)

PUSHCODE entries reference other entries by a single 32-byte CONTENT HASH
(Hash()/double-SHA256 of the raw referenced scriptPubKey bytes), NOT by
(txid, nOutput) outpoint as in dev2024. Rationale: unifies with the
content-addressed architecture used throughout the llm.c side (weight deltas,
dataset commitments, DA layer); gives acyclicity for free (a child's hash
depends on its parent's, so reference cycles need an infeasible hash-preimage
cycle -- no explicit "reference earlier only" rule needed); natural dedup and
location independence; 32 vs 36 bytes.

Costs, all landing on the phase-3 codeindex (DA-flavored bookkeeping):
- canonical selection among byte-identical entries (rule: lowest height, then
  tx position);
- availability refcounting: a reference is valid iff some confirmed entry with
  that content hash exists; reorg that drops the last copy invalidates it;
- dangling references: content may be referenced before publication; valid
  only once confirmed.

OPEN QUESTION to confirm: authorization model. Outpoints let UTXO ownership
gate "replace/modify this code branch." Content-hash refs decouple identity
from any spendable output, so if governance leaned on UTXO control it needs a
separate mechanism. If the model is "anyone proposes, PoW-voting decides"
(the intended dynamic-algo spirit), authority never came from the outpoint and
nothing is lost.

Phase-1 impact: none (script recognition is param-semantics-agnostic; the
reference layout only matters in phase 3).

## Phase 1 COMPLETE (2026-07-19): script layer

- `script/script.h`: OP_PUSHCODE = OP_NOP4 = 0xb3 (alias).
- `script/interpreter.h`: SCRIPT_VERIFY_PUSHCODE = (1U << 21).
- `script/interpreter.cpp`: OP_PUSHCODE pulled out of the upgradable-NOP
  group into its own case -- no-op when the verify flag is set (meaning lives
  in the phase-3 assembly path, not in EvalScript), else falls through to
  DISCOURAGE_UPGRADABLE_NOPS.
- `script/solver.{h,cpp}`: TxoutType::PUSHCODE + MatchPushCode() (modern
  hand-written matcher replacing the old OP_PC_PARAMS mTemplates): 1..5 push
  params then OP_PUSHCODE and nothing else; data pushes -> bytes, OP_0/OP_1..16
  -> 1 byte 0..16 (matches dev2024 decode). No OP_PC_PARAMS pseudo-opcode
  needed. MAX_PUSHCODE_PARAMS = 5 (was 6 in dev2024): the maximal form is
  <pushtype> <codehash 32B> <nPart> <nPart2> <code>. dev2024's maximal form
  (main.cpp:2488-2498) was <pushtype> <txid> <nOutput> <nPart> <nPart2> <code>;
  replacing the (txid,nOutput) outpoint reference with a single content hash
  drops one slot. Phase-3 will also repurpose PUSHTYPE_TX (now "codehash
  reference present" rather than "txid specified").
- Exhaustive TxoutType switches updated (build breaks otherwise): addresstype,
  script/sign, wallet/scriptpubkeyman, wallet/rpc/backup, rpc/rawtransaction
  (x2) -- PUSHCODE grouped with NULL_DATA/nonstandard (no address, not
  wrapped). policy.cpp uses if/else -> falls through to nonstandard (relay
  standardness is phase 2).
- Test: script_standard_tests extended (match with data+32B-ref+smallint,
  6-param max, 7-param reject, no-param reject, trailing-opcode reject);
  full build green, suite passes.

## Phase 2 COMPLETE (2026-07-21): consensus activation + relay policy

- `primitives/pureheader.h`: CURRENT_VERSION 4 -> 5 (new blocks signal PUSHCODE
  readiness). Base version is the low 8 bits.
- `consensus/params.h`: nPushCodeVersion / nPushCodeActivationThreshold /
  nPushCodeActivationWindow. Set in ALL FOUR network classes in
  kernel/chainparams.cpp (main/testnet/signet 5/750/1000; regtest 5/75/100 so
  functional tests cross the boundary fast).
- `validation.cpp` GetBlockScriptFlags: sets SCRIPT_VERIFY_PUSHCODE when
  block_index.pprev->IsSuperMajority(5, threshold, window). Window ends at the
  parent so a block cannot self-activate. NO hardcoded height.
- KEY FINDING: the masked supermajority machinery already exists in 27.xb
  (Bitmark kept CBlockIndex::IsSuperMajority + GetBlockVersion = nVersion & 255
  for its multi-PoW fork), so no reintroduction was needed -- the plan's
  masking caution is handled by the existing GetBlockVersion mask. BIP9
  versionbits is unusable here precisely because nVersion's upper bits carry
  algo/auxpow/variant/chainid.
- `policy/policy.{h,cpp}`: MAX_CODE_RELAY = 256 (relay-only, tunable, subject to
  change); IsStandard caps a PUSHCODE output's code chunk (last push param).
- Test: `src/test/pushcode_tests.cpp` (unit) -- threshold boundary (74 vs 75 of
  100) and, critically, that algo/auxpow/variant/chainid bits do NOT perturb the
  count (a version-4 block with algo bits, raw nVersion 516, must not count as
  >=5; genuine version-5 blocks with mixed algo bits still count). Registered in
  Makefile.test.include.
- Note: phase 2 activation has NO observable consensus effect yet -- OP_PUSHCODE
  is a NOP in the interpreter until phase 3 adds real validation gated on the
  flag. So the "accepted-before / rejected-after" FUNCTIONAL test belongs in
  phase 3; the phase-2 unit test targets the mechanism (masking + threshold).
- DEPLOYMENT CAUTION: because the CURRENT_VERSION bump makes mainnet start
  signalling immediately, do not let mainnet reach the activation threshold
  before phase 3 (real validation) has shipped -- ship the full rule set with,
  or before, activation. Fine on the dev branch.
- TEST-VECTOR FALLOUT of the version bump (expected; Bitcoin Core does the same
  for BIP34/65/66): CURRENT_VERSION 4->5 changes every regtest block header, so
  every hardcoded regtest BLOCK HASH had to be regenerated:
    * TestChain100Setup tip hash (test/util/setup_common.cpp) -> cf9e4abe...
    * regtest m_assumeutxo_data[].blockhash (kernel/chainparams.cpp): height 730
      -> 303714dc..., height 299 -> a11ee63f... (.hash_serialized and .nChainTx
      unchanged -- the UTXO SET is version-independent, only the block hash moves)
  Mainnet/testnet/signet assumeutxo + checkpoints are NOT affected (they
  reference real historical blocks, not version-bumped test chains). Symptom if
  missed: a SIGABRT in a fixture (stale hash assert or failed snapshot load)
  cascades into a flood of unrelated "AddArg:576 ret.second" aborts, because a
  SIGABRT mid-test leaves the global ArgsManager populated and the next
  fixture's SetupServerArgs re-registers duplicates. The flood is an artifact;
  find the FIRST real SIGABRT. Full suite green after the regen.

## Phase 3 DESIGN (2026-07-22): content-hash code model + assembly

### What dev2024 did (and why we change it)

dev2024 stores code as a MUTABLE doubly-linked list of "parts" spliced across
five LevelDB indexes (CodeHeight/CodeSize/CodePos/CodeNext/CodePrev), each part
identified by a (txid,nOutput) outpoint (COutPointPair = (part_outpoint,
branch_outpoint)). A branch is a sequence of parts; the assembled code is their
concatenation. Operations on a referenced branch:
  - NEW: start a branch with one part.
  - INSERT @ nPart: splice a new part before part index nPart.
  - REPLACE/DELETE [nPart, nPart2]: replace a range of parts (empty code = delete).
Reference to the branch/part being modified is the (txid,nOutput) outpoint.
Only the code POSITION (CDiskTxPos into the block file) is stored, not bytes.
Limits (main.h): MAX_PUSHCODE_DEPTH / _LENGTH = 33638400, _PART_DEPTH = 525600,
_SIZE = int64 max. Validation in ConnectBlock; a flood of bad-pushcode DoS
rejects. Reorg undo must reverse every splice -- the hard, error-prone part.

### The content-hash redesign (chosen; big simplification)

Because phase 1 made references 32-byte CONTENT HASHES (Hash() of the referenced
scriptPubKey), code entries become IMMUTABLE and content-addressed -- like git
commits. This replaces the 5 mutable spliced indexes with ONE append-only map
and makes reorg trivial.

Entry model: each PUSHCODE output is an immutable code entry
  E = (op, parent_hash, nPart, nPart2, code_chunk)
with identity  H = Hash(scriptPubKey)  (the whole output script, which embeds
parent_hash). Because H depends on parent_hash, the DAG is acyclic by
construction (a cycle needs a hash preimage cycle) -- no "reference earlier
only" rule needed.

Codeindex: a single map  H -> { parent_hash, op, nPart, nPart2, code_pos
(CDiskTxPos), height, refcount }. No linked list; no splicing.

Assembly of a branch tip H (pure function, no stored mutable state):
  walk parent_hash from H back to the NEW root, collecting entries; then replay
  ops root->tip to build the ordered part list (NEW seeds [p]; INSERT adds a
  part at nPart; REPLACE/DELETE rewrites [nPart,nPart2]); concatenate the
  parts' code chunks (fetched from code_pos in the block files). The materialized
  code of any entry is thus deterministic and recomputable from the DAG alone.

Reorg safety (the payoff): entries are immutable, so DisconnectBlock just deletes
the block's entries (and decrements refcount); there is NOTHING to un-splice.
Content dedup: if two outputs have byte-identical scriptPubKeys they share H;
refcount tracks how many confirmed outputs back H, so a reference is valid iff
refcount>0, and a reorg dropping the last one invalidates it. Canonical
selection among duplicates (for code_pos) = lowest height, then tx position.

Consensus validation in ConnectBlock (gated on SCRIPT_VERIFY_PUSHCODE /
DeploymentActiveAt), per PUSHCODE output:
  1. Grammar: parse {pushtype, [codehash 32B], [nPart], [nPart2], code_chunk}
     from Solver's vSolutions; the 1..5 param forms mirror dev2024 minus the
     (txid,nOutput)->codehash collapse. Range/consistency: pushtype>=0; INSERT
     forbids empty code and nPart2; REPLACE required when nPart2 present;
     indices >=0.
  2. Reference: NEW has no parent; otherwise parent_hash=codehash must resolve
     to a confirmed entry (refcount>0) in the codeindex.
  3. Limits: assembled part-count/length/total-size and DAG depth under the
     MAX_PUSHCODE_* caps (recompute cheaply by walking parents; cache lengths).
  4. On success, stage the new entry for the codeindex batch (written with the
     block).

### Staged implementation (each testable; full set required before mainnet activation)

- 3a: ConnectBlock param-grammar validation gated on activation (steps 1 above,
  no storage) -- makes the fork OBSERVABLE (malformed PUSHCODE rejected after
  activation, ignored before) and functional-testable. Reference resolution
  and assembly stubbed/deferred. [DONE 2026-07-22]
    * New module src/script/pushcode.{h,cpp}: CheckPushCodeGrammar(solutions,
      reason) + CheckPushCodeOutputs(tx, reason) -- pure functions returning a
      consensus reject-reason string (no BlockValidationState dep, so unit-
      testable; CTransaction forward-declared in the header, full include only
      in the .cpp). Registered in Makefile.am (libbitcoin_common +
      libbitcoinkernel + headers).
    * validation.cpp ConnectBlock tx loop: when (flags & SCRIPT_VERIFY_PUSHCODE),
      runs CheckPushCodeOutputs on every tx (coinbase included) and, on failure,
      state.Invalid(BLOCK_CONSENSUS, reason).
    * Numeric params (pushtype/nPart/nPart2) decoded as CScriptNum (<=4 bytes =>
      int32; NOT CompactSize -- no length prefix), fRequireMinimal=false since
      MatchPushCode emits OP_0 as {0x00}.
    * Unit tests in test/pushcode_tests.cpp (pushcode_grammar): valid 1..5-param
      forms incl. REPLACE-range and delete; rejects 0/6 params, empty NEW/INSERT
      code, non-32-byte ref hash, range-on-INSERT, nPart2<nPart, negative
      pushtype, oversized numeric param.
- 3b: code-entry consensus store. CORRECTION (2026-07-22): this is NOT a
  BaseIndex/src-index optional index -- those sync in the background and are
  unavailable during ConnectBlock. Reference resolution is CONSENSUS (a
  connecting block's PUSHCODE ref must resolve against already-confirmed
  entries), so the store must be updated SYNCHRONOUSLY in ConnectBlock and
  undone in DisconnectBlock, like the UTXO set / block-tree DB (this is what
  dev2024 did -- it put the code indexes in CBlockTreeDB/txdb and wrote them
  from ConnectBlock). Design: a LevelDB (extend CBlockTreeDB, or a dedicated
  CCodeDB) with map H -> { parent_hash, op, nPart, nPart2, height, refcount,
  code_bytes }. Writes staged in ConnectBlock via the block's write batch;
  DisconnectBlock deletes the block's entries and decrements refcounts.
  Content-hash immutability keeps disconnect trivial (delete, no un-splice).
  Storage decision (2026-07-22): store code_pos (CDiskTxPos into the block
  file), as dev2024 did -- NOT the code bytes. Tiny index; assembly seeks into
  block files to fetch each chunk (so assembly requires the block files -- not
  available under pruning; acceptable, matching dev2024). Authorization model:
  anyone-proposes / PoW-decides (phase-1 assumption; no per-entry spend auth).
  So codeindex map: H -> { parent_hash, op, nPart, nPart2, height, refcount,
  code_pos (CDiskTxPos) }.
    * MODULE DONE (2026-07-22): src/pushcodedb.{h,cpp} (registered in
      Makefile.am kernel+node libs). CCodeEntry (serialized), PushCodeHash =
      Hash() of the output scriptPubKey (content identity), and CCodeDB
      (CDBWrapper): ReadEntry/HaveEntry/AddEntry(refcount-bumping on dedup)/
      RemoveEntry(refcount-decrement then erase)/Read+WriteBestBlock. Best-block
      marker is written in the same batch as each entry change so the store can
      be reconciled with the active chain on startup. Note: content-hash refs
      mean resolution is a code-DB lookup, NOT GetTransaction -- so, unlike
      dev2024, PUSHCODE validation does NOT require -txindex. Unit tests:
      test/pushcodedb_tests.cpp (content hash determinism/sensitivity; entry
      round-trip; dedup refcount up/down; best-block tracking).
    * INFRASTRUCTURE DONE (2026-07-22, compilable checkpoint):
      - CCodeDB owned by BlockManager (m_code_db, blockstorage.h) and opened at
        startup next to m_block_tree_db (node/chainstate.cpp, path blocks/code,
        shares reindex/in-memory options). Available during ConnectBlock.
      - script/pushcode.{h,cpp}: added PushCodeParams + ParsePushCode() which
        validates grammar AND extracts {op, has_parent, parent_hash, has_part,
        nPart, has_part2, nPart2}; CheckPushCodeGrammar now wraps it.
      - CCodeEntry gained a `vout` field: code_pos is the containing tx's
        CDiskTxPos (computed like txindex), vout selects the output; 3c reads
        the tx and Solvers vout[vout] for the code chunk.
    * CONSENSUS WIRING DONE (2026-07-22):
      - CCodeDB block-atomic API: ApplyBlock(entries, best)/UndoBlock(hashes,
        best), each one batch; both aggregate duplicate H within a block for
        correct refcounting; both always write the best block (so empty-entry
        blocks still advance/retreat it). Unit test extended for intra-block
        dedup.
      - ConnectBlock: ProcessPushCodeBlock() (after the tx loop, before the
        `if (fJustCheck) return true;`) runs Solver+ParsePushCode on every
        output and rejects only on bad GRAMMAR -- runs even under fJustCheck
        (TestBlockValidity / mining pre-checks). Entries are built only when
        actually connecting (code_pos = containing tx's CDiskTxPos via
        GetBlockPos + GetSizeOfCompactSize + cumulative TX_WITH_WITNESS sizes;
        vout = output index) and committed with ApplyBlock(best = block hash)
        after the fJustCheck return. FatalError on a DB write failure.
      - DisconnectBlock: scan the block's PUSHCODE outputs, UndoBlock(hashes,
        best = pprev hash) -- trivial thanks to content-hash immutability.
    * REFERENCES ARE COMMITMENTS, NOT RESOLVED AT PUSH TIME (design, 2026-07-23):
      no reference-resolution check in ConnectBlock. A PUSHCODE output's
      parent_hash may name an entry that appears in this same block, a future
      block, or never -- validity is grammar only. This enables intra-block and
      FORWARD references (referencing a scriptPubKey not yet on chain).
      Acyclicity still holds (H depends on parent_hash). Whether a referenced
      part is AVAILABLE is a separate concern, resolved at ASSEMBLY time (3c):
      a missing part makes a branch INCOMPLETE (unassemblable), not invalid, so
      an algo with a dangling ref simply cannot be activated/run.
    * THE CODE INDEX IS CONSENSUS-CRITICAL (clarified by user 2026-07-23): the
      future dynamic-PoW-algo execution phase assembles code from this index to
      decide/verify which algo to run, so every node must hold identical, correct
      entries. Therefore it MUST remain a synchronous consensus DB (as built) --
      it is NOT an optional/background index, and an earlier note musing that it
      could become one is WRONG. Consequently refcount correctness and startup
      reconciliation DO matter for consensus (wrong entry -> wrong assembly ->
      wrong algo verification -> chain split).
    * STARTUP RECONCILIATION DONE (2026-07-23): Chainstate::ReconcileCodeDB()
      (validation.cpp), called once from node/chainstate.cpp LoadChainstate
      after LoadChainTip, against the active chainstate, under cs_main. Logic:
      no-op if OP_PUSHCODE isn't active at the tip (code DB legitimately empty)
      or if code-DB-best == tip; if the code DB is AHEAD of the tip on the same
      chain (best.GetAncestor(tip.height) == tip -- the crash case, code DB
      written every block vs coins DB flushed periodically), roll it back by
      reading each block from best down to tip and UndoBlock-ing its outputs;
      any other divergence (behind / wiped / forked) returns false -> load
      fails asking for -reindex (which wipes blocks/code and rebuilds via normal
      ConnectBlock). CollectPushCodeHashes() helper shared by DisconnectBlock
      and reconciliation so both scan identically. ReconcileCodeDB SKIPS
      snapshot (assumeutxo) chainstates (m_from_snapshot_blockhash set): a
      snapshot trusts the UTXO set at its base height without connecting the
      historical blocks, so it never populates the code DB for that history --
      the fully-validated (background) chainstate owns that. Without the skip,
      snapshot chainstate load fails (validation_chainstatemanager tests).
    * ASSUMEUTXO + CODE INDEX (limitation to carry into the execution phase):
      currently only testnet/regtest configure m_assumeutxo_data (mainnet is
      empty, so mainnet always full-validates from genesis and its code DB is
      always complete -- the safe case). IF a mainnet snapshot is ever shipped
      for fast sync, a node that loads it lacks PRE-SNAPSHOT code entries until
      the background chainstate validates from genesis; during that window a
      dynamic algo referencing pre-snapshot code is incomplete/unassemblable
      (handled by "incomplete != invalid", but it cannot be RUN yet). Design
      item for the execution phase: ship code entries as part of / alongside the
      snapshot, or gate dynamic-algo assembly on background validation reaching
      the referenced blocks.
    * 3b COMPLETE (2026-07-23): functional test test/functional/feature_pushcode.py
      passes -- MiniWallet + generateblock drives real scrypt PoW across the
      activation boundary and asserts: pre-activation malformed PUSHCODE ignored
      (block accepted); post-activation well-formed NEW accepted; forward
      reference (codehash not yet on chain) accepted; malformed 31-byte codehash
      rejected (bad-pushcode-codehash). Framework adaptations for Bitmark:
      renamed bitcoin.conf->bitmark.conf and bitcoind->bitmarkd binaries;
      test_framework/blocktools.py COINBASE_MATURITY 100->720 and
      MAX_FUTURE_BLOCK_TIME 2h->12min (mirrors the *enforced* CheckBlock rule at
      validation.cpp:4232, not the shadowed chain.h MAX_FUTURE_BLOCK_TIME=2h used
      in ContextualCheckBlockHeader).
- 3c: full assembly (walk parents / replay ops), the MAX_PUSHCODE_* limits
  (step 3), and code_pos materialization; unit tests for insert/replace/delete,
  cycle/dangling rejection, canonical selection.

### Open questions for review
- MAX_PUSHCODE_* values: keep dev2024's (huge) or retune for the wasm-module
  use case (llm.c verifier ~100 KB assembled from MAX_CODE_RELAY=256 chunks =>
  ~400 parts; depth/length caps should comfortably exceed that)?
- Authorization model (from phase-1 doc): still "anyone proposes, PoW-vote
  decides"? If so, no per-entry spend auth is needed and content-hash refs are
  fully sufficient. Confirm before 3b.
- Store code bytes in the codeindex, or keep dev2024's code_pos-into-blockfile
  approach (smaller index, but assembly must read block files)? Lean code_pos.

## Suggested phases

1. **Script layer** (self-contained, unit-testable): opcode at NOP4, verify
   flag, script error, interpreter case, solver template + TxoutType, param
   helpers. Unit tests green without any activation wiring.
2. **Consensus + policy**: supermajority activation (reintroduced
   IsSuperMajority with algo-bit masking; thresholds in chainparams, low on
   regtest), GetBlockScriptFlags wiring, relay policy caps. Functional test:
   mine version-N blocks past the threshold on regtest, verify the rule
   flips exactly at 750-of-1000 (regtest-scaled), and that algo-bit
   variation does not perturb the count.
3. **Code assembly + storage**: codeindex (BaseIndex) assembling multi-output
   / multi-part code with the replacement rules from dev2024 commits cd336a6
   and d42cc03; reorg behavior tested.
4. **RPC**: raw-transaction construction/decoding + query RPCs.
5. **Wallet** (optional, last).
6. **Execution bridge** (new work, not in dev2024): wasmtime C API embedding,
   the dynamic-algo evaluation hook, resident weight state (see llm.c doc:
   2 GB/instance bound, state cache semantics). Design doc first.

Phase 1-2 are a comfortable session each; 3 is the subtle one (reorg safety);
6 is where the llm.c verifier finally meets the node.

## Porting cautions

- dev2024's `IMPLEMENT_SERIALIZE`, `mapArgs`, `CBigNum`-era idioms all have
  modern replacements; port semantics, not syntax.
- 27.xb has its own Bitmark customizations (mPoW, base38, marking commits) --
  read `git log master..origin/27.xb -- src/script src/consensus` before
  touching shared files.
- The old code intermixed consensus validation and relay policy in main.cpp;
  27.x separates them strictly (validation.cpp vs policy/) -- classify each
  dev2024 hunk before placing it.
