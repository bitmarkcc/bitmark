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
