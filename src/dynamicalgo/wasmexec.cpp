// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/wasmexec.h>

#include <wasm_export.h>

#include <crypto/common.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

namespace {
//! WAMR execution-environment operand/call stack. Consensus constant (a too-small
//! value would trap a legitimate module while a larger one accepts it); 1 MiB,
//! measured. See doc/dynamic-algo-mining.md sec 8.5.
constexpr uint32_t WASM_STACK_BYTES = 1024 * 1024;

//! Per-verifier memory is bounded at ~2 GiB across two channels: linear memory
//! (mmap'd, hardware-bounds-checked) + all WAMR runtime allocations (instance
//! structs, tables, exec stack) via the custom allocator.
//!   module linear cap = 32512 pages x 64 KiB = 2032 MiB (1.984375 GiB)
//!   alloc ceiling     = 16 MiB (WASM_ALLOC_CEILING)
//!   plus the host-managed app heap, which lives INSIDE linear memory in addition
//!   to the cap: inputs_total + 64 KiB, so 2 pages for a small solution and ~17
//!   for a 1 MB one => total <= ~2049 MiB (not exactly 2048; see doc sec 8.5).
//! The module ceiling is kept FIXED rather than reduced by the heap: the heap
//! depends on the block's solution length, and a consensus memory limit must not
//! vary with block content. Every node still grants the same 32512 growable pages
//! for a given block, so memory.grow fails at the identical point everywhere.
//! WAMR only LOWERS a module's declared max, so this is a ceiling that bounds a
//! large algo but never blocks one; a module that never grows keeps its own
//! smaller max and WAMR logs a benign "cannot override max memory".
//! The trunk verifier measured 31,163 pages (1.902 GiB), leaving ~84 MiB headroom.
//! CONSENSUS constants, fixed network-wide (doc sec 8.5). max_memory_pages is
//! enforced per-instance by WAMR; the alloc ceiling is process-global (see
//! EnsureWamrReady), i.e. per-instance only for one verify at a time.
constexpr uint32_t WASM_MAX_MEMORY_PAGES = 32512;
constexpr uint64_t WASM_ALLOC_CEILING = 16ull * 1024 * 1024;

using dynamicalgo::GasClass;

//! Per-execution state, hung off the exec_env's user data so the native functions
//! can find it. `used[]` accumulates each count class's executions; `bulk_bytes` the
//! combined BULK budget (each bulk op's runtime size N converted to bytes); io_calls
//! and io_bytes the chain-access budgets. Once any budget exceeds its consensus limit
//! the module is trapped and the offending class recorded in `tripped`. `uncapped`
//! disables the caps for offline measurement (never set on the consensus path).
//! `chain` serves the chain-access imports and may be null.
struct ExecState {
    uint64_t used[dynamicalgo::GC_COUNT_N] = {0};
    uint64_t bulk_bytes{0};
    uint64_t io_calls{0};
    uint64_t io_bytes{0};
    int32_t tripped{-1};
    bool uncapped{false};
    const SlotBlockSource* chain{nullptr};
    bool chain_unavailable{false};
};

//! Distinctive trap messages so these cases are recognizable in the result.
constexpr char OUT_OF_GAS_MSG[] = "dynamic-algo out of gas";
constexpr char CHAIN_UNAVAIL_MSG[] = "dynamic-algo chain block unavailable";

//! Trap the module, recording which budget tripped.
void TripBudget(wasm_exec_env_t exec_env, ExecState& st, int32_t cls)
{
    st.tripped = cls;
    wasm_runtime_set_exception(wasm_runtime_get_module_inst(exec_env), OUT_OF_GAS_MSG);
}

//! Host function imported by instrumented modules as `metering.usegas(i32 class,
//! i32 n)`. For a count class (0..GC_COUNT_N-1), n is the basic block's execution
//! count of that class; for a bulk sub-kind (GC_BULK_*), n is the bulk op's runtime
//! size operand, converted to bytes and folded into the combined BULK budget. Traps
//! deterministically the moment any class exceeds its consensus limit. WAMR passes
//! exec_env as the first argument (signature "(ii)" = two i32, no return).
void bitmark_usegas(wasm_exec_env_t exec_env, int32_t cls, int32_t n_raw)
{
    auto* st = static_cast<ExecState*>(wasm_runtime_get_user_data(exec_env));
    if (st == nullptr) return; // no budget attached (e.g. a direct, non-metered call)
    const uint64_t n = static_cast<uint32_t>(n_raw); // count / size operand, non-negative
    if (cls >= 0 && cls < dynamicalgo::GC_COUNT_N) {
        const uint64_t u = (st->used[cls] += n);
        if (!st->uncapped && u > dynamicalgo::GAS_LIMIT[cls]) TripBudget(exec_env, *st, cls);
    } else if (cls >= dynamicalgo::GC_BULK_MEM && cls < dynamicalgo::GC_USEGAS_MAX) {
        st->bulk_bytes += n * dynamicalgo::GasBulkFactor(cls);
        if (!st->uncapped && st->bulk_bytes > dynamicalgo::GAS_BULK_LIMIT) {
            TripBudget(exec_env, *st, cls);
        }
    }
    // Unknown class id: ignore -- including the host-charged ids at or above
    // GC_USEGAS_MAX, which guest code must never be able to credit or consume. The
    // instrumenter only ever emits valid ids; a hand-crafted module passing garbage
    // simply charges nothing (its real opcodes are still metered by their own
    // charges), so this cannot evade the caps.
}

//! Host function `chain.slot_block_count() -> i32`: the addressable window size.
//! Free (no read), so it is not charged beyond the guest's own `call`.
int32_t bitmark_slot_block_count(wasm_exec_env_t exec_env)
{
    auto* st = static_cast<ExecState*>(wasm_runtime_get_user_data(exec_env));
    if (st == nullptr || st->chain == nullptr) return 0;
    // Count is bounded by MIN_SLOT_BLOCKS_ON_DISK, far below INT32_MAX, but clamp
    // rather than let a bad source produce a negative count in the guest.
    return static_cast<int32_t>(std::min<uint32_t>(st->chain->Count(), 0x7fffffffu));
}

//! Host function `chain.slot_block(i32 index, i32 ptr, i32 cap) -> i32`: write the
//! serialized block at `index` (0 == newest) into the module's memory at `ptr`,
//! returning its size, or a negative SLOT_BLOCK_* code with nothing written.
int32_t bitmark_slot_block(wasm_exec_env_t exec_env, int32_t index_raw, int32_t ptr_raw,
                           int32_t cap_raw)
{
    auto* st = static_cast<ExecState*>(wasm_runtime_get_user_data(exec_env));
    if (st == nullptr || st->chain == nullptr) return SLOT_BLOCK_NO_BLOCK;

    // Charge the call BEFORE anything else: the per-fetch overhead (index walk, seek,
    // deserialization) is paid even by an out-of-range probe, so charging afterwards
    // would leave probing free.
    st->io_calls += 1;
    if (!st->uncapped && st->io_calls > dynamicalgo::GAS_IO_CALLS_LIMIT) {
        TripBudget(exec_env, *st, dynamicalgo::GC_IO_CALLS);
        return 0; // return value is irrelevant; the trap aborts the call
    }

    const uint32_t index = static_cast<uint32_t>(index_raw);
    if (index >= st->chain->Count()) return SLOT_BLOCK_NO_BLOCK; // deterministic everywhere

    std::vector<unsigned char> blk;
    if (!st->chain->Read(index, blk)) {
        // Consensus says this block is in the window but this node cannot read it.
        // Trap with a distinct message so the caller escalates instead of rejecting.
        st->chain_unavailable = true;
        wasm_runtime_set_exception(wasm_runtime_get_module_inst(exec_env), CHAIN_UNAVAIL_MSG);
        return 0;
    }

    const uint64_t size = blk.size();
    st->io_bytes += size;
    if (!st->uncapped && st->io_bytes > dynamicalgo::GAS_IO_BYTES_LIMIT) {
        TripBudget(exec_env, *st, dynamicalgo::GC_IO_BYTES);
        return 0;
    }

    // The read is charged whether or not it fits, so a module that wants one fetch
    // per block passes a buffer of at least MAX_BLOCK_SERIALIZED_SIZE.
    if (size > static_cast<uint64_t>(static_cast<uint32_t>(cap_raw))) return SLOT_BLOCK_TOO_SMALL;

    // An out-of-bounds destination traps rather than returning a code: WAMR's check
    // sets the "out of bounds memory access" exception itself before returning false,
    // so the call is already doomed and the return value is never observed. That is
    // the same thing a plain i32.store out of bounds would do.
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    const uint64_t ptr = static_cast<uint32_t>(ptr_raw);
    if (!wasm_runtime_validate_app_addr(inst, ptr, size)) return 0;
    void* native = wasm_runtime_addr_app_to_native(inst, ptr);
    if (native == nullptr) {
        wasm_runtime_set_exception(inst, "out of bounds memory access");
        return 0;
    }
    std::memcpy(native, blk.data(), size);
    return static_cast<int32_t>(size);
}

// Custom allocator enforcing WASM_ALLOC_CEILING on ALL WAMR runtime allocations
// (instance structs, tables, the exec-env stack). Linear memory is mmap'd on a
// separate path (capped by max_memory_pages), so linear + these two caps sum to
// the 2 GiB total. A 16-byte header records each block's size for free/realloc
// accounting and keeps the returned pointer 16-byte aligned. NOTE: this is a
// process-global ceiling (WAMR installs one allocator), so it bounds concurrent
// instances collectively; strictly per-instance only for one verify at a time.
std::atomic<uint64_t> g_wamr_alloc_used{0};

void* bm_malloc(unsigned size)
{
    const uint64_t need = static_cast<uint64_t>(size) + 16;
    if (g_wamr_alloc_used.fetch_add(need, std::memory_order_relaxed) + need > WASM_ALLOC_CEILING) {
        g_wamr_alloc_used.fetch_sub(need, std::memory_order_relaxed);
        return nullptr;
    }
    void* base = std::malloc(need);
    if (base == nullptr) { g_wamr_alloc_used.fetch_sub(need, std::memory_order_relaxed); return nullptr; }
    *static_cast<uint64_t*>(base) = need;
    return static_cast<char*>(base) + 16;
}

void bm_free(void* ptr)
{
    if (ptr == nullptr) return;
    void* base = static_cast<char*>(ptr) - 16;
    g_wamr_alloc_used.fetch_sub(*static_cast<uint64_t*>(base), std::memory_order_relaxed);
    std::free(base);
}

void* bm_realloc(void* ptr, unsigned size)
{
    if (ptr == nullptr) return bm_malloc(size);
    void* base = static_cast<char*>(ptr) - 16;
    const uint64_t old = *static_cast<uint64_t*>(base);
    const uint64_t need = static_cast<uint64_t>(size) + 16;
    if (need > old) {
        const uint64_t d = need - old;
        if (g_wamr_alloc_used.fetch_add(d, std::memory_order_relaxed) + d > WASM_ALLOC_CEILING) {
            g_wamr_alloc_used.fetch_sub(d, std::memory_order_relaxed);
            return nullptr; // over ceiling; original block stays valid
        }
    } else {
        g_wamr_alloc_used.fetch_sub(old - need, std::memory_order_relaxed);
    }
    void* nb = std::realloc(base, need);
    if (nb == nullptr) { // realloc failed: block unchanged at `old`; undo the counter delta
        if (need > old) g_wamr_alloc_used.fetch_sub(need - old, std::memory_order_relaxed);
        else g_wamr_alloc_used.fetch_add(old - need, std::memory_order_relaxed);
        return nullptr;
    }
    *static_cast<uint64_t*>(nb) = need;
    return static_cast<char*>(nb) + 16;
}

//! WAMR's runtime must be initialized once per process (with our capped allocator),
//! and the gas native registered before any instrumented module is instantiated.
//! WAMR's AOT mode bounds-checks guest memory with a per-THREAD signal handler, so every
//! thread that executes a module must initialise its own signal environment or the first
//! guest memory access traps with "thread signal env not inited".
//!
//! wasm_runtime_full_init() (EnsureWamrReady below) only initialises it for whichever
//! thread happens to call it first, and consensus runs verify() from several: an RPC
//! worker for getblocktemplate or submitblock, the message-handling thread for a block
//! arriving over p2p, whichever thread connects a block during a reorg. Without this,
//! whether verify() works depends on which thread ran it -- so one node could judge a
//! solution valid and another judge the same block's solution a fault, purely from
//! threading. That is a consensus split, not a performance problem.
//!
//! Initialised once per thread on first use and released when that thread exits. `mine`
//! so the thread that already owns an env (the one that ran full_init) does not have it
//! destroyed underneath the runtime.
namespace {
struct WamrThreadEnv {
    bool ok{false};
    bool mine{false};
    WamrThreadEnv()
    {
        if (wasm_runtime_thread_env_inited()) { ok = true; return; }
        ok = wasm_runtime_init_thread_env();
        mine = ok;
    }
    ~WamrThreadEnv() { if (mine) wasm_runtime_destroy_thread_env(); }
};
} // namespace

bool EnsureWamrReady()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        RuntimeInitArgs init_args;
        std::memset(&init_args, 0, sizeof(init_args));
        init_args.mem_alloc_type = Alloc_With_Allocator;
        init_args.mem_alloc_option.allocator.malloc_func = reinterpret_cast<void*>(bm_malloc);
        init_args.mem_alloc_option.allocator.realloc_func = reinterpret_cast<void*>(bm_realloc);
        init_args.mem_alloc_option.allocator.free_func = reinterpret_cast<void*>(bm_free);
        if (!wasm_runtime_full_init(&init_args)) return;
        static NativeSymbol metering_syms[] = {
            {"usegas", reinterpret_cast<void*>(bitmark_usegas), "(ii)", nullptr},
        };
        // Chain-access imports (doc sec 3). Signatures name only the wasm-visible
        // params -- WAMR passes exec_env to the native as a hidden first argument.
        static NativeSymbol chain_syms[] = {
            {"slot_block_count", reinterpret_cast<void*>(bitmark_slot_block_count), "()i", nullptr},
            {"slot_block", reinterpret_cast<void*>(bitmark_slot_block), "(iii)i", nullptr},
        };
        ok = wasm_runtime_register_natives("metering", metering_syms, 1)
          && wasm_runtime_register_natives("chain", chain_syms, 2);
    });
    return ok;
}

//! RAII teardown, in reverse order of creation. Freeing the instance also frees
//! its app heap, so per-buffer module_free is unnecessary.
struct InstGuard {
    wasm_exec_env_t env{nullptr};
    wasm_module_inst_t inst{nullptr};
    wasm_module_t module{nullptr};
    ~InstGuard()
    {
        if (env) wasm_runtime_destroy_exec_env(env);
        if (inst) wasm_runtime_deinstantiate(inst);
        if (module) wasm_runtime_unload(module);
    }
};
} // namespace

AlgoVerifyResult RunAlgoVerify(Span<const unsigned char> module_bytes,
                               Span<const unsigned char> anchor_hash,
                               Span<const unsigned char> payout,
                               uint32_t nbits,
                               Span<const unsigned char> solution,
                               const SlotBlockSource* chain,
                               bool meter_uncapped)
{
    AlgoVerifyResult res;

    if (module_bytes.empty()) { res.error = "empty module"; return res; }
    // The guest reads exactly 32 anchor_hash bytes; reject anything else.
    if (anchor_hash.size() != 32) { res.error = "anchor_hash must be 32 bytes"; return res; }
    if (!EnsureWamrReady()) { res.error = "WAMR init/register failed"; return res; }
    // Per-thread signal environment; see WamrThreadEnv. Must come after the runtime is
    // up and before anything touches guest memory.
    static thread_local WamrThreadEnv thread_env;
    if (!thread_env.ok) { res.error = "WAMR thread env init failed"; return res; }

    // WAMR references the module buffer until wasm_runtime_unload; keep our own
    // copy alive for the whole call (declared before the guard so it outlives it).
    std::vector<uint8_t> mod_buf(module_bytes.begin(), module_bytes.end());

    char err[256];
    InstGuard g;
    g.module = wasm_runtime_load(mod_buf.data(), (uint32_t)mod_buf.size(), err, sizeof(err));
    if (!g.module) { res.error = std::string("load: ") + err; return res; }

    // App heap for host-marshaled inputs (module_malloc). Consensus verifier
    // modules are freestanding, so WAMR provides this heap; size it to the inputs
    // plus a small margin for per-allocation headers. The model's own large
    // allocations happen inside the module and are not marshaled here.
    // The slot's previous blocks are NOT marshaled here -- the module pulls them
    // through the chain.* imports into its own memory (doc sec 2.5).
    const uint64_t inputs_total = (uint64_t)anchor_hash.size() + payout.size()
                                + solution.size() + 8;
    const uint32_t heap_size = (uint32_t)std::min<uint64_t>(inputs_total + (1u << 16), 0xFFFFFFFFu);

    InstantiationArgs inst_args{};
    inst_args.default_stack_size = WASM_STACK_BYTES; // ignored once create_exec_env sets its own
    inst_args.host_managed_heap_size = heap_size;
    inst_args.max_memory_pages = WASM_MAX_MEMORY_PAGES; // 2 GiB cap, consensus (doc 8.5)
    g.inst = wasm_runtime_instantiate_ex(g.module, &inst_args, err, sizeof(err));
    if (!g.inst) { res.error = std::string("instantiate: ") + err; return res; }

    g.env = wasm_runtime_create_exec_env(g.inst, WASM_STACK_BYTES);
    if (!g.env) { res.error = "create_exec_env failed"; return res; }

    // Marshal each input into the module's memory, writing immediately (data at an
    // app offset survives later memory growth; only native pointers go stale).
    auto put = [&](Span<const unsigned char> s, uint32_t& off) -> bool {
        void* native = nullptr;
        uint64_t o = wasm_runtime_module_malloc(g.inst, s.empty() ? 1 : (uint64_t)s.size(), &native);
        if (o == 0 || native == nullptr) return false;
        if (!s.empty()) std::memcpy(native, s.data(), s.size());
        off = (uint32_t)o;
        return true;
    };
    uint32_t off_anchor = 0, off_payout = 0, off_nonce = 0, off_outab = 0;
    void* outab_native = nullptr;
    bool marshalled = put(anchor_hash, off_anchor) && put(payout, off_payout)
                   && put(solution, off_nonce);
    if (marshalled) {
        uint64_t o = wasm_runtime_module_malloc(g.inst, 8, &outab_native);
        if (o == 0 || outab_native == nullptr) marshalled = false;
        else { off_outab = (uint32_t)o; std::memset(outab_native, 0, 8); }
    }
    if (!marshalled) { res.error = "module_malloc failed (app heap too small?)"; return res; }

    wasm_function_inst_t fn = wasm_runtime_lookup_function(g.inst, "verify");
    if (!fn) { res.error = "no verify export"; return res; }

    // Attach the execution state so the natives meter this run and trap on overrun,
    // and so the chain.* imports can reach the block source. `st` must outlive the
    // call (referenced via the exec_env user data). Limits are consensus constants
    // (gasclasses.h); meter_uncapped only disables them for offline measurement.
    ExecState st{};
    st.uncapped = meter_uncapped;
    st.chain = chain;
    wasm_runtime_set_user_data(g.env, &st);

    // verify(prev, payout,payout_len, nbits, nonce,nonce_len, out_ab) -> i32. All
    // args are i32 (one cell each); the i32 return lands in argv[0].
    uint32_t argv[7] = {
        off_anchor, off_payout, (uint32_t)payout.size(), nbits,
        off_nonce, (uint32_t)solution.size(), off_outab};
    bool called = wasm_runtime_call_wasm(g.env, fn, 7, argv);
    // Report the per-class usage (both on success and on any trap). gas_used is the
    // total count-class executions; bulk_bytes the combined BULK budget.
    for (int cl = 0; cl < dynamicalgo::GC_COUNT_N; cl++) {
        res.class_used[cl] = st.used[cl];
        res.gas_used += st.used[cl];
    }
    res.bulk_bytes = st.bulk_bytes;
    res.io_calls = st.io_calls;
    res.io_bytes = st.io_bytes;
    res.gas_class = st.tripped;
    res.chain_unavailable = st.chain_unavailable;
    if (!called) {
        const char* ex = wasm_runtime_get_exception(g.inst);
        res.out_of_gas = (ex != nullptr && std::strstr(ex, OUT_OF_GAS_MSG) != nullptr);
        res.error = std::string("verify trap: ") + (ex ? ex : "unknown");
        return res;
    }
    const int32_t ret = (int32_t)argv[0];

    // The call may have grown memory, invalidating outab_native; re-resolve the
    // app offset to a fresh native pointer and bounds-check it.
    if (!wasm_runtime_validate_app_addr(g.inst, off_outab, 8)) {
        res.error = "out_ab address invalid after call";
        return res;
    }
    const auto* ab = static_cast<const unsigned char*>(wasm_runtime_addr_app_to_native(g.inst, off_outab));
    if (!ab) { res.error = "out_ab unresolved after call"; return res; }

    // out_ab is little-endian on the wire; read it endian-independently.
    res.ok = true;
    res.solution_valid = (ret == 0);
    res.alpha_q32 = ReadLE32(ab);
    res.beta_q32 = ReadLE32(ab + 4);
    return res;
}
