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

//! Total per-verifier memory is capped at 2 GiB, split so the two channels sum
//! exactly: linear memory (mmap'd, hardware-bounds-checked) + all WAMR runtime
//! allocations (instance structs, tables, exec stack) via the custom allocator.
//!   linear cap   = 32512 pages x 64 KiB = 2032 MiB (1.984375 GiB)
//!   alloc ceiling = 16 MiB (WASM_ALLOC_CEILING)
//!   total        = 2032 + 16 = 2048 MiB = 2 GiB exactly.
//! The trunk verifier measured 31,163 pages (1.902 GiB), leaving ~84 MiB headroom.
//! CONSENSUS constants, fixed network-wide (doc sec 8.5). max_memory_pages is
//! enforced per-instance by WAMR; the alloc ceiling is process-global (see
//! EnsureWamrReady), i.e. per-instance only for one verify at a time.
constexpr uint32_t WASM_MAX_MEMORY_PAGES = 32512;
constexpr uint64_t WASM_ALLOC_CEILING = 16ull * 1024 * 1024;

using dynamicalgo::GasClass;

//! Per-execution gas accounting, hung off the exec_env's user data so the usegas
//! native can find it. `used[]` accumulates each count class's executions; `bulk_bytes`
//! accumulates the combined BULK budget (each bulk op's runtime size N converted to
//! bytes). Once any class exceeds its consensus limit the module is trapped and the
//! offending class recorded in `tripped`. `uncapped` disables the caps for offline
//! measurement (never set on the consensus path).
struct GasState {
    uint64_t used[dynamicalgo::GC_COUNT_N] = {0};
    uint64_t bulk_bytes{0};
    int32_t tripped{-1};
    bool uncapped{false};
};

//! Distinctive trap message so the out-of-gas case is recognizable in the result.
constexpr char OUT_OF_GAS_MSG[] = "dynamic-algo out of gas";

//! Host function imported by instrumented modules as `metering.usegas(i32 class,
//! i32 n)`. For a count class (0..GC_COUNT_N-1), n is the basic block's execution
//! count of that class; for a bulk sub-kind (GC_BULK_*), n is the bulk op's runtime
//! size operand, converted to bytes and folded into the combined BULK budget. Traps
//! deterministically the moment any class exceeds its consensus limit. WAMR passes
//! exec_env as the first argument (signature "(ii)" = two i32, no return).
void bitmark_usegas(wasm_exec_env_t exec_env, int32_t cls, int32_t n_raw)
{
    auto* gas = static_cast<GasState*>(wasm_runtime_get_user_data(exec_env));
    if (gas == nullptr) return; // no budget attached (e.g. a direct, non-metered call)
    const uint64_t n = static_cast<uint32_t>(n_raw); // count / size operand, non-negative
    if (cls >= 0 && cls < dynamicalgo::GC_COUNT_N) {
        const uint64_t u = (gas->used[cls] += n);
        if (!gas->uncapped && u > dynamicalgo::GAS_LIMIT[cls]) {
            gas->tripped = cls;
            wasm_runtime_set_exception(wasm_runtime_get_module_inst(exec_env), OUT_OF_GAS_MSG);
        }
    } else if (cls >= dynamicalgo::GC_BULK_MEM && cls < dynamicalgo::GC_CLASS_MAX) {
        gas->bulk_bytes += n * dynamicalgo::GasBulkFactor(cls);
        if (!gas->uncapped && gas->bulk_bytes > dynamicalgo::GAS_BULK_LIMIT) {
            gas->tripped = cls;
            wasm_runtime_set_exception(wasm_runtime_get_module_inst(exec_env), OUT_OF_GAS_MSG);
        }
    }
    // Unknown class id: ignore. The instrumenter only ever emits valid ids; a
    // hand-crafted module passing garbage simply charges nothing (its real opcodes
    // are still metered by their own charges), so this cannot evade the caps.
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
        static NativeSymbol syms[] = {
            {"usegas", reinterpret_cast<void*>(bitmark_usegas), "(ii)", nullptr},
        };
        ok = wasm_runtime_register_natives("metering", syms, 1);
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
                               Span<const unsigned char> prev_hash,
                               Span<const unsigned char> payout,
                               uint32_t nbits,
                               Span<const unsigned char> txs,
                               Span<const unsigned char> last_n_blocks,
                               Span<const unsigned char> solution,
                               bool meter_uncapped)
{
    AlgoVerifyResult res;

    if (module_bytes.empty()) { res.error = "empty module"; return res; }
    // The guest reads exactly 32 prev_hash bytes; reject anything else.
    if (prev_hash.size() != 32) { res.error = "prev_hash must be 32 bytes"; return res; }
    if (!EnsureWamrReady()) { res.error = "WAMR init/register failed"; return res; }

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
    const uint64_t inputs_total = (uint64_t)prev_hash.size() + payout.size() + txs.size()
                                + last_n_blocks.size() + solution.size() + 8;
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
    uint32_t off_prev = 0, off_payout = 0, off_txs = 0, off_lastn = 0, off_nonce = 0, off_outab = 0;
    void* outab_native = nullptr;
    bool marshalled = put(prev_hash, off_prev) && put(payout, off_payout) && put(txs, off_txs)
                   && put(last_n_blocks, off_lastn) && put(solution, off_nonce);
    if (marshalled) {
        uint64_t o = wasm_runtime_module_malloc(g.inst, 8, &outab_native);
        if (o == 0 || outab_native == nullptr) marshalled = false;
        else { off_outab = (uint32_t)o; std::memset(outab_native, 0, 8); }
    }
    if (!marshalled) { res.error = "module_malloc failed (app heap too small?)"; return res; }

    wasm_function_inst_t fn = wasm_runtime_lookup_function(g.inst, "verify");
    if (!fn) { res.error = "no verify export"; return res; }

    // Attach the gas budget so the usegas native meters this execution and traps on
    // overrun. `gas` must outlive the call (referenced via the exec_env user data).
    // Limits are consensus constants (gasclasses.h); meter_uncapped only disables
    // them for offline measurement.
    GasState gas{};
    gas.uncapped = meter_uncapped;
    wasm_runtime_set_user_data(g.env, &gas);

    // verify(prev, payout,payout_len, nbits, txs,txs_len, last_n,last_n_len,
    //        nonce,nonce_len, out_ab) -> i32. All args are i32 (one cell each);
    // the i32 return lands in argv[0].
    uint32_t argv[11] = {
        off_prev, off_payout, (uint32_t)payout.size(), nbits,
        off_txs, (uint32_t)txs.size(), off_lastn, (uint32_t)last_n_blocks.size(),
        off_nonce, (uint32_t)solution.size(), off_outab};
    bool called = wasm_runtime_call_wasm(g.env, fn, 11, argv);
    // Report the per-class usage (both on success and on any trap). gas_used is the
    // total count-class executions; bulk_bytes the combined BULK budget.
    for (int cl = 0; cl < dynamicalgo::GC_COUNT_N; cl++) {
        res.class_used[cl] = gas.used[cl];
        res.gas_used += gas.used[cl];
    }
    res.bulk_bytes = gas.bulk_bytes;
    res.gas_class = gas.tripped;
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
