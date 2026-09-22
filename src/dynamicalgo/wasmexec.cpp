// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/wasmexec.h>

#include <wasm_export.h>

#include <crypto/common.h>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <vector>

namespace {
//! WAMR execution-environment operand/call stack. Consensus constant (a too-small
//! value would trap a legitimate module while a larger one accepts it); 1 MiB,
//! measured. See doc/dynamic-algo-mining.md sec 8.5.
constexpr uint32_t WASM_STACK_BYTES = 1024 * 1024;

//! Hard cap on a verifier's linear memory: 2 GiB = 32768 wasm pages of 64 KiB.
//! Enforced at instantiation regardless of the module's own declared maximum, so a
//! module cannot grow past it on any node. CONSENSUS constant (doc sec 8.5); the
//! WAMR analog of wasm3's d_m3MaxLinearMemoryPages=32768.
constexpr uint32_t WASM_MAX_MEMORY_PAGES = 32768;

//! Per-execution gas accounting, hung off the exec_env's user data so the usegas
//! native can find it. `used` accumulates the weighted cost the instrumented module
//! charges; once it exceeds `limit` the module is trapped.
struct GasState {
    uint64_t used{0};
    uint64_t limit{0};
};

//! Distinctive trap message so the out-of-gas case is recognizable in the result.
constexpr char OUT_OF_GAS_MSG[] = "dynamic-algo out of gas";

//! Host function imported by instrumented modules as `metering.usegas(i32 cost)`.
//! Charges the basic block's cost and traps deterministically on overrun. WAMR
//! passes exec_env as the first argument (signature "(i)" = one i32, no return).
void bitmark_usegas(wasm_exec_env_t exec_env, int32_t cost)
{
    auto* gas = static_cast<GasState*>(wasm_runtime_get_user_data(exec_env));
    if (gas == nullptr) return; // no budget attached (e.g. a direct, non-metered call)
    gas->used += static_cast<uint32_t>(cost); // cost is a non-negative block weight
    if (gas->used > gas->limit) {
        wasm_runtime_set_exception(wasm_runtime_get_module_inst(exec_env), OUT_OF_GAS_MSG);
    }
}

//! WAMR's runtime must be initialized once per process, and the gas native
//! registered before any instrumented module is instantiated.
bool EnsureWamrReady()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        if (!wasm_runtime_init()) return;
        static NativeSymbol syms[] = {
            {"usegas", reinterpret_cast<void*>(bitmark_usegas), "(i)", nullptr},
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
                               uint64_t gas_limit)
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
    GasState gas{};
    gas.limit = gas_limit;
    wasm_runtime_set_user_data(g.env, &gas);

    // verify(prev, payout,payout_len, nbits, txs,txs_len, last_n,last_n_len,
    //        nonce,nonce_len, out_ab) -> i32. All args are i32 (one cell each);
    // the i32 return lands in argv[0].
    uint32_t argv[11] = {
        off_prev, off_payout, (uint32_t)payout.size(), nbits,
        off_txs, (uint32_t)txs.size(), off_lastn, (uint32_t)last_n_blocks.size(),
        off_nonce, (uint32_t)solution.size(), off_outab};
    bool called = wasm_runtime_call_wasm(g.env, fn, 11, argv);
    res.gas_used = gas.used;
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
