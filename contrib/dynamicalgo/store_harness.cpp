// Exercises the full dynamic-algo materialization pipeline without a running node:
//
//   on-chain .wasm -> ModuleStore::GetOrCompile (execs wamrc) -> .aot -> RunAlgoVerify
//
// usage: store_harness <module.wasm> <store-dir> <wamrc-path|-> [nbits_hex]
// A second run over the same store-dir must hit the cache (no recompile).

#include <dynamicalgo/modulestore.h>
#include <dynamicalgo/wasmexec.h>
#include <hash.h>
#include <logging.h>

#include <util/translation.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

//! Normally provided by bitcoind/the test suite; a bare harness must define it.
const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

namespace {
std::vector<unsigned char> ReadFile(const char* p)
{
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
} // namespace

int main(int argc, char** argv)
{
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s <module.wasm> <store-dir> <wamrc|-> [nbits_hex]\n", argv[0]);
        return 2;
    }
    LogInstance().m_print_to_console = true;
    LogInstance().StartLogging();

    const std::vector<unsigned char> wasm{ReadFile(argv[1])};
    if (wasm.empty()) { std::fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }

    // The branch is OP_PUSHCODE's content address; any stable id works here.
    const uint256 branch{Hash(wasm)};
    const fs::path wamrc{std::string(argv[3]) == "-" ? fs::path{} : fs::PathFromString(argv[3])};
    const dynamicalgo::ModuleStore store{fs::PathFromString(argv[2]), wamrc};

    const dynamicalgo::AotTarget& t{dynamicalgo::PinnedAotTarget()};
    std::printf("target tag=%s supported=%d\n", t.tag.c_str(), (int)t.supported);
    std::printf("cached before=%d\n", (int)store.Has(branch));

    std::vector<unsigned char> aot;
    std::string err;
    if (!store.GetOrCompile(branch, wasm, aot, err)) {
        std::printf("GetOrCompile FAILED:\n%s\n", err.c_str());
        return 1;
    }
    std::printf("aot=%zu bytes  magic=%.4s  cached after=%d\n", aot.size(),
                aot.size() >= 4 ? (const char*)aot.data() : "????", (int)store.Has(branch));

    std::vector<unsigned char> anchor(32);
    for (int i = 0; i < 32; i++) anchor[i] = (unsigned char)i;
    const std::vector<unsigned char> payout{0x6a, 0x00, 0x00};
    const std::vector<unsigned char> solution(8, 0x00);
    const uint32_t nbits{argc > 4 ? (uint32_t)std::strtoul(argv[4], nullptr, 16) : 0x2100ffffu};

    const AlgoVerifyResult r{RunAlgoVerify(aot, anchor, payout, nbits, solution, nullptr)};
    std::printf("verify: ok=%d solution_valid=%d alpha=0x%08x beta=0x%08x\n",
                (int)r.ok, (int)r.solution_valid, r.alpha_q32, r.beta_q32);
    if (!r.error.empty()) std::printf("verify error: %s\n", r.error.c_str());
    return r.ok ? 0 : 1;
}
