// Standalone harness: drives the node's RunAlgoVerify bridge against a .aot file,
// so the whole consensus path (WAMR load -> marshal -> 7-arg verify() -> out_ab)
// can be exercised without a running node.
//
//   g++ -std=c++20 -I src -I src/config -I src/wamr/core/iwasm/include \
//       aot_harness.cpp src/dynamicalgo/wasmexec.cpp src/wamr/build/libvmlib.a -o aot_harness
//
// usage: aot_harness <module.aot> [mode_or_nbits_hex] [slot_block_count] [block_size]

#include <dynamicalgo/wasmexec.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {
//! Serves synthetic slot blocks, so the chain.* imports can be driven without a chain.
class StubChain final : public SlotBlockSource
{
public:
    uint32_t count{0};
    size_t block_size{200};
    bool fail_read{false};
    mutable uint32_t reads{0};

    uint32_t Count() const override { return count; }
    bool Read(uint32_t index, std::vector<unsigned char>& out) const override
    {
        ++reads;
        if (fail_read) return false;
        out.assign(block_size, 0x11);
        if (!out.empty()) out[0] = static_cast<unsigned char>(0xa0 + (index & 0x0f));
        return true;
    }
};

std::vector<unsigned char> ReadFile(const char* path)
{
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) { std::fprintf(stderr, "usage: %s <module.aot> [nbits_hex] [count] [blksz]\n", argv[0]); return 2; }
    const std::vector<unsigned char> mod = ReadFile(argv[1]);
    if (mod.empty()) { std::fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }

    const uint32_t nbits = argc > 2 ? (uint32_t)std::strtoul(argv[2], nullptr, 16) : 0x2100ffffu;
    StubChain chain;
    if (argc > 3) chain.count = (uint32_t)std::strtoul(argv[3], nullptr, 10);
    if (argc > 4) chain.block_size = (size_t)std::strtoul(argv[4], nullptr, 10);
    if (argc > 5 && std::strcmp(argv[5], "failread") == 0) chain.fail_read = true;

    std::vector<unsigned char> prev(32);
    for (int i = 0; i < 32; i++) prev[i] = (unsigned char)i;
    const std::vector<unsigned char> payout{0x6a, 0x00, 0x00};
    const std::vector<unsigned char> solution(8, 0x00);

    std::printf("module: %s (%zu bytes)  magic=%.4s\n", argv[1], mod.size(),
                mod.size() >= 4 ? (const char*)mod.data() : "????");
    const AlgoVerifyResult r = RunAlgoVerify(mod, prev, payout, nbits, solution, &chain);

    std::printf("ok=%d solution_valid=%d alpha=0x%08x beta=0x%08x\n",
                (int)r.ok, (int)r.solution_valid, r.alpha_q32, r.beta_q32);
    std::printf("gas_used=%llu bulk_bytes=%llu io_calls=%llu io_bytes=%llu\n",
                (unsigned long long)r.gas_used, (unsigned long long)r.bulk_bytes,
                (unsigned long long)r.io_calls, (unsigned long long)r.io_bytes);
    std::printf("gas_class=%d out_of_gas=%d chain_unavailable=%d host_reads=%u\n",
                r.gas_class, (int)r.out_of_gas, (int)r.chain_unavailable, chain.reads);
    if (!r.error.empty()) std::printf("error: %s\n", r.error.c_str());
    return r.ok ? 0 : 1;
}
