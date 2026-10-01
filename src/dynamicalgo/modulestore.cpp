// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dynamicalgo/modulestore.h>

#include <logging.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/fs_helpers.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>

#ifdef WIN32
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace dynamicalgo {

namespace {

//! The WAMR commit both the runtime and wamrc are vendored from
//! (src/wamr/BITMARK-VENDOR.txt). Part of the cache path: re-vendoring WAMR must
//! miss the cache rather than reuse artifacts from a different toolchain, since the
//! .aot format and codegen are tied to it.
constexpr const char* WAMR_PINNED_COMMIT = "b70d708";

//! Run `prog` with `args` to completion. Returns the exit status, or -1 if the
//! program could not be run at all. Nothing is read from its stdout; wamrc is
//! chatty on success and writes diagnostics to stderr, which we leave attached so
//! an operator sees them in the node's console.
int RunProgram(const fs::path& prog, const std::vector<std::string>& args)
{
    // Build argv BEFORE forking: between fork() and exec() only async-signal-safe
    // work is permitted, and this process is multithreaded.
    const std::string prog_str{fs::PathToString(prog)};
    std::vector<const char*> argv;
    argv.reserve(args.size() + 2);
    argv.push_back(prog_str.c_str());
    for (const std::string& a : args) argv.push_back(a.c_str());
    argv.push_back(nullptr);

#ifdef WIN32
    const intptr_t rc{_spawnv(_P_WAIT, prog_str.c_str(), argv.data())};
    return rc < 0 ? -1 : static_cast<int>(rc);
#else
    // A bare name (the default, "wamrc") is resolved through PATH, so an installed
    // companion binary is found without the node having to locate its own bindir;
    // anything containing a separator is taken literally.
    const bool bare{prog_str.find('/') == std::string::npos};
    const pid_t pid{fork()};
    if (pid < 0) return -1;
    if (pid == 0) {
        if (bare) {
            execvp(prog_str.c_str(), const_cast<char* const*>(argv.data()));
        } else {
            execv(prog_str.c_str(), const_cast<char* const*>(argv.data()));
        }
        _exit(127); // exec failed; 127 is the conventional "not found"
    }
    int status{0};
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1; // killed by a signal
#endif
}

bool WriteFileBytes(const fs::path& p, Span<const unsigned char> bytes, std::string& err)
{
    FILE* f{fsbridge::fopen(p, "wb")};
    if (f == nullptr) {
        err = strprintf("cannot open %s for writing: %s", fs::PathToString(p), std::strerror(errno));
        return false;
    }
    const bool ok{bytes.empty() ||
                  std::fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size()};
    if (std::fclose(f) != 0 || !ok) {
        err = strprintf("cannot write %s", fs::PathToString(p));
        return false;
    }
    return true;
}

bool ReadFileBytes(const fs::path& p, std::vector<unsigned char>& out)
{
    FILE* f{fsbridge::fopen(p, "rb")};
    if (f == nullptr) return false;
    out.clear();
    unsigned char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + n);
    const bool ok{std::ferror(f) == 0};
    std::fclose(f);
    return ok;
}

} // namespace

const AotTarget& PinnedAotTarget()
{
    static const AotTarget target{[] {
        AotTarget t;
#if defined(__x86_64__) || defined(_M_X64)
        // x86-64-v2 == SSE4.2 baseline. Verified bit-identical to scalar and to the
        // interpreters (doc sec 8.3).
        t.tag = "x86_64-v2";
        t.args = {"--target=x86_64", "--cpu=x86-64-v2"};
#elif defined(__i386__) || defined(_M_IX86)
        // MUST use SSE2 float math, never x87: x87's 80-bit extended precision would
        // diverge from every other target. SSE2 is universal on post-2004 x86.
        t.tag = "i386-sse2";
        t.args = {"--target=i386", "--cpu=pentium4", "--cpu-features=+sse2"};
#elif defined(__aarch64__) || defined(_M_ARM64)
        // armv8-a baseline; NEON/ASIMD is mandatory there and is IEEE-754 including
        // denormals, so it matches x86.
        t.tag = "aarch64-v8a";
        t.args = {"--target=aarch64", "--cpu=generic"};
#elif defined(__arm__)
        t.tag = "armv7";
        t.supported = false;
        t.why_unsupported =
            "ARMv7 NEON float flushes denormals to zero rather than being fully "
            "IEEE-754, so v128 float could diverge from every other target on "
            "denormal inputs. Unresolved (doc sec 8.3): an ARMv7 node cannot be a "
            "dynamic-algo validator yet.";
#else
        t.tag = "unknown";
        t.supported = false;
        t.why_unsupported =
            "no pinned AOT target is defined for this architecture, and compiling "
            "with a host-specific target is forbidden because it could diverge "
            "(doc sec 8.3)";
#endif
        if (t.supported) {
            // Pinned so the artifact is reproducible for debugging. These do not
            // change results -- IEEE-strict float and integer semantics are fixed by
            // the target above -- but leaving them to wamrc's defaults would let a
            // toolchain change move them silently.
            t.args.emplace_back("--opt-level=3");
            t.args.emplace_back("--size-level=3");
        }
        return t;
    }()};
    return target;
}

fs::path FindWamrc(const std::string& configured)
{
    // An explicit -wamrc wins even if it does not exist, so the error names what the
    // operator actually asked for rather than silently falling back. It is also how
    // a --disable-wamrc build can still point at a compiler it has from elsewhere.
    if (!configured.empty()) return fs::PathFromString(configured);
#ifndef HAVE_WAMRC
    return {}; // built with --disable-wamrc: the operator supplies .aot modules
#else
#ifdef BITMARK_BINDIR
    const fs::path installed{fs::PathFromString(BITMARK_BINDIR) / fs::PathFromString("wamrc")};
    if (fs::exists(installed)) return installed;
#endif
    return fs::PathFromString("wamrc"); // bare: resolved through PATH by execvp
#endif // HAVE_WAMRC
}

ModuleStore::ModuleStore(fs::path dir, fs::path wamrc)
    : m_dir{std::move(dir)}, m_wamrc{std::move(wamrc)}
{
}

bool ModuleStore::ProbeCompiler(std::string& err) const
{
    if (m_wamrc.empty()) {
        err = "no AOT compiler configured (built with --disable-wamrc)";
        return false;
    }
    const int rc{RunProgram(m_wamrc, {"--version"})};
    if (rc != 0) {
        err = strprintf("cannot run the AOT compiler '%s' (exit %d)",
                        fs::PathToString(m_wamrc), rc);
        return false;
    }
    return true;
}

fs::path ModuleStore::AotPath(const uint256& branch) const
{
    return m_dir / fs::PathFromString(PinnedAotTarget().tag)
         / fs::PathFromString(WAMR_PINNED_COMMIT)
         / fs::PathFromString(branch.GetHex() + ".aot");
}

bool ModuleStore::Has(const uint256& branch) const
{
    return fs::exists(AotPath(branch));
}

std::string ModuleStore::ManualCommand(const uint256& branch, const fs::path& wasm_path) const
{
    const AotTarget& t{PinnedAotTarget()};
    std::string cmd{"wamrc"};
    for (const std::string& a : t.args) cmd += " " + a;
    cmd += " -o " + fs::PathToString(AotPath(branch));
    cmd += " " + fs::PathToString(wasm_path);
    return cmd;
}

bool ModuleStore::GetOrCompile(const uint256& branch, Span<const unsigned char> wasm,
                               std::vector<unsigned char>& aot, std::string& err) const
{
    const fs::path out{AotPath(branch)};
    if (ReadFileBytes(out, aot) && !aot.empty()) return true; // already materialized

    const AotTarget& target{PinnedAotTarget()};
    if (!target.supported) {
        err = strprintf("cannot compile dynamic algo %s: %s", branch.GetHex(),
                        target.why_unsupported);
        return false;
    }

    // The .wasm has to reach wamrc as a file. Write it next to the output so both
    // live on the same filesystem and the rename below is atomic.
    const fs::path dir{out.parent_path()};
    if (!fs::create_directories(dir) && !fs::is_directory(dir)) {
        err = strprintf("cannot create the dynamic-algo module store at %s",
                        fs::PathToString(dir));
        return false;
    }
    const fs::path wasm_tmp{dir / fs::PathFromString(branch.GetHex() + ".wasm.tmp")};
    const fs::path aot_tmp{dir / fs::PathFromString(branch.GetHex() + ".aot.tmp")};
    if (!WriteFileBytes(wasm_tmp, wasm, err)) return false;

    if (m_wamrc.empty()) {
        err = strprintf(
            "no AOT compiler available, so dynamic algo %s cannot be materialized. "
            "This node was built with --disable-wamrc, so it needs the compiled "
            "module supplied out of band. Produce it with:\n    %s\n"
            "(the assembled module has been left at %s)",
            branch.GetHex(), ManualCommand(branch, wasm_tmp), fs::PathToString(wasm_tmp));
        return false; // keep wasm_tmp: the operator needs it
    }

    std::vector<std::string> args{target.args};
    args.emplace_back("-o");
    args.emplace_back(fs::PathToString(aot_tmp));
    args.emplace_back(fs::PathToString(wasm_tmp));

    LogPrintf("Compiling dynamic algo %s for %s (this happens once per algo)\n",
              branch.GetHex(), target.tag);
    const int rc{RunProgram(m_wamrc, args)};
    if (rc != 0) {
        err = strprintf(
            "AOT compilation of dynamic algo %s failed (%s exited %d). Reproduce with:"
            "\n    %s\n(the assembled module has been left at %s)",
            branch.GetHex(), fs::PathToString(m_wamrc), rc,
            ManualCommand(branch, wasm_tmp), fs::PathToString(wasm_tmp));
        return false;
    }

    // Publish atomically, so a concurrent reader never sees a half-written module
    // and an interrupted compile leaves no usable file behind.
    std::error_code ec;
    fs::rename(aot_tmp, out, ec);
    if (ec) {
        err = strprintf("cannot move the compiled module into place at %s: %s",
                        fs::PathToString(out), ec.message());
        return false;
    }
    fs::remove(wasm_tmp, ec); // best effort; only an input to the compile

    if (!ReadFileBytes(out, aot) || aot.empty()) {
        err = strprintf("compiled module %s is unreadable", fs::PathToString(out));
        return false;
    }
    return true;
}

} // namespace dynamicalgo
