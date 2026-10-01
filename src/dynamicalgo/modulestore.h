// Copyright (c) 2026 The Bitmark developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DYNAMICALGO_MODULESTORE_H
#define BITCOIN_DYNAMICALGO_MODULESTORE_H

#include <span.h>
#include <uint256.h>
#include <util/fs.h>

#include <string>
#include <vector>

// Materialized dynamic-algo module store (doc/dynamic-algo-mining.md sec 8.3, 8.4).
//
// What lives on the chain is a .wasm: OP_PUSHCODE chunks that assemble into the algo
// module. What the node can EXECUTE is a .aot, because the vendored WAMR runtime is
// AOT-only. This store bridges the two: it holds the compiled module per branch and
// materializes a missing one by running the companion `wamrc` (built from the same
// pinned WAMR commit -- aot_loader.c demands an exact AOT_CURRENT_VERSION match).
//
// The .aot is DERIVED, never consensus data. It is a per-architecture artifact of the
// canonical .wasm, so:
//   * nodes do NOT need identical .aot bytes, only identical observable behaviour
//     (result, traps, gas counts). That is why reproducible compilation is not
//     required and only the target SEMANTICS are pinned (sec 8.3).
//   * the store can be deleted at any time and is rebuilt on demand.
//   * AOT-compilability must never gate activation: it is per-arch, so an x86 node
//     succeeding where an ARM node fails would split the activation decision. A node
//     that cannot produce the module therefore has a LOCAL problem and must stop,
//     not reject the block. Governance is the defence against an algo that will not
//     compile.
//
// Layout: <dir>/<target tag>/<pinned WAMR commit>/<branch hex>.aot
// The branch is OP_PUSHCODE's content address, so it determines the .wasm bytes; the
// two parent directories make a changed architecture or re-vendored toolchain miss
// the cache and recompile instead of loading a stale artifact.

namespace dynamicalgo {

//! The pinned per-arch AOT target -- a CONSENSUS parameter (doc sec 8.3).
//! `-mcpu=native` is forbidden: an +avx2 .aot SIGILLs on a non-AVX2 host, and a
//! node-specific target could diverge. Every node compiles the canonical .wasm with
//! the same conservative baseline and strict IEEE, so results are bit-identical.
struct AotTarget {
    //! Directory component, and what identifies this target in error messages.
    std::string tag;
    //! The pinned wamrc arguments, in order. Empty means this architecture is not
    //! (yet) supported as a dynamic-algo validator -- see `supported`.
    std::vector<std::string> args;
    //! False when the architecture cannot currently validate dynamic blocks at all;
    //! `why_unsupported` explains. (ARMv7: NEON float flushes denormals to zero, so
    //! v128 float could diverge from every other target -- unresolved, sec 8.3.)
    bool supported{true};
    std::string why_unsupported;
};

//! The pinned target for the architecture this node was built for.
const AotTarget& PinnedAotTarget();

//! Resolve the companion compiler, in order: `configured` (the -wamrc argument) if
//! given; then the install bindir, which is where `make install` puts it next to
//! the daemon; then the bare name "wamrc", which execvp resolves through PATH.
//!
//! The bindir step matters because PATH alone is not reliable for a daemon: running
//! from the build tree, a systemd unit with a trimmed Environment=PATH, or a GUI
//! launch on macOS can all miss an installed binary. Operators should not have to
//! set PATH for the normal case, and a node must not discover a missing compiler
//! only when an algo first activates.
fs::path FindWamrc(const std::string& configured);

class ModuleStore
{
private:
    const fs::path m_dir;    //!< store root (a datadir subdirectory)
    const fs::path m_wamrc;  //!< the companion compiler, or empty if not built

    fs::path AotPath(const uint256& branch) const;

public:
    //! `wamrc` may be empty (configured with --disable-wamrc, or the binary is
    //! missing), in which case only already-present modules can be served.
    ModuleStore(fs::path dir, fs::path wamrc);

    //! The executable module for `branch`, compiling it from `wasm` if absent.
    //!
    //! Returns false ONLY for local failures -- missing compiler, compile error,
    //! unwritable store, unsupported architecture -- never because the block is
    //! invalid. `err` is operator-facing and names the exact command to reproduce,
    //! because the caller's correct response is a fatal error, not block rejection.
    bool GetOrCompile(const uint256& branch, Span<const unsigned char> wasm,
                      std::vector<unsigned char>& aot, std::string& err) const;

    //! Is a compiled module already present? (For pre-warming and diagnostics.)
    bool Has(const uint256& branch) const;

    //! Run the compiler's --version to check it is actually present and usable.
    //! Called once at startup so an operator learns about a missing or broken
    //! compiler then, rather than when the first algo activates and the node would
    //! otherwise have to stop. False with `err` set if it cannot be run.
    bool ProbeCompiler(std::string& err) const;

    //! The resolved compiler path (possibly a bare name resolved via PATH).
    const fs::path& CompilerPath() const { return m_wamrc; }

    //! The command an operator would run to produce `branch`'s module by hand, for
    //! the --disable-wamrc path and for error messages.
    std::string ManualCommand(const uint256& branch, const fs::path& wasm_path) const;
};

} // namespace dynamicalgo

#endif // BITCOIN_DYNAMICALGO_MODULESTORE_H
