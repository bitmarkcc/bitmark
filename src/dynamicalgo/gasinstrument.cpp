// Dynamic-algo gas instrumenter (offline tool, doc sec 8.6/8.8).
//
// Rewrites a freestanding verifier .wasm so it charges gas per opcode CLASS: it
// imports metering.usegas(i32 class, i32 n) and, at the top of every structured
// block body (function entry, and each block/loop/if/else body), calls
// usegas(class, count) once for each opcode class that occurs in that body, where
// count is the number of that body's own (non-nested) instructions of that class.
// A loop body's charge re-executes each iteration, so total gas per class tracks
// total instructions of that class executed -- a deterministic per-class CPU bound.
// Charging a whole block on entry (even if an inner branch skips part of it) only
// ever OVER-charges, which is safe.
//
// The classes are the 15 "count" classes plus a combined BULK budget, defined once
// in gasclasses.h and shared with the runtime (wasmexec.cpp). Count classes are
// charged by execution count as above. The four data-dependent bulk ops
// (memory/table fill/copy/init/grow) are charged by their runtime size operand N
// instead: the instrumenter reads N off the stack (via a scratch global) and calls
// usegas(bulk_kind, N); the runtime converts N to bytes and folds all bulk kinds
// into one budget. See gasclasses.h and doc sec 8.6 for the taxonomy and limits.
//
// The per-function structural caps (doc sec 8.8) are enforced separately at algo
// approval; this tool only injects metering.
//
// Usage: gas_instrument in.wasm out.wasm
#include "gasclasses.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

using namespace dynamicalgo;
using Bytes = std::vector<uint8_t>;

// ---- LEB128 ----------------------------------------------------------------
static uint64_t readU(const Bytes& b, size_t& i) {
    uint64_t r = 0; int s = 0; uint8_t c;
    do { if (i >= b.size()) throw std::runtime_error("leb eof"); c = b[i++]; r |= uint64_t(c & 0x7f) << s; s += 7; } while (c & 0x80);
    return r;
}
static int64_t readS(const Bytes& b, size_t& i) {
    int64_t r = 0; int s = 0; uint8_t c;
    do { c = b[i++]; r |= int64_t(c & 0x7f) << s; s += 7; } while (c & 0x80);
    if (s < 64 && (c & 0x40)) r |= -(int64_t(1) << s);
    return r;
}
static void putU(Bytes& b, uint64_t v) {
    do { uint8_t c = v & 0x7f; v >>= 7; if (v) c |= 0x80; b.push_back(c); } while (v);
}
static void putS(Bytes& b, int64_t v) {
    bool more = true;
    while (more) { uint8_t c = v & 0x7f; v >>= 7;
        if ((v == 0 && !(c & 0x40)) || (v == -1 && (c & 0x40))) more = false; else c |= 0x80;
        b.push_back(c); }
}

// ---- sections --------------------------------------------------------------
struct Section { uint8_t id; Bytes body; };

// ---- opcode -> class -------------------------------------------------------
//
// These map each opcode to its GasClass (gasclasses.h). Per-op worst-case times
// and the rationale for the boundaries (e.g. why i32/i64.const is its own ICONST
// class and local/f-const are VAR) are documented in doc sec 8.6.

// Numeric/comparison/conversion ops (0x45..0xc4).
static int classNumeric(uint8_t op) {
    switch (op) {
        case 0x6c: case 0x7e: return GC_IMUL;                                 // i32/i64.mul
        case 0x6d: case 0x6e: case 0x6f: case 0x70:                           // i32 div/rem_s/u
        case 0x7f: case 0x80: case 0x81: case 0x82: return GC_IDIV;           // i64 div/rem_s/u
        case 0x91: case 0x95: case 0x9f: case 0xa3: return GC_FDIV;           // f32/f64 sqrt, div
        // f32 add/sub/mul/min/max/copysign/abs/neg + compares
        case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: case 0x60:
        case 0x8b: case 0x8c: case 0x92: case 0x93: case 0x94: case 0x96: case 0x97: case 0x98:
        // f64 same
        case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66:
        case 0x99: case 0x9a: case 0xa0: case 0xa1: case 0xa2: case 0xa4: case 0xa5: case 0xa6:
            return GC_FADD;
        // f32/f64 ceil/floor/trunc/nearest
        case 0x8d: case 0x8e: case 0x8f: case 0x90:
        case 0x9b: case 0x9c: case 0x9d: case 0x9e:
            return GC_FCVT;
        case 0xbc: case 0xbd: case 0xbe: case 0xbf: return GC_NOP;            // reinterpret (bitcast, free)
        default: break;
    }
    if (op >= 0xa8 && op <= 0xbb) return GC_FCVT; // trunc_f*/convert_i*/demote/promote (0xa7 wrap & 0xac/0xad extend fall to INT)
    return GC_INT;                                // add/sub/logic/shift/rot/cmp/eqz/clz/ctz/popcnt/wrap/extend
}
// 0xFC sub-opcodes: trunc_sat + bulk memory/table.
static int classFC(uint32_t sub) {
    switch (sub) {
        case 8: case 10: case 11: return GC_BULK_MEM;                 // memory.init/copy/fill (N = bytes)
        case 12: case 14: case 15: case 17: return GC_BULK_TABLE;     // table.init/copy/grow/fill (N = elements)
        case 9: case 13: case 16: return GC_NOP;                      // data.drop, elem.drop, table.size (O(1))
        default: return GC_FCVT;                                      // 0..7 trunc_sat_f32/f64_s/u
    }
}
// 0xFD sub-opcodes: SIMD (v128).
static int classSIMD(uint32_t sub) {
    if (sub <= 11 || (sub >= 84 && sub <= 93)) return GC_SIMD_MEM;             // v128 loads/stores/lane
    if (sub == 227 || sub == 231 || sub == 239 || sub == 243) return GC_SIMD_DIV; // f32x4/f64x2 sqrt, div
    return GC_SIMD;
}

// ---- one instruction: copy + remap + classify -----------------------------
//
// A wasm instruction is one opcode byte followed by zero or more *immediate*
// operands baked into the bytecode (indices, memory align/offset, constants,
// block signatures, ...). To rewrite code correctly we must know each opcode's
// immediate layout so we can (a) copy the instruction faithfully, (b) advance
// past exactly its bytes -- getting this wrong desyncs the whole stream -- (c)
// spot the control-flow ops that delimit basic blocks for metering, (d) bump the
// function references (`call`, `ref.func`) that the new usegas import shifted, and
// (e) classify the opcode into its GasClass (returned via `klass`). The 0xFC and
// 0xFD prefixes each introduce a second "sub-opcode" (a LEB) that selects a
// bulk-memory/table or SIMD instruction respectively.
//
// Opcode numbers below are the WebAssembly binary opcodes. Authoritative refs:
//   - In-tree (and what our runtime decodes with, so guaranteed consistent):
//       src/wamr/core/iwasm/interpreter/wasm_opcode.h  (the WASM_OP_* enum)
//   - Spec, binary format of instructions (this is core spec 5.4):
//       https://webassembly.github.io/spec/core/binary/instructions.html
//   - Flat index of every opcode with its hex:
//       https://webassembly.github.io/spec/core/appendix/index-instructions.html
//   - Spec source: https://github.com/WebAssembly/spec
//       (document/core/binary/instructions.rst)
//   - SIMD (0xFD) binary opcodes:
//       https://github.com/WebAssembly/simd/blob/main/proposals/simd/BinarySIMD.md
//
// Copies one instruction from in[i..] into out, advancing i. Remaps the func
// index of `call`/`ref.func` (any index >= shift_at gains +1, since usegas was
// inserted at index shift_at). Sets `klass` to the opcode's GasClass. Returns the
// opcode's structural class, which drives the per-block metering in main():
//   0 = ordinary,  1 = block/loop/if opener,  2 = else,  3 = end
static int copyInstr(const Bytes& in, size_t& i, Bytes& out, uint32_t shift_at, int& klass) {
    uint8_t op = in[i++];
    auto emitByte = [&](uint8_t b){ out.push_back(b); };
    auto copyU = [&]{ uint64_t v = readU(in, i); putU(out, v); };
    auto copyS = [&]{ int64_t v = readS(in, i); putS(out, v); };
    auto copyMemarg = [&]{ copyU(); copyU(); }; // align, offset
    auto copyBlockType = [&]{ int64_t v = readS(in, i); putS(out, v); }; // s33
    emitByte(op);
    klass = GC_NOP;
    switch (op) {
        // -- control flow. block/loop/if carry a "block type" (an s33: 0x40 empty,
        //    a value type, or a type index) and open a new block => class 1. else
        //    (0x05) splits an if => class 2; end (0x0b) closes a block => class 3.
        //    if/else are conditional branches => GC_BRANCH; block/loop are structural.
        case 0x00: return 0;                                         // unreachable (NOP class, never re-executes)
        case 0x01: return 0;                                         // nop
        case 0x02: case 0x03: copyBlockType(); return 1;             // block, loop (NOP)
        case 0x04: klass = GC_BRANCH; copyBlockType(); return 1;     // if (conditional branch)
        case 0x05: klass = GC_BRANCH; return 2;                      // else
        case 0x0b: return 3;                                         // end
        case 0x0c: case 0x0d: klass = GC_BRANCH; copyU(); return 0;  // br, br_if      (label idx)
        case 0x0e: { klass = GC_BRANCH; uint64_t n = readU(in, i); putU(out, n); for (uint64_t k = 0; k <= n; k++) copyU(); return 0; } // br_table (vec(label)+default)
        case 0x0f: klass = GC_BRANCH; return 0;                      // return
        case 0x10: { klass = GC_CALL; uint64_t f = readU(in, i); if (f >= shift_at) f++; putU(out, f); return 0; } // call (func idx -- REMAP)
        case 0x11: klass = GC_CALL; copyU(); copyU(); return 0;      // call_indirect (type idx, table idx -- neither is a func idx)
        // -- parametric
        case 0x1a: return 0;                                         // drop (NOP)
        case 0x1b: klass = GC_BRANCH; return 0;                      // select (conditional move)
        case 0x1c: { klass = GC_BRANCH; uint64_t n = readU(in, i); putU(out, n); for (uint64_t k = 0; k < n; k++) emitByte(in[i++]); return 0; } // select t* (vec(valtype))
        // -- variable / table accessors (one index each)
        case 0x20: case 0x21: case 0x22: klass = GC_VAR; copyU(); return 0;  // local.get/set/tee (spill-risk ~1 ns)
        case 0x23: case 0x24: klass = GC_MEM; copyU(); return 0;             // global.get/set (memory access)
        case 0x25: case 0x26: klass = GC_MEM; copyU(); return 0;             // table.get/set (memory access)
        // -- memory size/grow take a single memory-index (u32 LEB; 0x00 in the MVP)
        case 0x3f: klass = GC_MEM; copyU(); return 0;                // memory.size (field load)
        case 0x40: klass = GC_BULK_GROW; copyU(); return 0;          // memory.grow (charged by N pages)
        // -- constants
        case 0x41: case 0x42: klass = GC_ICONST; copyS(); return 0;  // i32/i64.const (~0.25 ns: immediate / reg mov)
        case 0x43: klass = GC_VAR; for (int k = 0; k < 4; k++) emitByte(in[i++]); return 0; // f32.const (const-pool ~1 ns)
        case 0x44: klass = GC_VAR; for (int k = 0; k < 8; k++) emitByte(in[i++]); return 0; // f64.const
        // -- reference types
        case 0xd0: copyU(); return 0;                                // ref.null t (reftype) (NOP)
        case 0xd1: return 0;                                         // ref.is_null (NOP)
        case 0xd2: { uint64_t f = readU(in, i); if (f >= shift_at) f++; putU(out, f); return 0; } // ref.func (func idx -- REMAP) (NOP)
        default: break;
    }
    // Memory load/store family (i32.load .. i64.store32): each takes a "memarg"
    // (align LEB + offset LEB).
    if (op >= 0x28 && op <= 0x3e) { klass = GC_MEM; copyMemarg(); return 0; }
    // Numeric/comparison/conversion ops (i32.eqz .. i64.extend32_s): opcode only.
    if (op >= 0x45 && op <= 0xc4) { klass = classNumeric(op); return 0; }
    // 0xFC prefix: saturating float->int truncation (sub 0..7, no immediate) plus
    // the bulk memory/table ops (sub 8..17). Sub-opcode is a LEB.
    if (op == 0xfc) {
        uint32_t sub = (uint32_t)readU(in, i); putU(out, sub);
        klass = classFC(sub);
        switch (sub) {
            case 8:  copyU(); emitByte(in[i++]); break;              // memory.init (data idx, mem idx)
            case 9:  copyU(); break;                                 // data.drop   (data idx)
            case 10: emitByte(in[i++]); emitByte(in[i++]); break;    // memory.copy (dst mem, src mem)
            case 11: emitByte(in[i++]); break;                       // memory.fill (mem idx)
            case 12: copyU(); copyU(); break;                        // table.init  (elem idx, table idx)
            case 13: copyU(); break;                                 // elem.drop   (elem idx)
            case 14: copyU(); copyU(); break;                        // table.copy  (dst table, src table)
            case 15: case 16: case 17: copyU(); break;               // table.grow/size/fill (table idx)
            default: break;                                          // 0..7 = i32/i64.trunc_sat_f32/f64_s/u: no immediate
        }
        return 0;
    }
    // 0xFD prefix: fixed-width SIMD (v128). Sub-opcode is a LEB; only these carry
    // immediates, everything else (lane arithmetic, comparisons, ...) is bare.
    if (op == 0xfd) {
        uint32_t sub = (uint32_t)readU(in, i); putU(out, sub);
        klass = classSIMD(sub);
        if (sub == 12 || sub == 13) { for (int k = 0; k < 16; k++) emitByte(in[i++]); } // v128.const, i8x16.shuffle (16-byte literal / 16 lane indices)
        else if (sub <= 11 || (sub >= 84 && sub <= 93)) {           // memory-accessing SIMD:
            copyMemarg();                                           //   0..11  v128.load*/store*, load*_splat  (memarg)
            if (sub >= 84 && sub <= 91) emitByte(in[i++]);          //   84..91 v128.load/store{8,16,32,64}_lane (memarg + lane idx)
            // 92,93 v128.load32_zero/load64_zero are memarg-only
        }
        else if (sub >= 21 && sub <= 34) { emitByte(in[i++]); }     // 21..34 {i8x16..f64x2}.extract/replace_lane (one lane-index byte)
        // else: lane-wise arithmetic/compare/convert etc. -- no immediate
        return 0;
    }
    // 0xFB prefix is the GC proposal; our runtime builds with GC off, and a real
    // verifier must not use it. Fail loudly rather than mis-walk the stream.
    if (op == 0xfb) throw std::runtime_error("GC opcodes (0xfb) not supported");
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s in.wasm out.wasm\n", argv[0]); return 2; }
    FILE* f = fopen(argv[1], "rb"); if (!f) { perror(argv[1]); return 1; }
    Bytes in; { fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); in.resize(n); if (fread(in.data(), 1, n, f) != (size_t)n) return 1; fclose(f); }
    if (in.size() < 8 || in[0] != 0 || in[1] != 'a') { fprintf(stderr, "not a wasm\n"); return 1; }

    // Split sections.
    std::vector<Section> secs; size_t i = 8;
    while (i < in.size()) { uint8_t id = in[i++]; uint64_t len = readU(in, i); secs.push_back({id, Bytes(in.begin() + i, in.begin() + i + len)}); i += len; }

    auto find = [&](uint8_t id) -> Section* { for (auto& s : secs) if (s.id == id) return &s; return nullptr; };

    // --- type section: ensure a (i32,i32)->void type exists; record its index. ---
    Section* tsec = find(1);
    Bytes tbody = tsec ? tsec->body : Bytes{};
    uint32_t ntypes = 0; { size_t p = 0; if (!tbody.empty()) ntypes = (uint32_t)readU(tbody, p); }
    // Append the usegas type: func (0x60) 2 params i32,i32 (0x7f 0x7f) 0 results.
    uint32_t usegas_type = ntypes;
    { Bytes nb; putU(nb, ntypes + 1); size_t p = 0; if (!tbody.empty()) readU(tbody, p);
      nb.insert(nb.end(), tbody.begin() + p, tbody.end());
      nb.push_back(0x60); putU(nb, 2); nb.push_back(0x7f); nb.push_back(0x7f); putU(nb, 0);
      tbody = nb; }

    // --- import section: count func imports, append usegas as a func import. ---
    Section* isec = find(2);
    uint32_t nfunc_imports = 0, nglob_imports = 0;
    Bytes ibody;
    { Bytes old = isec ? isec->body : Bytes{}; size_t p = 0; uint32_t nimp = old.empty() ? 0 : (uint32_t)readU(old, p);
      size_t after_count = p;
      // scan to count func imports (they precede any defined func in the index space)
      // and global imports (the scratch global's index sits above imported globals).
      for (uint32_t k = 0; k < nimp; k++) {
          uint64_t ml = readU(old, p); p += ml; uint64_t nl = readU(old, p); p += nl;
          uint8_t kind = old[p++];
          if (kind == 0x00) { readU(old, p); nfunc_imports++; }
          else if (kind == 0x01) { p += 1; uint8_t fl = old[p++]; readU(old, p); if (fl) readU(old, p); } // table
          else if (kind == 0x02) { uint8_t fl = old[p++]; readU(old, p); if (fl) readU(old, p); }         // mem
          else if (kind == 0x03) { p += 2; nglob_imports++; }                                             // global
      }
      putU(ibody, nimp + 1);
      ibody.insert(ibody.end(), old.begin() + after_count, old.end());
      const char* mod = "metering"; const char* nm = "usegas";
      putU(ibody, strlen(mod)); ibody.insert(ibody.end(), mod, mod + strlen(mod));
      putU(ibody, strlen(nm));  ibody.insert(ibody.end(), nm, nm + strlen(nm));
      ibody.push_back(0x00); putU(ibody, usegas_type); }
    const uint32_t shift_at = nfunc_imports; // usegas takes this index; defined funcs shift +1

    // --- export section: remap func exports (kind 0x00). ---
    if (Section* esec = find(7)) { Bytes old = esec->body, nb; size_t p = 0; uint32_t n = (uint32_t)readU(old, p); putU(nb, n);
        for (uint32_t k = 0; k < n; k++) { uint64_t nl = readU(old, p); putU(nb, nl); nb.insert(nb.end(), old.begin() + p, old.begin() + p + nl); p += nl;
            uint8_t kind = old[p++]; nb.push_back(kind); uint64_t idx = readU(old, p);
            if (kind == 0x00 && idx >= shift_at) idx++;
            putU(nb, idx); }
        esec->body = nb; }

    // --- start section: remap. ---
    if (Section* ssec = find(8)) { Bytes old = ssec->body, nb; size_t p = 0; uint64_t idx = readU(old, p); if (idx >= shift_at) idx++; putU(nb, idx); ssec->body = nb; }

    // Copy a constant/init expression (instructions terminated by `end`), remapping
    // any ref.func inside via copyInstr.
    auto copyInitExpr = [&](const Bytes& old, size_t& p, Bytes& nb) {
        for (;;) { Bytes one; int kl; int cls = copyInstr(old, p, one, shift_at, kl); nb.insert(nb.end(), one.begin(), one.end()); if (cls == 3) break; }
    };
    auto remapIdx = [&](uint64_t idx) { return idx >= shift_at ? idx + 1 : idx; };

    // --- global section: remap ref.func in each global's init expr AND append a
    //     mutable i32 scratch global, used to read a bulk op's runtime size operand
    //     N off the stack so we can charge usegas(bulk_kind, N) and restore N for
    //     the bulk op itself. Its index sits above any imported + defined globals.
    bool made_global = false; Bytes glob_created; uint32_t scratch_idx = 0;
    { Section* gsec = find(6); Bytes old = gsec ? gsec->body : Bytes{}; size_t p = 0; uint32_t n = old.empty() ? 0 : (uint32_t)readU(old, p);
      Bytes nb; putU(nb, n + 1);
      for (uint32_t k = 0; k < n; k++) { nb.push_back(old[p++]); nb.push_back(old[p++]); copyInitExpr(old, p, nb); } // valtype, mut, init
      nb.push_back(0x7f); nb.push_back(0x01); nb.push_back(0x41); putS(nb, 0); nb.push_back(0x0b); // i32, mut, init=(i32.const 0) end
      scratch_idx = nglob_imports + n;
      if (gsec) gsec->body = nb; else { made_global = true; glob_created = nb; } }

    // --- elem section: remap function indices in every segment format (0-7). ---
    if (Section* elsec = find(9)) {
        Bytes old = elsec->body, nb; size_t p = 0; uint32_t n = (uint32_t)readU(old, p); putU(nb, n);
        for (uint32_t k = 0; k < n; k++) {
            uint32_t flag = (uint32_t)readU(old, p); putU(nb, flag);
            // Formats 0..7 (bit0=non-active, bit1=explicit tableidx/kind, bit2=elemexpr).
            if (flag == 2 || flag == 6) { uint64_t t = readU(old, p); putU(nb, t); } // explicit tableidx
            if (!(flag & 1)) copyInitExpr(old, p, nb);              // active (0,2,4,6): offset expr
            if (flag != 0 && flag != 4) nb.push_back(old[p++]);     // elemkind(1,2,3) / reftype(5,6,7) byte
            bool use_expr = (flag & 4) != 0;                        // 4-7: vec(elemexpr); 0-3: vec(funcidx)
            uint32_t cnt = (uint32_t)readU(old, p); putU(nb, cnt);
            for (uint32_t j = 0; j < cnt; j++) {
                if (use_expr) copyInitExpr(old, p, nb);            // ref.func remapped inside
                else { uint64_t fi = readU(old, p); putU(nb, remapIdx(fi)); }
            }
        }
        elsec->body = nb;
    }

    // --- code section: remap calls + insert per-class metering. ---
    Section* csec = find(10);
    if (csec) {
        Bytes old = csec->body, nb; size_t p = 0; uint32_t nfns = (uint32_t)readU(old, p); putU(nb, nfns);
        for (uint32_t fn = 0; fn < nfns; fn++) {
            uint64_t body_len = readU(old, p); size_t body_end = p + body_len;
            // locals declarations: copy verbatim.
            size_t body_start = p; uint64_t nloc = readU(old, p); Bytes locals; { for (uint64_t k = 0; k < nloc; k++) { readU(old, p); p++; } locals.assign(old.begin() + body_start, old.begin() + p); }
            // Instrument the instruction stream with a stack of block frames. Each
            // frame tallies its own (non-nested) instructions per count class.
            struct Frame { Bytes buf; uint32_t cnt[GC_COUNT_N] = {0}; };
            std::vector<Frame> st; st.push_back({});            // function-level frame
            bool fn_end = false;
            // Emit `usegas(class, count)` for each class with a nonzero tally: push
            // the class id, push the count, call usegas. usegas sits at index
            // shift_at (= the old func-import count), NOT 0 -- modules with existing
            // imports put it higher.
            auto charge = [shift_at](Bytes& dst, const uint32_t cnt[GC_COUNT_N]) {
                for (int cl = 0; cl < GC_COUNT_N; cl++) if (cnt[cl]) {
                    dst.push_back(0x41); putS(dst, (int64_t)cl);            // i32.const class
                    dst.push_back(0x41); putS(dst, (int64_t)cnt[cl]);       // i32.const count
                    dst.push_back(0x10); putU(dst, shift_at);              // call usegas
                }
            };
            while (p < body_end) {
                Bytes one; int kl; int cls = copyInstr(old, p, one, shift_at, kl);
                if (cls == 1) {            // block/loop/if opener: emit to current frame, push new body frame
                    st.back().buf.insert(st.back().buf.end(), one.begin(), one.end()); st.back().cnt[kl]++;
                    st.push_back({});
                } else if (cls == 2) {     // else: close then-arm, emit else, open else-arm
                    Frame body = st.back(); st.pop_back(); Bytes chg; charge(chg, body.cnt);
                    st.back().buf.insert(st.back().buf.end(), chg.begin(), chg.end());
                    st.back().buf.insert(st.back().buf.end(), body.buf.begin(), body.buf.end());
                    st.back().buf.insert(st.back().buf.end(), one.begin(), one.end());
                    st.push_back({});
                } else if (cls == 3) {     // end: close current body, prepend its charge, splice into parent
                    Frame body = st.back(); st.pop_back();
                    if (st.empty()) {      // function end
                        Bytes chg; charge(chg, body.cnt);
                        st.push_back({}); st.back().buf.insert(st.back().buf.end(), chg.begin(), chg.end());
                        st.back().buf.insert(st.back().buf.end(), body.buf.begin(), body.buf.end());
                        st.back().buf.insert(st.back().buf.end(), one.begin(), one.end());
                        fn_end = true;
                        break;
                    }
                    Bytes chg; charge(chg, body.cnt);
                    st.back().buf.insert(st.back().buf.end(), chg.begin(), chg.end());
                    st.back().buf.insert(st.back().buf.end(), body.buf.begin(), body.buf.end());
                    st.back().buf.insert(st.back().buf.end(), one.begin(), one.end());
                } else if (kl >= GC_BULK_MEM && kl <= GC_BULK_TABLE) {
                    // Data-dependent bulk op: charge usegas(bulk_kind, N) where N is
                    // the size operand on top of the stack, then restore N for the op.
                    // (The `kl >= GC_BULK_MEM` lower bound is essential: count classes
                    // are all < GC_BULK_MEM, so none is ever mistaken for a bulk op.)
                    Bytes& b = st.back().buf;
                    b.push_back(0x24); putU(b, scratch_idx);   // global.set $tmp  (pop N)
                    b.push_back(0x41); putS(b, (int64_t)kl);   // i32.const bulk_kind
                    b.push_back(0x23); putU(b, scratch_idx);   // global.get $tmp  (push N as arg)
                    b.push_back(0x10); putU(b, shift_at);      // call usegas(kind, N)
                    b.push_back(0x23); putU(b, scratch_idx);   // global.get $tmp  (restore N)
                    b.insert(b.end(), one.begin(), one.end()); // the bulk op
                } else {
                    st.back().buf.insert(st.back().buf.end(), one.begin(), one.end()); st.back().cnt[kl]++;
                }
            }
            if (!fn_end || p != body_end)
                throw std::runtime_error("instruction-walk desync in function " + std::to_string(fn) +
                                         " (unhandled opcode immediate?)");
            Bytes code = st.back().buf;
            Bytes newbody; newbody.insert(newbody.end(), locals.begin(), locals.end());
            newbody.insert(newbody.end(), code.begin(), code.end());
            putU(nb, newbody.size()); nb.insert(nb.end(), newbody.begin(), newbody.end());
            p = body_end;
        }
        csec->body = nb;
    }

    // --- reassemble, inserting type/import/global sections if they were absent ---
    if (tsec) tsec->body = tbody;
    if (isec) isec->body = ibody;
    Bytes out = {0,'a','s','m',1,0,0,0};
    bool wrote_type = tsec != nullptr, wrote_imp = isec != nullptr, wrote_glob = !made_global;
    auto emitSec = [&](uint8_t id, const Bytes& body){ out.push_back(id); putU(out, body.size()); out.insert(out.end(), body.begin(), body.end()); };
    // Ensure type(1), import(2) and global(6) exist and land in id order.
    std::vector<Section> outsecs;
    for (auto& s : secs) {
        if (!wrote_type && s.id > 1) { outsecs.push_back({1, tbody}); wrote_type = true; }
        if (!wrote_imp && s.id > 2) { outsecs.push_back({2, ibody}); wrote_imp = true; }
        if (!wrote_glob && s.id > 6) { outsecs.push_back({6, glob_created}); wrote_glob = true; }
        outsecs.push_back(s);
    }
    if (!wrote_type) outsecs.push_back({1, tbody});
    if (!wrote_imp) outsecs.push_back({2, ibody});
    if (!wrote_glob) outsecs.push_back({6, glob_created});
    for (auto& s : outsecs) emitSec(s.id, s.body);

    FILE* o = fopen(argv[2], "wb"); if (!o) { perror(argv[2]); return 1; }
    fwrite(out.data(), 1, out.size(), o); fclose(o);
    fprintf(stderr, "instrumented: %zu -> %zu bytes, usegas import idx %u, %u func imports, scratch global %u\n",
            in.size(), out.size(), shift_at, nfunc_imports, scratch_idx);
    return 0;
}
