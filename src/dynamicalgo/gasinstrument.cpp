// Dynamic-algo gas instrumenter (offline tool, doc sec 8.6/8.8).
//
// Rewrites a freestanding verifier .wasm so it charges gas: it imports
// metering.usegas(i32) and, at the top of every structured block body (function
// entry, and each block/loop/if/else body), calls usegas(N) where N is the count
// of that body's own (non-nested) instructions. A loop body's charge re-executes
// each iteration, so total gas tracks total instructions executed -- a
// deterministic CPU bound. Charging a whole block on entry (even if an inner
// branch skips part of it) only ever OVER-charges, which is safe.
//
// v1 cost model: 1 per instruction (uniform). Weighting (memory/float heavier)
// and the per-function structural caps (doc 8.8) are follow-ups.
//
// Usage: gas_instrument in.wasm out.wasm
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

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

// ---- one instruction: copy + remap + classify -----------------------------
//
// A wasm instruction is one opcode byte followed by zero or more *immediate*
// operands baked into the bytecode (indices, memory align/offset, constants,
// block signatures, ...). To rewrite code correctly we must know each opcode's
// immediate layout so we can (a) copy the instruction faithfully, (b) advance
// past exactly its bytes -- getting this wrong desyncs the whole stream -- (c)
// spot the control-flow ops that delimit basic blocks for metering, and (d)
// bump the function references (`call`, `ref.func`) that the new usegas import
// shifted. The 0xFC and 0xFD prefixes each introduce a second "sub-opcode"
// (a LEB) that selects a bulk-memory/table or SIMD instruction respectively.
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
// inserted at index shift_at). Returns the opcode's structural class, which
// drives the per-block metering in main():
//   0 = ordinary,  1 = block/loop/if opener,  2 = else,  3 = end
static int copyInstr(const Bytes& in, size_t& i, Bytes& out, uint32_t shift_at) {
    uint8_t op = in[i++];
    auto emitByte = [&](uint8_t b){ out.push_back(b); };
    auto copyU = [&]{ uint64_t v = readU(in, i); putU(out, v); };
    auto copyS = [&]{ int64_t v = readS(in, i); putS(out, v); };
    auto copyMemarg = [&]{ copyU(); copyU(); }; // align, offset
    auto copyBlockType = [&]{ int64_t v = readS(in, i); putS(out, v); }; // s33
    emitByte(op);
    switch (op) {
        // -- control flow. block/loop/if carry a "block type" (an s33: 0x40 empty,
        //    a value type, or a type index) and open a new block => class 1. else
        //    (0x05) splits an if => class 2; end (0x0b) closes a block => class 3.
        case 0x00: return 0;                                       // unreachable
        case 0x01: return 0;                                       // nop
        case 0x02: case 0x03: case 0x04: copyBlockType(); return 1; // block, loop, if
        case 0x05: return 2;                                        // else
        case 0x0b: return 3;                                        // end
        case 0x0c: case 0x0d: copyU(); return 0;                   // br, br_if      (label idx)
        case 0x0e: { uint64_t n = readU(in, i); putU(out, n); for (uint64_t k = 0; k <= n; k++) copyU(); return 0; } // br_table (vec(label)+default)
        case 0x0f: return 0;                                       // return
        case 0x10: { uint64_t f = readU(in, i); if (f >= shift_at) f++; putU(out, f); return 0; } // call (func idx -- REMAP)
        case 0x11: copyU(); copyU(); return 0;                     // call_indirect (type idx, table idx -- neither is a func idx)
        // -- parametric
        case 0x1a: case 0x1b: return 0;                            // drop, select
        case 0x1c: { uint64_t n = readU(in, i); putU(out, n); for (uint64_t k = 0; k < n; k++) emitByte(in[i++]); return 0; } // select t* (vec(valtype))
        // -- variable / table accessors (one index each)
        case 0x20: case 0x21: case 0x22: copyU(); return 0;        // local.get/set/tee
        case 0x23: case 0x24: copyU(); return 0;                   // global.get/set
        case 0x25: case 0x26: copyU(); return 0;                   // table.get/set
        // -- memory size/grow take a single memory-index byte
        case 0x3f: case 0x40: emitByte(in[i++]); return 0;         // memory.size, memory.grow
        // -- constants
        case 0x41: case 0x42: copyS(); return 0;                   // i32.const, i64.const (signed LEB)
        case 0x43: for (int k = 0; k < 4; k++) emitByte(in[i++]); return 0; // f32.const (4 raw bytes)
        case 0x44: for (int k = 0; k < 8; k++) emitByte(in[i++]); return 0; // f64.const (8 raw bytes)
        // -- reference types
        case 0xd0: copyU(); return 0;                              // ref.null t (reftype)
        case 0xd1: return 0;                                       // ref.is_null
        case 0xd2: { uint64_t f = readU(in, i); if (f >= shift_at) f++; putU(out, f); return 0; } // ref.func (func idx -- REMAP)
        default: break;
    }
    // Memory load/store family (i32.load .. i64.store32): each takes a "memarg"
    // (align LEB + offset LEB).
    if (op >= 0x28 && op <= 0x3e) { copyMemarg(); return 0; }
    // Numeric/comparison/conversion ops (i32.eqz .. i64.extend32_s): opcode only.
    if (op >= 0x45 && op <= 0xc4) return 0;
    // 0xFC prefix: saturating float->int truncation (sub 0..7, no immediate) plus
    // the bulk memory/table ops (sub 8..17). Sub-opcode is a LEB.
    if (op == 0xfc) {
        uint64_t sub = readU(in, i); putU(out, sub);
        switch (sub) {
            case 8:  copyU(); emitByte(in[i++]); break;            // memory.init (data idx, mem idx)
            case 9:  copyU(); break;                               // data.drop   (data idx)
            case 10: emitByte(in[i++]); emitByte(in[i++]); break;  // memory.copy (dst mem, src mem)
            case 11: emitByte(in[i++]); break;                     // memory.fill (mem idx)
            case 12: copyU(); copyU(); break;                      // table.init  (elem idx, table idx)
            case 13: copyU(); break;                               // elem.drop   (elem idx)
            case 14: copyU(); copyU(); break;                      // table.copy  (dst table, src table)
            case 15: case 16: case 17: copyU(); break;             // table.grow/size/fill (table idx)
            default: break;                                        // 0..7 = i32/i64.trunc_sat_f32/f64_s/u: no immediate
        }
        return 0;
    }
    // 0xFD prefix: fixed-width SIMD (v128). Sub-opcode is a LEB; only these carry
    // immediates, everything else (lane arithmetic, comparisons, ...) is bare.
    if (op == 0xfd) {
        uint64_t sub = readU(in, i); putU(out, sub);
        if (sub == 12 || sub == 13) { for (int k = 0; k < 16; k++) emitByte(in[i++]); } // v128.const, i8x16.shuffle (16-byte literal / 16 lane indices)
        else if (sub <= 11 || (sub >= 84 && sub <= 93)) {          // memory-accessing SIMD:
            copyMemarg();                                          //   0..11  v128.load*/store*, load*_splat  (memarg)
            if (sub >= 84 && sub <= 91) emitByte(in[i++]);         //   84..91 v128.load/store{8,16,32,64}_lane (memarg + lane idx)
            // 92,93 v128.load32_zero/load64_zero are memarg-only
        }
        else if (sub >= 21 && sub <= 34) { emitByte(in[i++]); }    // 21..34 {i8x16..f64x2}.extract/replace_lane (one lane-index byte)
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

    // --- type section: ensure a (i32)->void type exists; record its index. ---
    Section* tsec = find(1);
    Bytes tbody = tsec ? tsec->body : Bytes{};
    uint32_t ntypes = 0; { size_t p = 0; if (!tbody.empty()) ntypes = (uint32_t)readU(tbody, p); }
    // Append the usegas type: func (0x60) 1 param i32 (0x7f) 0 results.
    uint32_t usegas_type = ntypes;
    { Bytes nb; putU(nb, ntypes + 1); size_t p = 0; if (!tbody.empty()) readU(tbody, p);
      nb.insert(nb.end(), tbody.begin() + p, tbody.end());
      nb.push_back(0x60); putU(nb, 1); nb.push_back(0x7f); putU(nb, 0);
      tbody = nb; }

    // --- import section: count func imports, append usegas as a func import. ---
    Section* isec = find(2);
    uint32_t nfunc_imports = 0;
    Bytes ibody;
    { Bytes old = isec ? isec->body : Bytes{}; size_t p = 0; uint32_t nimp = old.empty() ? 0 : (uint32_t)readU(old, p);
      size_t after_count = p;
      // scan to count func imports
      for (uint32_t k = 0; k < nimp; k++) {
          uint64_t ml = readU(old, p); p += ml; uint64_t nl = readU(old, p); p += nl;
          uint8_t kind = old[p++];
          if (kind == 0x00) { readU(old, p); nfunc_imports++; }
          else if (kind == 0x01) { p += 1; uint8_t fl = old[p++]; readU(old, p); if (fl) readU(old, p); } // table
          else if (kind == 0x02) { uint8_t fl = old[p++]; readU(old, p); if (fl) readU(old, p); }         // mem
          else if (kind == 0x03) { p += 2; }                                                              // global
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
            if (kind == 0x00 && idx >= shift_at) idx++; putU(nb, idx); }
        esec->body = nb; }

    // --- start section: remap. ---
    if (Section* ssec = find(8)) { Bytes old = ssec->body, nb; size_t p = 0; uint64_t idx = readU(old, p); if (idx >= shift_at) idx++; putU(nb, idx); ssec->body = nb; }

    // Copy a constant/init expression (instructions terminated by `end`), remapping
    // any ref.func inside via copyInstr.
    auto copyInitExpr = [&](const Bytes& old, size_t& p, Bytes& nb) {
        for (;;) { Bytes one; int cls = copyInstr(old, p, one, shift_at); nb.insert(nb.end(), one.begin(), one.end()); if (cls == 3) break; }
    };
    auto remapIdx = [&](uint64_t idx) { return idx >= shift_at ? idx + 1 : idx; };

    // --- global section: remap ref.func in each global's init expr. ---
    if (Section* gsec = find(6)) {
        Bytes old = gsec->body, nb; size_t p = 0; uint32_t n = (uint32_t)readU(old, p); putU(nb, n);
        for (uint32_t k = 0; k < n; k++) { nb.push_back(old[p++]); nb.push_back(old[p++]); copyInitExpr(old, p, nb); } // valtype, mut, init
        gsec->body = nb;
    }

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

    // --- code section: remap calls + insert metering. ---
    Section* csec = find(10);
    if (csec) {
        Bytes old = csec->body, nb; size_t p = 0; uint32_t nfns = (uint32_t)readU(old, p); putU(nb, nfns);
        for (uint32_t fn = 0; fn < nfns; fn++) {
            uint64_t body_len = readU(old, p); size_t body_end = p + body_len;
            // locals declarations: copy verbatim.
            size_t body_start = p; uint64_t nloc = readU(old, p); Bytes locals; { size_t ls = p; for (uint64_t k = 0; k < nloc; k++) { readU(old, p); p++; } locals.assign(old.begin() + body_start, old.begin() + p); (void)ls; }
            // Instrument the instruction stream with a stack of block frames.
            struct Frame { Bytes buf; uint32_t count = 0; };
            std::vector<Frame> st; st.push_back({});            // function-level frame
            bool fn_end = false;
            // i32.const cost; call <usegas>. usegas sits at index shift_at (= the old
            // func-import count), NOT 0 -- modules with existing imports put it higher.
            auto charge = [shift_at](Bytes& dst, uint32_t cost){ if (!cost) return; dst.push_back(0x41); putS(dst, (int64_t)cost); dst.push_back(0x10); putU(dst, shift_at); };
            while (p < body_end) {
                Bytes one; int cls = copyInstr(old, p, one, shift_at);
                if (cls == 1) {            // block/loop/if opener: emit to current frame, push new body frame
                    st.back().buf.insert(st.back().buf.end(), one.begin(), one.end()); st.back().count++;
                    st.push_back({});
                } else if (cls == 2) {     // else: close then-arm, emit else, open else-arm
                    Frame body = st.back(); st.pop_back(); Bytes chg; charge(chg, body.count);
                    st.back().buf.insert(st.back().buf.end(), chg.begin(), chg.end());
                    st.back().buf.insert(st.back().buf.end(), body.buf.begin(), body.buf.end());
                    st.back().buf.insert(st.back().buf.end(), one.begin(), one.end());
                    st.push_back({});
                } else if (cls == 3) {     // end: close current body, prepend its charge, splice into parent
                    Frame body = st.back(); st.pop_back();
                    if (st.empty()) {      // function end
                        Bytes chg; charge(chg, body.count);
                        st.push_back({}); st.back().buf.insert(st.back().buf.end(), chg.begin(), chg.end());
                        st.back().buf.insert(st.back().buf.end(), body.buf.begin(), body.buf.end());
                        st.back().buf.insert(st.back().buf.end(), one.begin(), one.end());
                        fn_end = true;
                        break;
                    }
                    Bytes chg; charge(chg, body.count);
                    st.back().buf.insert(st.back().buf.end(), chg.begin(), chg.end());
                    st.back().buf.insert(st.back().buf.end(), body.buf.begin(), body.buf.end());
                    st.back().buf.insert(st.back().buf.end(), one.begin(), one.end());
                } else {
                    st.back().buf.insert(st.back().buf.end(), one.begin(), one.end()); st.back().count++;
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

    // --- reassemble, inserting type/import sections if they were absent ---
    if (tsec) tsec->body = tbody;
    if (isec) isec->body = ibody;
    Bytes out = {0,'a','s','m',1,0,0,0};
    bool wrote_type = tsec != nullptr, wrote_imp = isec != nullptr;
    auto emitSec = [&](uint8_t id, const Bytes& body){ out.push_back(id); putU(out, body.size()); out.insert(out.end(), body.begin(), body.end()); };
    // Ensure type(1) and import(2) exist and land in id order.
    std::vector<Section> outsecs;
    for (auto& s : secs) {
        if (!wrote_type && s.id > 1) { outsecs.push_back({1, tbody}); wrote_type = true; }
        if (!wrote_imp && s.id > 2) { outsecs.push_back({2, ibody}); wrote_imp = true; }
        outsecs.push_back(s);
    }
    if (!wrote_type) outsecs.push_back({1, tbody});
    if (!wrote_imp) outsecs.push_back({2, ibody});
    for (auto& s : outsecs) emitSec(s.id, s.body);

    FILE* o = fopen(argv[2], "wb"); if (!o) { perror(argv[2]); return 1; }
    fwrite(out.data(), 1, out.size(), o); fclose(o);
    fprintf(stderr, "instrumented: %zu -> %zu bytes, usegas import idx %u, %u func imports\n", in.size(), out.size(), shift_at, nfunc_imports);
    return 0;
}
