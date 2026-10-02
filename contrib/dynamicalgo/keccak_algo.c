// Keccak-256 dynamic-algo verifier (Bitmark). Same ABI as whirlpool_algo.c: the
// pushed wasm module IS the PoW verifier.
//
//   verify(anchor_hash, payout, payout_len, nbits, nonce, nonce_len, out_ab)
//
// returns 0 if Keccak256(anchor_hash||payout||nonce) meets the nBits target, else 1,
// and writes the reward fractions alpha,beta as two little-endian u32 in Q32 fixed
// point (value = u32 / 2^32; whole u32 range is [0,1)): valid solution =>
// alpha=beta=0.5 (0x80000000); no valid solution => alpha=0 (no dynamic miner to
// pay), beta=0.5 (constant here). See doc/dynamic-algo-mining.md sec 3-4.
// Integer-only / deterministic / freestanding.
//
// This is a PURE HASH-POW algo: it is stateless and ignores the chain entirely, so
// it imports nothing but is still a complete reference for the ABI's money path.
// An algo that needs earlier blocks of its own mPoW slot (a multi-block/streaming
// algo) fetches them on demand through the chain.* imports -- see sec 3.1 and the
// commented idiom at the bottom of this file. Those fetches are metered by their own
// per-call budgets (sec 8.7), so the window is reachable, not free.
//
// ABI NOTE (2026-09-30): verify() previously also took `txs, txs_len` (the current
// block's non-coinbase txs) and `last_n_blocks, last_n_len`. Both are gone. The tx
// input was circular -- the solution lives in a tx inside the block, so the tx set
// would determine the solution and the solution would be part of the tx set, and any
// pool reshuffling the block would silently invalidate an already-computed solution.
// The prior-blocks buffer became the chain.* imports because the window is up to
// 32850 blocks, far too much to marshal per call.
//
// This is the ORIGINAL Keccak-256 (padding byte 0x01, as used by Ethereum), not
// NIST SHA3-256 (which pads 0x06). Validated against known Keccak-256 vectors.

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

// ---- Keccak-f[1600] permutation --------------------------------------------
#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const u64 RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
static const int RHO[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
static const int PI[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                           15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

static void keccakf(u64 s[25]) {
    for (int r = 0; r < 24; r++) {
        u64 bc[5], t;
        for (int i = 0; i < 5; i++) bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20]; // theta
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) s[j + i] ^= t;
        }
        t = s[1]; // rho + pi
        for (int i = 0; i < 24; i++) {
            int j = PI[i];
            u64 tmp = s[j];
            s[j] = ROTL64(t, RHO[i]);
            t = tmp;
        }
        for (int j = 0; j < 25; j += 5) { // chi
            for (int i = 0; i < 5; i++) bc[i] = s[j + i];
            for (int i = 0; i < 5; i++) s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        s[0] ^= RC[r]; // iota
    }
}

// Keccak-256: rate 1088 bits (136 bytes), capacity 512, 32-byte output. State
// lanes are little-endian, so bytes are XOR'd/read directly (targets are LE:
// x86 for the native test, wasm32 for the module).
#define RATE 136
__attribute__((export_name("keccak256")))
void keccak256(const u8 *in, u64 len, u8 *out) {
    u64 s[25];
    for (int i = 0; i < 25; i++) s[i] = 0;
    u8 *sb = (u8 *)s;

    u64 pos = 0;
    while (len - pos >= (u64)RATE) {
        for (int i = 0; i < RATE; i++) sb[i] ^= in[pos + i];
        keccakf(s);
        pos += RATE;
    }
    u8 block[RATE];
    u64 rem = len - pos;
    for (u64 i = 0; i < rem; i++) block[i] = in[pos + i];
    for (u64 i = rem; i < RATE; i++) block[i] = 0;
    block[rem] ^= 0x01;       // Keccak padding (SHA3 would be 0x06)
    block[RATE - 1] ^= 0x80;
    for (int i = 0; i < RATE; i++) sb[i] ^= block[i];
    keccakf(s);

    for (int i = 0; i < 32; i++) out[i] = sb[i];
}

// ---- nBits (Bitcoin compact) -> 32-byte big-endian target ------------------
static void set_be(u8 t[32], int idx, u8 v) { if (idx >= 0 && idx < 32) t[idx] = v; }
static void target_from_nbits(u32 nbits, u8 t[32]) {
    for (int i = 0; i < 32; i++) t[i] = 0;
    u32 exp = nbits >> 24;
    u32 mant = nbits & 0x007fffff;
    int lsb = 34 - (int)exp;
    set_be(t, lsb, (u8)(mant & 0xff));
    set_be(t, lsb - 1, (u8)((mant >> 8) & 0xff));
    set_be(t, lsb - 2, (u8)((mant >> 16) & 0xff));
}

// ---- reward fractions ---------------------------------------------------------
// out_ab holds alpha then beta as little-endian u32 in Q32 fixed point (value*2^32,
// so 0.5 = 0x80000000, 0.0 = 0). Node reward math is pure integer; the whole u32
// range maps to [0,1) so 0<=alpha,beta<1 is automatic.
static void put_u32le(u8 *p, u32 v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_ab(u8 *out_ab, int solution_valid) {
    put_u32le(out_ab,     solution_valid ? 0x80000000u : 0u); // alpha: 0.5 or 0
    put_u32le(out_ab + 4, 0x80000000u);                       // beta: 0.5 (constant)
}

// ---- dynamic-algo verifier -------------------------------------------------
#define PREIMAGE_MAX 4096
__attribute__((export_name("verify")))
int verify(const u8 *anchor_hash,
           const u8 *payout, u32 payout_len,
           u32 nbits,
           const u8 *nonce, u32 nonce_len,
           u8 *out_ab) {           // OUT: alpha(u32 Q32) || beta(u32 Q32), LE
    put_ab(out_ab, 0);                  // default: no valid solution (alpha=0, beta=0.5)

    u64 total = (u64)32 + payout_len + nonce_len;
    if (total > PREIMAGE_MAX) return 1;
    u8 buf[PREIMAGE_MAX];
    u64 o = 0;
    for (int k = 0; k < 32; k++) buf[o++] = anchor_hash[k];
    for (u32 k = 0; k < payout_len; k++) buf[o++] = payout[k];
    for (u32 k = 0; k < nonce_len; k++) buf[o++] = nonce[k];

    u8 digest[32];
    keccak256(buf, total, digest);
    u8 target[32];
    target_from_nbits(nbits, target);
    int meets = 1;                       // all-equal => meets target
    for (int i = 0; i < 32; i++) {
        if (digest[i] < target[i]) { meets = 1; break; }
        if (digest[i] > target[i]) { meets = 0; break; }
    }
    if (meets) put_ab(out_ab, 1);        // valid solution => alpha=beta=0.5
    return meets ? 0 : 1;
}

// ---- chain access: reference idiom (not used by keccak) --------------------
// A multi-block algo reads earlier blocks of its OWN mPoW slot on demand. Declare
// the two host functions as wasm imports (clang emits a proper module/name import
// from these attributes, so no libc and no --allow-undefined are needed):
//
//   __attribute__((import_module("chain"), import_name("slot_block_count")))
//   extern int chain_slot_block_count(void);
//
//   __attribute__((import_module("chain"), import_name("slot_block")))
//   extern int chain_slot_block(int index, void *ptr, int cap);
//
// Then, with index 0 == the newest slot block below this one:
//
//   static u8 blk[MAX_BLOCK_SERIALIZED_SIZE];   // one fetch per block, never -3
//   int n = chain_slot_block_count();           // free; <= 32850, smaller early on
//   for (int i = 0; i < n && i < MY_WINDOW; i++) {
//       int sz = chain_slot_block(i, blk, (int)sizeof(blk));
//       if (sz < 0) break;                      // -1 no such block, -2 bad addr,
//                                               // -3 cap too small
//       /* parse blk[0..sz): 80-byte header, then the tx list; scan the txs'
//          outputs for OP_SOLUTION chunks exactly as the node does. Bytes are the
//          TX_NO_WITNESS serialization -- the one unconditional framing. */
//   }
//
// BUDGETS (sec 8.7): 1024 fetches and 256 MiB per verify() call, whichever binds
// first. The call is charged BEFORE the index lookup, so probing past the end is
// not free. Exceeding either traps like any other gas overrun. These caps are far
// below the 32850-block window ON PURPOSE: reading the whole window every block
// would be minutes of disk I/O. An algo whose state is the fold of ALL history
// cannot re-derive it here -- it must receive it pre-folded (checkpoint epochs or
// node-held state; still an open item, sec 9).

#ifdef WASM_SELFTEST
static const u8 ABC[32] = { // keccak256("abc")
 0x4e,0x03,0x65,0x7a,0xea,0x45,0xa9,0x4f,0xc7,0xd4,0x7b,0xa8,0x26,0xc8,0xd6,0x67,
 0xc0,0xd1,0xe6,0xe3,0x3a,0x64,0xa0,0x36,0xec,0x44,0xf5,0x8f,0xa1,0x2d,0x6c,0x45 };
__attribute__((export_name("selftest")))
int selftest(void) {
    u8 out[32];
    const u8 msg[3] = {'a', 'b', 'c'};
    keccak256(msg, 3, out);
    for (int i = 0; i < 32; i++) if (out[i] != ABC[i]) return 1;
    u8 anchor[32]; for (int i = 0; i < 32; i++) anchor[i] = (u8)i;
    const u8 payout[3] = {0x6a, 0x00, 0x00};
    const u8 nonce[8] = {0};
    u8 ab[8];
    if (verify(anchor, payout, 3, 0x03000001, nonce, 8, ab) != 1) return 2;
    if (ab[0] || ab[1] || ab[2] || ab[3]) return 4;                                   // alpha == 0 on fail
    if (verify(anchor, payout, 3, 0x2100ffff, nonce, 8, ab) != 0) return 3;
    if (ab[3] != 0x80 || ab[0] || ab[1] || ab[2]) return 5;                           // alpha == 0.5 (0x80000000) on pass
    if (ab[7] != 0x80 || ab[4] || ab[5] || ab[6]) return 6;                           // beta == 0.5 (0x80000000)
    return 0;
}
#endif

#ifdef TEST
#include <stdio.h>
#include <string.h>
static void show(const char *label, const u8 *d, int n) {
    printf("%-6s ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}
int main(void) {
    u8 out[32];
    keccak256((const u8 *)"", 0, out);   show("''", out, 32);
    keccak256((const u8 *)"abc", 3, out); show("abc", out, 32);
    keccak256((const u8 *)"The quick brown fox jumps over the lazy dog", 43, out); show("fox", out, 32);
    // expected (Keccak-256):
    // ''  c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    // abc 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    // fox 4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15
    return 0;
}
#endif
