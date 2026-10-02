// Whirlpool dynamic-algo verifier (Bitmark). The pushed wasm module IS the PoW
// verifier:
//
//   verify(anchor_hash, payout, payout_len, nbits, nonce, nonce_len, out_ab)
//
// returns 0 if Whirlpool(anchor_hash||payout||nonce) meets the nBits target, else 1.
// It also writes the reward fractions alpha,beta as two little-endian
// u32 in Q32 fixed point (value = u32 / 2^32, so the whole u32 range is [0,1)):
// a valid solution => alpha=beta=0.5 (the classic r/2 // r/4 split); no valid solution
// => alpha=0 (no dynamic miner to pay), beta=0.5 (constant here). 0.5 = 0x80000000.
// See doc/dynamic-algo-mining.md sec 3-4. Integer-only / deterministic / freestanding.
// The Whirlpool core is validated against known test vectors (see whirlpool.c).
//
// Like keccak_algo.c this is a PURE HASH-POW algo: stateless, ignoring the chain, so
// it imports nothing. A multi-block algo instead pulls its own slot's earlier blocks
// through the chain.* imports -- see sec 3.1 and the idiom at the end of
// keccak_algo.c.
//
// ABI NOTE (2026-09-30): verify() previously also took `txs, txs_len` and
// `last_n_blocks, last_n_len`. The tx input was circular (the solution lives in a tx
// inside the block, so the tx set would determine the solution and vice versa), and
// the prior-blocks buffer became imports because the window is up to 32850 blocks.

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

// ---- Whirlpool core (identical to the vector-validated whirlpool.c) ----------
static const u8 SBOX[256] = {
 0x18,0x23,0xc6,0xE8,0x87,0xB8,0x01,0x4F,0x36,0xA6,0xd2,0xF5,0x79,0x6F,0x91,0x52,
 0x60,0xBc,0x9B,0x8E,0xA3,0x0C,0x7B,0x35,0x1D,0xE0,0xD7,0xC2,0x2E,0x4B,0xFE,0x57,
 0x15,0x77,0x37,0xE5,0x9F,0xF0,0x4A,0xDA,0x58,0xC9,0x29,0x0A,0xB1,0xA0,0x6B,0x85,
 0xBD,0x5D,0x10,0xF4,0xCB,0x3E,0x05,0x67,0xE4,0x27,0x41,0x8B,0xA7,0x7D,0x95,0xD8,
 0xFB,0xEE,0x7C,0x66,0xDD,0x17,0x47,0x9E,0xCA,0x2D,0xBF,0x07,0xAD,0x5A,0x83,0x33,
 0x63,0x02,0xAA,0x71,0xC8,0x19,0x49,0xD9,0xF2,0xE3,0x5B,0x88,0x9A,0x26,0x32,0xB0,
 0xE9,0x0F,0xD5,0x80,0xBE,0xCD,0x34,0x48,0xFF,0x7A,0x90,0x5F,0x20,0x68,0x1A,0xAE,
 0xB4,0x54,0x93,0x22,0x64,0xF1,0x73,0x12,0x40,0x08,0xC3,0xEC,0xDB,0xA1,0x8D,0x3D,
 0x97,0x00,0xCF,0x2B,0x76,0x82,0xD6,0x1B,0xB5,0xAF,0x6A,0x50,0x45,0xF3,0x30,0xEF,
 0x3F,0x55,0xA2,0xEA,0x65,0xBA,0x2F,0xC0,0xDE,0x1C,0xFD,0x4D,0x92,0x75,0x06,0x8A,
 0xB2,0xE6,0x0E,0x1F,0x62,0xD4,0xA8,0x96,0xF9,0xC5,0x25,0x59,0x84,0x72,0x39,0x4C,
 0x5E,0x78,0x38,0x8C,0xD1,0xA5,0xE2,0x61,0xB3,0x21,0x9C,0x1E,0x43,0xC7,0xFC,0x04,
 0x51,0x99,0x6D,0x0D,0xFA,0xDF,0x7E,0x24,0x3B,0xAB,0xCE,0x11,0x8F,0x4E,0xB7,0xEB,
 0x3C,0x81,0x94,0xF7,0xB9,0x13,0x2C,0xD3,0xE7,0x6E,0xC4,0x03,0x56,0x44,0x7F,0xA9,
 0x2A,0xBB,0xC1,0x53,0xDC,0x0B,0x9D,0x6C,0x31,0x74,0xF6,0x46,0xAC,0x89,0x14,0xE1,
 0x16,0x3A,0x69,0x09,0x70,0xB6,0xD0,0xED,0xCC,0x42,0x98,0xA4,0x28,0x5C,0xF8,0x86
};
static const int CIR[8] = {1,1,4,1,8,5,2,9};
static u8 xt(u8 a) { return (u8)((a << 1) ^ ((a & 0x80) ? 0x1d : 0)); }
static u8 gm(u8 a, int c) {
    switch (c) {
        case 1: return a; case 2: return xt(a); case 4: return xt(xt(a));
        case 5: return (u8)(xt(xt(a)) ^ a); case 8: return xt(xt(xt(a)));
        case 9: return (u8)(xt(xt(xt(a))) ^ a);
    }
    return 0;
}
static void rho(const u8 a[8][8], u8 out[8][8]) {
    u8 t[8][8], p[8][8];
    for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) t[i][j] = SBOX[a[i][j]];
    for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) p[i][j] = t[(i - j) & 7][j];
    for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) {
        u8 s = 0;
        for (int k = 0; k < 8; k++) s ^= gm(p[i][k], CIR[(j - k) & 7]);
        out[i][j] = s;
    }
}
static void compress(u8 H[8][8], const u8 m[8][8]) {
    u8 key[8][8], st[8][8], tmp[8][8];
    for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) { key[i][j] = H[i][j]; st[i][j] = m[i][j] ^ H[i][j]; }
    for (int r = 1; r <= 10; r++) {
        rho(key, tmp);
        for (int j = 0; j < 8; j++) tmp[0][j] ^= SBOX[8 * (r - 1) + j];
        for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) key[i][j] = tmp[i][j];
        rho(st, tmp);
        for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) st[i][j] = tmp[i][j] ^ key[i][j];
    }
    for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) H[i][j] ^= st[i][j] ^ m[i][j];
}
__attribute__((export_name("whirlpool")))
void whirlpool(const u8 *in, u64 len, u8 *out) {
    u8 H[8][8];
    for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) H[i][j] = 0;
    u64 bitlen = len * 8, pos = 0;
    u8 block[64];
    while (len - pos >= 64) {
        u8 m[8][8];
        for (int k = 0; k < 64; k++) m[k >> 3][k & 7] = in[pos + k];
        compress(H, m); pos += 64;
    }
    u64 rem = len - pos;
    for (u64 k = 0; k < rem; k++) block[k] = in[pos + k];
    block[rem] = 0x80;
    for (u64 k = rem + 1; k < 64; k++) block[k] = 0;
    if (rem >= 32) {
        u8 m[8][8];
        for (int k = 0; k < 64; k++) m[k >> 3][k & 7] = block[k];
        compress(H, m);
        for (int k = 0; k < 64; k++) block[k] = 0;
    }
    for (int k = 0; k < 8; k++) block[56 + k] = (u8)(bitlen >> (56 - 8 * k));
    {
        u8 m[8][8];
        for (int k = 0; k < 64; k++) m[k >> 3][k & 7] = block[k];
        compress(H, m);
    }
    for (int k = 0; k < 64; k++) out[k] = H[k >> 3][k & 7];
}

// ---- nBits (Bitcoin compact) -> 32-byte big-endian target --------------------
static void set_be(u8 t[32], int idx, u8 v) { if (idx >= 0 && idx < 32) t[idx] = v; }
static void target_from_nbits(u32 nbits, u8 t[32]) {
    for (int i = 0; i < 32; i++) t[i] = 0;
    u32 exp = nbits >> 24;
    u32 mant = nbits & 0x007fffff;              // ignore the sign bit
    int lsb = 34 - (int)exp;                     // big-endian index of the mantissa LSB
    set_be(t, lsb,     (u8)(mant & 0xff));
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

// ---- dynamic-algo verifier ---------------------------------------------------
// Returns 0 iff Whirlpool(anchor_hash||payout||nonce) top-256 bits <= target(nBits),
// and writes alpha,beta to out_ab (see put_ab). Param order: block context first
// (anchor_hash, payout, nBits), then the miner's solution (nonce), then the alpha/beta
// output pointer last.
#define PREIMAGE_MAX 4096
__attribute__((export_name("verify")))
int verify(const u8 *anchor_hash,                  // 32 bytes: the parent block hash
           const u8 *payout, u32 payout_len,     // the dynamic miner's payout spk
           u32 nbits,                            // u32 compact target
           const u8 *nonce, u32 nonce_len,       // the miner's solution
           u8 *out_ab)                           // OUT: alpha(u32 Q32) || beta, LE
{
    put_ab(out_ab, 0);                  // default: no valid solution (alpha=0, beta=0.5)

    u64 total = (u64)32 + payout_len + nonce_len;
    if (total > PREIMAGE_MAX) return 1; // over-long preimage: reject
    u8 buf[PREIMAGE_MAX];
    u64 o = 0;
    for (int k = 0; k < 32; k++) buf[o++] = anchor_hash[k];
    for (u32 k = 0; k < payout_len; k++) buf[o++] = payout[k];
    for (u32 k = 0; k < nonce_len; k++) buf[o++] = nonce[k];

    u8 digest[64];
    whirlpool(buf, total, digest);

    u8 target[32];
    target_from_nbits(nbits, target);

    // big-endian compare of the top 256 bits of the digest against the target
    int meets = 1;                       // all-equal => meets target
    for (int i = 0; i < 32; i++) {
        if (digest[i] < target[i]) { meets = 1; break; } // below target => success
        if (digest[i] > target[i]) { meets = 0; break; } // above target => fail
    }
    if (meets) put_ab(out_ab, 1);        // valid solution => alpha=beta=0.5
    return meets ? 0 : 1;
}

#ifdef WASM_SELFTEST
// Runs the vectors INSIDE the wasm and returns 0 on success (nonzero = which check
// failed). Lets wasmtime exercise the compiled module without seeding memory.
// Not built into the pushed module (guarded by WASM_SELFTEST).
static const u8 ABC[64] = {
 0x4E,0x24,0x48,0xA4,0xC6,0xF4,0x86,0xBB,0x16,0xB6,0x56,0x2C,0x73,0xB4,0x02,0x0B,
 0xF3,0x04,0x3E,0x3A,0x73,0x1B,0xCE,0x72,0x1A,0xE1,0xB3,0x03,0xD9,0x7E,0x6D,0x4C,
 0x71,0x81,0xEE,0xBD,0xB6,0xC5,0x7E,0x27,0x7D,0x0E,0x34,0x95,0x71,0x14,0xCB,0xD6,
 0xC7,0x97,0xFC,0x9D,0x95,0xD8,0xB5,0x82,0xD2,0x25,0x29,0x20,0x76,0xD4,0xEE,0xF5
};
__attribute__((export_name("selftest")))
int selftest(void) {
    u8 out[64];
    const u8 msg[3] = {'a','b','c'};
    whirlpool(msg, 3, out);
    for (int i = 0; i < 64; i++) if (out[i] != ABC[i]) return 1; // whirlpool("abc")
    u8 tg[32];
    target_from_nbits(0x1d00ffff, tg);
    if (tg[0] || tg[1] || tg[2] || tg[3] || tg[4] != 0xff || tg[5] != 0xff || tg[6]) return 2;
    u8 anchor[32]; for (int i = 0; i < 32; i++) anchor[i] = (u8)i;
    const u8 payout[3] = {0x6a, 0x00, 0x00};
    const u8 nonce[8] = {0,0,0,0,0,0,0,0};
    u8 ab[8];
    if (verify(anchor, payout, 3, 0x03000001, nonce, 8, ab) != 1) return 3; // tiny target fails
    if (ab[0] || ab[1] || ab[2] || ab[3]) return 5;                                   // alpha == 0 on fail
    if (verify(anchor, payout, 3, 0x2100ffff, nonce, 8, ab) != 0) return 4; // huge target passes
    if (ab[3] != 0x80 || ab[0] || ab[1] || ab[2]) return 6;                           // alpha == 0.5 (0x80000000) on pass
    if (ab[7] != 0x80 || ab[4] || ab[5] || ab[6]) return 7;                           // beta == 0.5 (0x80000000)
    return 0;
}
#endif

#ifdef TEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int hexeq(const u8 *b, const char *hex) {
    for (int i = 0; i < 32; i++) {
        char h[3] = {hex[2*i], hex[2*i+1], 0};
        if ((u8)strtol(h, 0, 16) != b[i]) return 0;
    }
    return 1;
}
int main(void) {
    // 1. nBits decode vs the Bitcoin genesis target (0x1d00ffff).
    u8 t[32];
    target_from_nbits(0x1d00ffff, t);
    const char *genesis = "00000000ffff0000000000000000000000000000000000000000000000000000";
    printf("nbits 0x1d00ffff -> "); for (int i=0;i<32;i++) printf("%02x", t[i]); printf("\n");
    printf("genesis target match: %s\n", hexeq(t, genesis) ? "OK" : "FAIL");

    // 2. verify() glue agrees with a direct compare, for a sample input.
    u8 anchor[32]; for (int i=0;i<32;i++) anchor[i]=(u8)i;
    u8 payout[] = {0x76,0xa9,0x14,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,0x88,0xac};
    u8 nonce[8] = {0,0,0,0,0,0,0,0};
    u32 nbits = 0x1f00ffff; // easy target
    u8 ab[8];
    // reference: compute digest and compare top32 to target
    u8 buf[65], dg[64], tg[32];
    int o=0; for(int i=0;i<32;i++) buf[o++]=anchor[i]; for(unsigned i=0;i<sizeof payout;i++) buf[o++]=payout[i]; for(int i=0;i<8;i++) buf[o++]=nonce[i];
    whirlpool(buf,o,dg); target_from_nbits(nbits,tg);
    int ref=0; for(int i=0;i<32;i++){ if(dg[i]<tg[i]){ref=0;break;} if(dg[i]>tg[i]){ref=1;break;} }
    int got = verify(anchor, payout, sizeof payout, nbits, nonce, 8, ab);
    printf("verify glue: got %d, ref %d -> %s ; alpha=%s beta=%s\n", got, ref,
           got==ref ? "OK" : "FAIL",
           (ab[3]==0x80 && !ab[0] && !ab[1] && !ab[2]) ? "0.5" : "0",
           (ab[7]==0x80 && !ab[4] && !ab[5] && !ab[6]) ? "0.5" : "?");
    // 3. impossible target (tiny) must fail; max target must pass.
    printf("tiny target  -> %d (expect 1)\n", verify(anchor,payout,sizeof payout,0x03000001,nonce,8,ab));
    printf("huge target  -> %d (expect 0)\n", verify(anchor,payout,sizeof payout,0x2100ffff,nonce,8,ab));
    return 0;
}
#endif
