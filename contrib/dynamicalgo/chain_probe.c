// Test fixture for the dynamic-algo chain-access ABI (doc/dynamic-algo-mining.md
// sec 3.1, 8.7). NOT a real algo: it exports verify() with the consensus signature
// but uses the `nbits` argument as a MODE selector so one small module can drive
// every chain-access case from a unit test, reporting what it observed through
// out_ab (alpha = the primary result, beta = a secondary).
//
// Built freestanding for wasm32:
//   clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -o chain_probe.wasm chain_probe.c

typedef unsigned char u8;
typedef unsigned int u32;

// The two chain-access imports. These attributes make clang emit real wasm imports
// with the module/name the node registers, so no libc and no --allow-undefined.
__attribute__((import_module("chain"), import_name("slot_block_count")))
extern int chain_slot_block_count(void);

__attribute__((import_module("chain"), import_name("slot_block")))
extern int chain_slot_block(int index, void *ptr, int cap);

#define BUFSZ (1 << 20) // 1 MiB: >= MAX_BLOCK_SERIALIZED_SIZE, so never -3 by accident
static u8 buf[BUFSZ];

static void put_u32le(u8 *p, u32 v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

enum {
    MODE_COUNT = 0,      // alpha <- slot_block_count()
    MODE_FETCH0 = 1,     // alpha <- size of block 0, beta <- its first byte
    MODE_OUT_OF_RANGE,   // alpha <- slot_block(count) -- expect -1
    MODE_CAP_TOO_SMALL,  // alpha <- slot_block(0, buf, 1) -- expect -3
    MODE_BAD_ADDR,       // slot_block(0, huge_ptr, big) -- expect a TRAP, not a code
    MODE_BURN_CALLS,     // many fetches -> trip GAS_IO_CALLS
    MODE_BURN_BYTES,     // fewer, larger fetches -> trip GAS_IO_BYTES
    MODE_FETCH_LAST,     // alpha <- size of block count-1 (oldest addressable)
};

__attribute__((export_name("verify")))
int verify(const u8 *anchor_hash,
           const u8 *payout, u32 payout_len,
           u32 mode,                     // the ABI's `nbits` slot, reused as a selector
           const u8 *nonce, u32 nonce_len,
           u8 *out_ab)
{
    (void)anchor_hash; (void)payout; (void)payout_len; (void)nonce; (void)nonce_len;
    put_u32le(out_ab, 0);
    put_u32le(out_ab + 4, 0);

    const int n = chain_slot_block_count();

    switch (mode) {
    case MODE_COUNT:
        put_u32le(out_ab, (u32)n);
        return 0;

    case MODE_FETCH0: {
        const int sz = chain_slot_block(0, buf, BUFSZ);
        put_u32le(out_ab, (u32)sz);
        if (sz > 0) put_u32le(out_ab + 4, buf[0]);
        return 0;
    }

    case MODE_OUT_OF_RANGE:
        put_u32le(out_ab, (u32)chain_slot_block(n, buf, BUFSZ));
        return 0;

    case MODE_CAP_TOO_SMALL:
        put_u32le(out_ab, (u32)chain_slot_block(0, buf, 1));
        return 0;

    case MODE_BAD_ADDR:
        // An offset far past the end of linear memory. The host must not trust the
        // guest pointer; the engine's bounds check traps, so this never returns.
        put_u32le(out_ab, (u32)chain_slot_block(0, (void *)0x7ffffff0, 4096));
        return 0;

    case MODE_BURN_CALLS:
        // Traps once the call budget is exhausted, so this never returns.
        for (int i = 0; i < 1000000; i++) (void)chain_slot_block(0, buf, BUFSZ);
        return 0;

    case MODE_BURN_BYTES:
        // Same, but the source serves large blocks so the byte budget binds first.
        // 4000 fetches of 1 MiB passes GAS_IO_BYTES_LIMIT (2 GiB) at ~2048 while staying
        // under GAS_IO_CALLS_LIMIT (4096), so it is really the BYTE cap being tested.
        // Hardcoded because this is freestanding wasm and cannot include gasclasses.h --
        // raise it together with the limits.
        for (int i = 0; i < 4000; i++) (void)chain_slot_block(0, buf, BUFSZ);
        return 0;

    case MODE_FETCH_LAST:
        put_u32le(out_ab, (u32)(n > 0 ? chain_slot_block(n - 1, buf, BUFSZ) : -1));
        if (n > 0) put_u32le(out_ab + 4, buf[0]);
        return 0;

    default:
        return 1;
    }
}
