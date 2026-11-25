#include "reshield/integrity.h"

#include "file_platform.h"
#include "reshield/reshield.h"
#include "sha256_accel.h"
#include "sha256_internal.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    size_t   datalen;
} sha256_ctx_t;

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8)  |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + K[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
}

/* n whole blocks: CPU instructions when available, else the portable transform. */
static void sha256_blocks(sha256_ctx_t *ctx, const uint8_t *p, size_t n) {
    if (reshield_sha256_backend() != 0) {
        reshield_sha256_hw_compress(ctx->state, p, n);
    } else {
        for (size_t i = 0; i < n; i++) {
            sha256_transform(ctx, p + i * 64);
        }
    }
    ctx->bitlen += (uint64_t)n * 512;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    while (ctx->datalen > 0 && i < len) {
        ctx->data[ctx->datalen++] = data[i++];
        if (ctx->datalen == 64) {
            sha256_blocks(ctx, ctx->data, 1);
            ctx->datalen = 0;
        }
    }
    if (len - i >= 64) {
        size_t n = (len - i) / 64;
        sha256_blocks(ctx, data + i, n);
        i += n * 64;
    }
    while (i < len) {
        ctx->data[ctx->datalen++] = data[i++];
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    ctx->bitlen += (uint64_t)ctx->datalen * 8ULL;

    ctx->data[i++] = 0x80u;
    if (i > 56) {
        while (i < 64) {
            ctx->data[i++] = 0x00u;
        }
        sha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) {
        ctx->data[i++] = 0x00u;
    }

    for (int shift = 56, idx = 56; idx < 64; shift -= 8, idx++) {
        ctx->data[idx] = (uint8_t)((ctx->bitlen >> shift) & 0xffu);
    }
    sha256_transform(ctx, ctx->data);

    for (int j = 0; j < 8; j++) {
        hash[j * 4 + 0] = (uint8_t)((ctx->state[j] >> 24) & 0xffu);
        hash[j * 4 + 1] = (uint8_t)((ctx->state[j] >> 16) & 0xffu);
        hash[j * 4 + 2] = (uint8_t)((ctx->state[j] >> 8)  & 0xffu);
        hash[j * 4 + 3] = (uint8_t)(ctx->state[j] & 0xffu);
    }
}

void reshield_sha256(const void *data, size_t len, uint8_t out_hash[RESHIELD_SHA256_SIZE]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    if (data != NULL && len > 0) {
        sha256_update(&ctx, (const uint8_t *)data, len);
    }
    sha256_final(&ctx, out_hash);
}

int reshield_sha256_parts(const reshield_sha256_part_t *parts, size_t count, uint8_t out_hash[32]) {
    if (parts == NULL || out_hash == NULL) {
        return -1;
    }
    uint64_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (parts[i].len > 0 && parts[i].ptr == NULL) {
            return -1;
        }
        /* bitlen is a uint64: keep total*8 plus HMAC's two blocks well below 2^64. */
        if ((uint64_t)parts[i].len > (UINT64_MAX / 8u) - 256u - total) {
            return -1;
        }
        total += (uint64_t)parts[i].len;
    }
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    for (size_t i = 0; i < count; i++) {
        if (parts[i].len > 0) {
            sha256_update(&ctx, (const uint8_t *)parts[i].ptr, parts[i].len);
        }
    }
    sha256_final(&ctx, out_hash);
    reshield_secure_zero(&ctx, sizeof(ctx)); /* ctx.data holds key-derived bytes when used by HMAC */
    return 0;
}

/* Internal (declared extern in manifest.c): hashes at most max_read bytes of a regular
 * file (non-regular files are rejected by reshield_file_open_regular). */
int reshield_sha256_file_limited(const char *path,
                                 uint8_t out_hash[RESHIELD_SHA256_SIZE],
                                 uint64_t *out_size,
                                 uint64_t max_read) {
    if (path == NULL || out_hash == NULL) {
        return -1;
    }
    reshield_file_t file;
    if (reshield_file_open_regular(path, &file, NULL) != 0) {
        return -1;
    }

    sha256_ctx_t ctx;
    sha256_init(&ctx);

    uint8_t buf[4096];
    uint64_t total = 0;
    while (total < max_read) {
        uint64_t left = max_read - total;
        size_t want = left < sizeof(buf) ? (size_t)left : sizeof(buf);
        intptr_t n = reshield_file_read_full(file, buf, want);
        if (n < 0) {
            reshield_file_close(file);
            return -1;
        }
        sha256_update(&ctx, buf, (size_t)n);
        total += (uint64_t)n;
        if ((size_t)n < want) {
            break; /* EOF */
        }
    }

    reshield_file_close(file);
    sha256_final(&ctx, out_hash);
    if (out_size != NULL) {
        *out_size = total;
    }
    return 0;
}

int reshield_sha256_file(const char *path,
                         uint8_t out_hash[RESHIELD_SHA256_SIZE],
                         uint64_t *out_size) {
    return reshield_sha256_file_limited(path, out_hash, out_size, UINT64_MAX);
}
