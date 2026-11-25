#ifndef RESHIELD_SHA256_INTERNAL_H
#define RESHIELD_SHA256_INTERNAL_H

/* Internal (not installed): SHA-256 over several buffers without concatenating them.
 * Implemented in sha256.c. */

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const void *ptr;
    size_t      len;
} reshield_sha256_part_t;

/* SHA-256 of parts[0] || parts[1] || ... . Returns 0, or -1 on a NULL ptr with len > 0 or a
 * total length the 64-bit bit counter cannot represent. */
int reshield_sha256_parts(const reshield_sha256_part_t *parts, size_t count, uint8_t out_hash[32]);

/* Streaming SHA-256 for callers that hash in pieces over time (the incremental code scan).
 * The struct is plain data: copy it freely. ctx_final consumes the state; call ctx_init to reuse. */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    size_t   datalen;
} sha256_ctx_t;

void reshield_sha256_ctx_init(sha256_ctx_t *ctx);
void reshield_sha256_ctx_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void reshield_sha256_ctx_final(sha256_ctx_t *ctx, uint8_t out_hash[32]);

#endif /* RESHIELD_SHA256_INTERNAL_H */
