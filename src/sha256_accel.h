#ifndef RESHIELD_SHA256_ACCEL_H
#define RESHIELD_SHA256_ACCEL_H

/* Internal (not installed): CPU-instruction SHA-256 block compression, used by sha256.c.
 * Not part of the public API or ABI. Compile with -DRESHIELD_NO_HW_SHA to remove it. */

#include <stddef.h>
#include <stdint.h>

/* Backend picked once on first use (idempotent, deterministic): 0 portable C, 1 AArch64 SHA2
 * (vsha256*), 2 x86-64 SHA-NI. Anything not certain on this compiler/OS/CPU is 0. */
int reshield_sha256_backend(void);

/* Tests only. 1: use the portable path from now on; 0: back to the detected backend. */
void reshield_sha256_force_portable(int on);

/* state += compress(blocks[0 .. nblocks*64)). Precondition: reshield_sha256_backend() != 0.
 * No alignment requirement on blocks. */
void reshield_sha256_hw_compress(uint32_t state[8], const uint8_t *blocks, size_t nblocks);

#endif
