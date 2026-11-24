/* libFuzzer: SHA-256 consistency across independent code paths of the public/linkable API:
 * one-shot buffer hash, reshield_verify_buffer, the 4 KiB-chunked file hash, and the
 * length-limited file hash (== one-shot hash of the prefix). Inputs up to 20000 bytes
 * (run with -max_len=20000) cross the chunk boundary. */
#include "fuzz_common.h"

#include "reshield/integrity.h"

/* Internal helper in sha256.c, linkable from libreshield.a. */
extern int reshield_sha256_file_limited(const char *path,
                                        uint8_t out_hash[RESHIELD_SHA256_SIZE],
                                        uint64_t *out_size,
                                        uint64_t max_read);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    fz_setup();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }
    /* First two bytes pick a prefix limit; the rest is the message. */
    uint64_t limit = (uint64_t)((data[0] << 8) | data[1]);
    data += 2;
    size -= 2;

    uint8_t one[RESHIELD_SHA256_SIZE], viafile[RESHIELD_SHA256_SIZE], lim[RESHIELD_SHA256_SIZE];
    reshield_sha256(data, size, one);
    if (!reshield_verify_buffer(data, size, one)) {
        abort();
    }

    fz_write(g_fz_manifest, data, size);
    uint64_t fsize = 0;
    if (reshield_sha256_file(g_fz_manifest, viafile, &fsize) != 0 || fsize != size ||
        memcmp(one, viafile, sizeof(one)) != 0) {
        abort();
    }

    uint64_t lsize = 0;
    if (reshield_sha256_file_limited(g_fz_manifest, lim, &lsize, limit) != 0) {
        abort();
    }
    uint64_t want = limit < size ? limit : size;
    uint8_t prefix[RESHIELD_SHA256_SIZE];
    reshield_sha256(data, (size_t)want, prefix);
    if (lsize != want || memcmp(prefix, lim, sizeof(prefix)) != 0) {
        abort();
    }
    return 0;
}
