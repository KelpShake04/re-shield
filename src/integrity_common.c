#include "reshield/integrity.h"

#include "sha256_internal.h"

#include <string.h>

/* Platform backend hook implemented in integrity_macos.c / integrity_linux.c / integrity_windows.c */
extern int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size);

#if !defined(__APPLE__) && !defined(__linux__) && !defined(_WIN32)
int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    (void)out_ptr;
    (void)out_size;
    return -1;
}
#endif

/**
 * Embedded v2 integrity record (96 bytes, naturally aligned) populated at build
 * time by tools/seal_binary.py. Placed in initialized data (outside code section)
 * and marked volatile + used so the compiler never constant-folds or drops it.
 */
typedef struct reshield_integrity_record {
    uint8_t  magic[RESHIELD_INTEGRITY_MAGIC_LEN]; /* "RSHLDCHK" */
    uint32_t version;
    uint32_t sealed;
    uint32_t build_id;
    uint32_t has_manifest;
    uint64_t expected_size;
    uint8_t  expected_sha256[RESHIELD_SHA256_SIZE];
    uint8_t  manifest_root_sha256[RESHIELD_SHA256_SIZE];
} reshield_integrity_record_t;

#if defined(__GNUC__) || defined(__clang__)
#define RESHIELD_USED __attribute__((used))
#else
#define RESHIELD_USED
#endif

/* Positional, in struct order: designated initializers are not C++ before C++20. */
static volatile reshield_integrity_record_t RESHIELD_USED g_reshield_integrity_record = {
    { 'R', 'S', 'H', 'L', 'D', 'C', 'H', 'K' }, /* magic */
    RESHIELD_INTEGRITY_RECORD_VERSION,          /* version */
    0u,                                         /* sealed */
    0u,                                         /* build_id */
    0u,                                         /* has_manifest */
    0u,                                         /* expected_size */
    { 0 },                                      /* expected_sha256 */
    { 0 }                                       /* manifest_root_sha256 */
};

#ifdef RESHIELD_ALLOW_UNSEALED
/* Development-build marker. Only a build compiled with RESHIELD_ALLOW_UNSEALED carries it, so
 * tools/reshield_release.py and tools/verify_release.py can refuse to ship such a binary. It is
 * a guard against shipping the wrong build by mistake, not a defense: an attacker can erase it.
 * It has external linkage (a static one that nothing really uses is never emitted by MSVC) but
 * hidden visibility, so it is not part of any library's exported interface. RESHIELD_USED and the
 * volatile read in the anchor function below keep it through the compiler and through
 * --gc-sections / -dead_strip; the value is never used. */
#if defined(__GNUC__) || defined(__clang__)
extern __attribute__((visibility("hidden"))) const volatile char reshield_internal_dev_build_marker[];
#else
extern const volatile char reshield_internal_dev_build_marker[];
#endif
RESHIELD_USED const volatile char reshield_internal_dev_build_marker[] = "RESHIELD-DEV-BUILD-v1";
#endif

/* Address inside this module's image (the record lives in the module that linked re-shield).
 * The platform hooks find "the image that holds the record" from it, so a library that links
 * re-shield verifies itself, not the host process. Internal: not in any public header. */
const void *reshield_internal_record_anchor(void) {
#ifdef RESHIELD_ALLOW_UNSEALED
    (void)reshield_internal_dev_build_marker[0];
#endif
    return (const void *)&g_reshield_integrity_record;
}

static void read_record(reshield_integrity_record_t *dst) {
    const volatile uint8_t *src = (const volatile uint8_t *)&g_reshield_integrity_record;
    uint8_t *out = (uint8_t *)dst;
    for (size_t i = 0; i < sizeof(*dst); i++) {
        out[i] = src[i];
    }
}

int reshield_digest_equal(const uint8_t a[RESHIELD_SHA256_SIZE],
                          const uint8_t b[RESHIELD_SHA256_SIZE]) {
    if (a == NULL || b == NULL) {
        return 0;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < RESHIELD_SHA256_SIZE; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0 ? 1 : 0;
}

int reshield_verify_buffer(const void *data, size_t len,
                           const uint8_t expected_sha256[RESHIELD_SHA256_SIZE]) {
    /* Always compares, even with -DRESHIELD_DISABLE: this is app-logic hashing, not an integrity check. */
    if (expected_sha256 == NULL) {
        return 0;
    }
    uint8_t actual[RESHIELD_SHA256_SIZE];
    reshield_sha256(data, len, actual);
    return reshield_digest_equal(actual, expected_sha256);
}

/* Record is structurally valid only with the expected magic/version and boolean flags.
 * An invalid record is never treated as "unsealed": flipping version/magic must not
 * turn a sealed binary into one that allow_unsealed accepts. */
static int record_is_valid(const reshield_integrity_record_t *rec) {
    static const uint8_t magic[RESHIELD_INTEGRITY_MAGIC_LEN] = { 'R', 'S', 'H', 'L', 'D', 'C', 'H', 'K' };
    return memcmp(rec->magic, magic, sizeof(magic)) == 0 &&
           rec->version == RESHIELD_INTEGRITY_RECORD_VERSION &&
           rec->sealed <= 1u &&
           rec->has_manifest <= 1u;
}

int reshield_get_sealed_manifest_root(uint8_t out_root[RESHIELD_SHA256_SIZE]) {
    if (out_root == NULL) {
        return -1;
    }
    reshield_integrity_record_t rec;
    read_record(&rec);
    if (!record_is_valid(&rec)) {
        return -2;
    }
    if (rec.sealed == 0u) {
        return -1;
    }
    if (rec.has_manifest == 0u) {
        return -2;
    }
    memcpy(out_root, rec.manifest_root_sha256, RESHIELD_SHA256_SIZE);
    return 0;
}

/* Private layout of reshield_code_scan_t. The public struct is an opaque uint64_t array; this
 * is copied in and out with memcpy so no uint64_t object is ever read through a struct type. */
#define RESHIELD_SCAN_MAGIC 0x52534353u /* "RSCS" */

typedef struct reshield_scan_impl {
    uint32_t       magic;
    uint32_t       reserved;
    const uint8_t *base;
    uint64_t       size;
    uint64_t       done;
    sha256_ctx_t   ctx;
} reshield_scan_impl_t;

/* Compile-time check that the private state fits (a negative array size is the C and C++ way). */
typedef char reshield_scan_fits_t[sizeof(reshield_scan_impl_t) <= sizeof(reshield_code_scan_t) ? 1 : -1];

reshield_integrity_status_t reshield_code_scan_begin(reshield_code_scan_t *scan) {
    if (scan == NULL) {
        return RESHIELD_INTEGRITY_ERROR;
    }
    memset(scan, 0, sizeof(*scan));

    reshield_scan_impl_t st;
    memset(&st, 0, sizeof(st));
#ifndef RESHIELD_DISABLE
    if (reshield_platform_get_code_section(&st.base, &st.size) != 0 ||
        st.base == NULL || st.size == 0) {
        return RESHIELD_INTEGRITY_ERROR;
    }
    reshield_sha256_ctx_init(&st.ctx);
#endif
    st.magic = RESHIELD_SCAN_MAGIC;
    memcpy(scan, &st, sizeof(st));
    return RESHIELD_INTEGRITY_OK;
}

int reshield_code_scan_step(reshield_code_scan_t *scan, size_t max_bytes,
                            reshield_integrity_result_t *out_result) {
    if (scan == NULL || max_bytes == 0) {
        return -1;
    }
    reshield_scan_impl_t st;
    memcpy(&st, scan, sizeof(st));
    if (st.magic != RESHIELD_SCAN_MAGIC) {
        return -1;
    }

    reshield_integrity_result_t res;
    memset(&res, 0, sizeof(res));

#ifdef RESHIELD_DISABLE
    res.status = RESHIELD_INTEGRITY_OK;
    if (out_result != NULL) {
        *out_result = res;
    }
    return 1;
#else
    uint64_t left = st.size - st.done;
    size_t n = (uint64_t)max_bytes < left ? max_bytes : (size_t)left;
    reshield_sha256_ctx_update(&st.ctx, st.base + st.done, n);
    st.done += n;
    if (st.done < st.size) {
        memcpy(scan, &st, sizeof(st));
        return 0;
    }

    /* The record is read only now: a change to it during the pass still counts. */
    reshield_integrity_record_t rec;
    read_record(&rec);

    res.build_id = rec.build_id;
    res.has_manifest = rec.has_manifest != 0u ? 1 : 0;
    res.actual_size = st.size;
    res.expected_size = rec.expected_size;
    memcpy(res.expected_sha256, rec.expected_sha256, RESHIELD_SHA256_SIZE);
    memcpy(res.manifest_root_sha256, rec.manifest_root_sha256, RESHIELD_SHA256_SIZE);
    reshield_sha256_ctx_final(&st.ctx, res.actual_sha256);

    if (!record_is_valid(&rec)) {
        res.status = RESHIELD_INTEGRITY_TAMPERED;
    } else if (rec.sealed == 0u) {
        res.status = RESHIELD_INTEGRITY_UNSEALED;
    } else if (rec.expected_size != st.size ||
               !reshield_digest_equal(res.actual_sha256, rec.expected_sha256)) {
        res.status = RESHIELD_INTEGRITY_TAMPERED;
    } else {
        res.status = RESHIELD_INTEGRITY_OK;
    }

    /* Next call starts a new pass over the same section; no need to call begin again. */
    st.done = 0;
    reshield_sha256_ctx_init(&st.ctx);
    memcpy(scan, &st, sizeof(st));

    if (out_result != NULL) {
        *out_result = res;
    }
    return 1;
#endif
}

reshield_integrity_status_t reshield_verify_code_section(reshield_integrity_result_t *out_result) {
    reshield_integrity_result_t res;
    memset(&res, 0, sizeof(res));

    /* One pass in one step: the verdict logic lives only in reshield_code_scan_step(). */
    reshield_code_scan_t scan;
    if (reshield_code_scan_begin(&scan) != RESHIELD_INTEGRITY_OK ||
        reshield_code_scan_step(&scan, SIZE_MAX, &res) != 1) {
        memset(&res, 0, sizeof(res));
        res.status = RESHIELD_INTEGRITY_ERROR;
    }

    if (out_result != NULL) {
        *out_result = res;
    }
    return res.status;
}
