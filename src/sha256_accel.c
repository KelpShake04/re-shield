#include "sha256_accel.h"

/* SHA-256 block compression on CPU hardware instructions (compiler intrinsics only, no external
 * dependency). Only combinations that were built and measured are enabled; everything else
 * compiles to "backend 0" and sha256.c keeps using the portable C code:
 *   AArch64 + gcc/clang + macOS or Linux  -> SHA2 extension (macOS: always present on arm64;
 *                                            Linux: getauxval(AT_HWCAP) & HWCAP_SHA2)
 *   x86-64  + gcc/clang, not Windows      -> SHA-NI (+SSSE3/SSE4.1), checked with cpuid
 *   x86-64  + MSVC cl (not clang-cl)      -> SHA-NI, checked with __cpuidex
 * Not enabled: Windows ARM64, mingw, clang-cl, 32-bit x86, other OSes. */

#if defined(RESHIELD_NO_HW_SHA)
/* disabled by the build */
#elif defined(__aarch64__) && (defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 6)) && \
      (defined(__APPLE__) || defined(__linux__))
#define RS_HW_ARMV8 1
#elif defined(__x86_64__) && (defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5)) && \
      !defined(_WIN32) && !defined(__CYGWIN__)
#define RS_HW_SHANI 1
#define RS_HW_SHANI_GNU 1
#elif defined(_MSC_VER) && !defined(__clang__) && defined(_M_X64)
#define RS_HW_SHANI 1
#endif

#if defined(RS_HW_ARMV8) || defined(RS_HW_SHANI)
/* Same table as sha256.c (FIPS 180-4 4.2.2); tests compare both paths bit for bit. */
static const uint32_t RS_K[64] = {
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
#endif

/* ------------------------------------------------------------------ AArch64 SHA2 */
#if defined(RS_HW_ARMV8)

#include <arm_neon.h>
#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1UL << 6)
#endif
#endif

#if defined(__clang__)
#define RS_TARGET_ARMV8 __attribute__((target("sha2")))
#else
#define RS_TARGET_ARMV8 __attribute__((target("arch=armv8-a+crypto")))
#endif

static int armv8_available(void) {
#if defined(__APPLE__)
    return 1; /* every arm64 Mac has the SHA2 instructions */
#else
    return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#endif
}

/* 4 rounds: m = 4 message words W[k..k+3]; (s0, s1) = (ABCD, EFGH). */
#define RS_A_RND(m, k)                                                          \
    do {                                                                        \
        uint32x4_t wk_ = vaddq_u32((m), vld1q_u32(RS_K + (k)));                 \
        uint32x4_t abcd_ = s0;                                                  \
        s0 = vsha256hq_u32(s0, s1, wk_);                                        \
        s1 = vsha256h2q_u32(s1, abcd_, wk_);                                    \
    } while (0)
/* a = next 4 words after d (a holds W[t-16..], b W[t-12..], c W[t-8..], d W[t-4..]). */
#define RS_A_SCHED(a, b, c, d) (a) = vsha256su1q_u32(vsha256su0q_u32((a), (b)), (c), (d))
#define RS_A_LOAD(i) vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16 * (i))))

RS_TARGET_ARMV8
static void armv8_compress(uint32_t state[8], const uint8_t *p, size_t nblocks) {
    uint32x4_t s0 = vld1q_u32(state);
    uint32x4_t s1 = vld1q_u32(state + 4);
    while (nblocks-- > 0) {
        uint32x4_t save0 = s0;
        uint32x4_t save1 = s1;
        uint32x4_t m0 = RS_A_LOAD(0);
        uint32x4_t m1 = RS_A_LOAD(1);
        uint32x4_t m2 = RS_A_LOAD(2);
        uint32x4_t m3 = RS_A_LOAD(3);

        RS_A_RND(m0, 0);
        RS_A_RND(m1, 4);
        RS_A_RND(m2, 8);
        RS_A_RND(m3, 12);
        for (int k = 16; k < 64; k += 16) {
            RS_A_SCHED(m0, m1, m2, m3); RS_A_RND(m0, k);
            RS_A_SCHED(m1, m2, m3, m0); RS_A_RND(m1, k + 4);
            RS_A_SCHED(m2, m3, m0, m1); RS_A_RND(m2, k + 8);
            RS_A_SCHED(m3, m0, m1, m2); RS_A_RND(m3, k + 12);
        }

        s0 = vaddq_u32(s0, save0);
        s1 = vaddq_u32(s1, save1);
        p += 64;
    }
    vst1q_u32(state, s0);
    vst1q_u32(state + 4, s1);
}

/* --------------------------------------------------------------------- x86-64 SHA-NI */
#elif defined(RS_HW_SHANI)

#if defined(RS_HW_SHANI_GNU)
#include <cpuid.h>
#include <immintrin.h>
#define RS_TARGET_SHANI __attribute__((target("sha,sse4.1,ssse3")))
#else
#include <immintrin.h>
#include <intrin.h>
#define RS_TARGET_SHANI
#endif

static int shani_available(void) {
#if defined(RS_HW_SHANI_GNU)
    unsigned int a, b, c, d;
    if (__get_cpuid_max(0, NULL) < 7) {
        return 0;
    }
    __cpuid(1, a, b, c, d);
    int ssse3_sse41 = ((c >> 9) & 1u) != 0 && ((c >> 19) & 1u) != 0;
    __cpuid_count(7, 0, a, b, c, d);
    return ssse3_sse41 && ((b >> 29) & 1u) != 0;
#else
    int r[4]; /* eax, ebx, ecx, edx */
    __cpuid(r, 0);
    if (r[0] < 7) {
        return 0;
    }
    __cpuid(r, 1);
    int ssse3_sse41 = ((r[2] >> 9) & 1) != 0 && ((r[2] >> 19) & 1) != 0;
    __cpuidex(r, 7, 0);
    return ssse3_sse41 && ((r[1] >> 29) & 1) != 0;
#endif
}

/* 4 rounds from W[k..k+3] in m; (s0, s1) = (ABEF, CDGH). The msg words 0,1 feed the first
 * sha256rnds2, words 2,3 (after the 0x0E shuffle) the second. */
#define RS_X_RND(m, k)                                                                      \
    do {                                                                                    \
        __m128i wk_ = _mm_add_epi32((m), _mm_loadu_si128((const __m128i *)(RS_K + (k))));   \
        s1 = _mm_sha256rnds2_epu32(s1, s0, wk_);                                            \
        wk_ = _mm_shuffle_epi32(wk_, 0x0E);                                                 \
        s0 = _mm_sha256rnds2_epu32(s0, s1, wk_);                                            \
    } while (0)
/* a (= W[t-16..]) becomes the next 4 words; b,c,d are the following three groups. */
#define RS_X_SCHED(a, b, c, d)                                                              \
    (a) = _mm_sha256msg2_epu32(                                                             \
        _mm_add_epi32(_mm_sha256msg1_epu32((a), (b)), _mm_alignr_epi8((d), (c), 4)), (d))
#define RS_X_LOAD(i) _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 16 * (i))), bswap)

RS_TARGET_SHANI
static void shani_compress(uint32_t state[8], const uint8_t *p, size_t nblocks) {
    const __m128i bswap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
    /* state[] is A..H; the instructions want ABEF / CDGH. */
    __m128i dcba = _mm_loadu_si128((const __m128i *)&state[0]);
    __m128i hgfe = _mm_loadu_si128((const __m128i *)&state[4]);
    __m128i cdab = _mm_shuffle_epi32(dcba, 0xB1);
    __m128i efgh = _mm_shuffle_epi32(hgfe, 0x1B);
    __m128i s0 = _mm_alignr_epi8(cdab, efgh, 8);   /* ABEF */
    __m128i s1 = _mm_blend_epi16(efgh, cdab, 0xF0); /* CDGH */

    while (nblocks-- > 0) {
        __m128i save0 = s0;
        __m128i save1 = s1;
        __m128i m0 = RS_X_LOAD(0);
        __m128i m1 = RS_X_LOAD(1);
        __m128i m2 = RS_X_LOAD(2);
        __m128i m3 = RS_X_LOAD(3);

        RS_X_RND(m0, 0);   RS_X_SCHED(m0, m1, m2, m3);
        RS_X_RND(m1, 4);   RS_X_SCHED(m1, m2, m3, m0);
        RS_X_RND(m2, 8);   RS_X_SCHED(m2, m3, m0, m1);
        RS_X_RND(m3, 12);  RS_X_SCHED(m3, m0, m1, m2);
        RS_X_RND(m0, 16);  RS_X_SCHED(m0, m1, m2, m3);
        RS_X_RND(m1, 20);  RS_X_SCHED(m1, m2, m3, m0);
        RS_X_RND(m2, 24);  RS_X_SCHED(m2, m3, m0, m1);
        RS_X_RND(m3, 28);  RS_X_SCHED(m3, m0, m1, m2);
        RS_X_RND(m0, 32);  RS_X_SCHED(m0, m1, m2, m3);
        RS_X_RND(m1, 36);  RS_X_SCHED(m1, m2, m3, m0);
        RS_X_RND(m2, 40);  RS_X_SCHED(m2, m3, m0, m1);
        RS_X_RND(m3, 44);  RS_X_SCHED(m3, m0, m1, m2);
        RS_X_RND(m0, 48);
        RS_X_RND(m1, 52);
        RS_X_RND(m2, 56);
        RS_X_RND(m3, 60);

        s0 = _mm_add_epi32(s0, save0);
        s1 = _mm_add_epi32(s1, save1);
        p += 64;
    }

    __m128i feba = _mm_shuffle_epi32(s0, 0x1B);
    __m128i dchg = _mm_shuffle_epi32(s1, 0xB1);
    _mm_storeu_si128((__m128i *)&state[0], _mm_blend_epi16(feba, dchg, 0xF0)); /* DCBA */
    _mm_storeu_si128((__m128i *)&state[4], _mm_alignr_epi8(dchg, feba, 8));    /* HGFE */
}

#endif

/* ------------------------------------------------------------------ dispatch */

/* -1 = not decided yet. The value is deterministic, so two threads racing here store the same
 * thing. Plain volatile is still a C11 data race (ThreadSanitizer reports it), so access goes
 * through relaxed atomics: <stdatomic.h> is not available to the C++11 / cl /TP builds of these
 * sources, hence the compiler's own intrinsics. No ordering is needed: the value only picks a code
 * path, and the compress functions read nothing but constants and their arguments.
 * shortcut: any other compiler falls back to volatile (atomic for an aligned int on every target
 * we build, but formally a race); add its intrinsic here when one is supported. */
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5)
static int g_backend = -1;
#define RS_BACKEND_LOAD() __atomic_load_n(&g_backend, __ATOMIC_RELAXED)
#define RS_BACKEND_STORE(v) __atomic_store_n(&g_backend, (v), __ATOMIC_RELAXED)
#elif defined(_MSC_VER)
#include <intrin.h>
static volatile __int32 g_backend = -1;
#define RS_BACKEND_LOAD() ((int)__iso_volatile_load32(&g_backend))
#define RS_BACKEND_STORE(v) ((void)_InterlockedExchange((volatile long *)&g_backend, (long)(v)))
#else
static volatile int g_backend = -1;
#define RS_BACKEND_LOAD() (g_backend)
#define RS_BACKEND_STORE(v) (g_backend = (v))
#endif

static int detect_backend(void) {
#if defined(RS_HW_ARMV8)
    if (armv8_available()) {
        return 1;
    }
#elif defined(RS_HW_SHANI)
    if (shani_available()) {
        return 2;
    }
#endif
    return 0;
}

int reshield_sha256_backend(void) {
    int b = RS_BACKEND_LOAD();
    if (b < 0) {
        b = detect_backend();
        RS_BACKEND_STORE(b);
    }
    return b;
}

void reshield_sha256_force_portable(int on) {
    RS_BACKEND_STORE(on ? 0 : detect_backend());
}

void reshield_sha256_hw_compress(uint32_t state[8], const uint8_t *blocks, size_t nblocks) {
    switch (reshield_sha256_backend()) {
#if defined(RS_HW_ARMV8)
    case 1:
        armv8_compress(state, blocks, nblocks);
        break;
#elif defined(RS_HW_SHANI)
    case 2:
        shani_compress(state, blocks, nblocks);
        break;
#endif
    default:
        (void)state;
        (void)blocks;
        (void)nblocks;
        break; /* precondition violated: never reached from sha256.c */
    }
}
