#if defined(__APPLE__) && defined(__MACH__)

#include <dlfcn.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>

extern const void *reshield_internal_record_anchor(void);

/* Hashes __text of the image that holds the integrity record: the main executable for a
 * statically linked program, the dylib/bundle itself when re-shield is linked into one. */
int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    if (out_ptr == NULL || out_size == NULL) {
        return -1;
    }

    Dl_info info;
    if (dladdr(reshield_internal_record_anchor(), &info) == 0 || info.dli_fbase == NULL) {
        return -1;
    }
    const struct mach_header *hdr = (const struct mach_header *)info.dli_fbase;
    if (hdr->magic != MH_MAGIC_64) {
        return -1;
    }

    unsigned long sect_size = 0;
    const uint8_t *sect_ptr = getsectiondata(
        (const struct mach_header_64 *)hdr,
        "__TEXT",
        "__text",
        &sect_size
    );

    if (sect_ptr == NULL || sect_size == 0) {
        return -1;
    }

    *out_ptr = sect_ptr;
    *out_size = (uint64_t)sect_size;
    return 0;
}

#else
typedef int reshield_integrity_macos_unused_t;
#endif
