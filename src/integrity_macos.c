#if defined(__APPLE__) && defined(__MACH__)

#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>

int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    if (out_ptr == NULL || out_size == NULL) {
        return -1;
    }

    const struct mach_header *hdr = _dyld_get_image_header(0);
    if (hdr == NULL || hdr->magic != MH_MAGIC_64) {
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
