#ifdef _WIN32

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

extern const void *reshield_internal_record_anchor(void);

/* Locates .text, in its mapped image, of the module that holds the integrity record: the EXE for
 * a statically linked program, the DLL itself when re-shield is linked into one. Must select exactly what
 * tools/seal_binary.py (parse_pe64/pe_find_text) hashes: the single section named
 * ".text", VirtualSize bytes, VirtualSize <= SizeOfRawData, not writable. In memory the
 * bytes equal the file bytes because the sealer refuses an image with base relocations
 * inside .text (MSVC links none there). Every header read is bounded by the headers
 * region and then by SizeOfImage; anything odd fails closed (-1). */

/* DOS header + NT headers must sit in the first page before SizeOfHeaders is known. */
#define RESHIELD_PE_BOOTSTRAP_LIMIT 0x1000u

int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    if (out_ptr == NULL || out_size == NULL) {
        return -1;
    }

    HMODULE module = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)reshield_internal_record_anchor(), &module) ||
        module == NULL) {
        return -1;
    }
    const uint8_t *base = (const uint8_t *)module;

    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return -1;
    }
    uint64_t nt_off = (uint32_t)dos->e_lfanew;
    if (dos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) || (nt_off & 3u) != 0u ||
        nt_off + sizeof(IMAGE_NT_HEADERS64) > RESHIELD_PE_BOOTSTRAP_LIMIT) {
        return -1;
    }

    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(base + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) -
            IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY)) {
        return -1;
    }

    uint64_t size_of_image = nt->OptionalHeader.SizeOfImage;
    uint64_t size_of_headers = nt->OptionalHeader.SizeOfHeaders;
    if (size_of_headers > size_of_image) {
        return -1;
    }

    uint64_t sect_off = nt_off + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                        nt->FileHeader.SizeOfOptionalHeader;
    uint64_t nsections = nt->FileHeader.NumberOfSections;
    if (sect_off + nsections * sizeof(IMAGE_SECTION_HEADER) > size_of_headers) {
        return -1;
    }

    const IMAGE_SECTION_HEADER *sec = (const IMAGE_SECTION_HEADER *)(base + sect_off);
    const IMAGE_SECTION_HEADER *text = NULL;
    for (uint64_t i = 0; i < nsections; i++) {
        if (memcmp(sec[i].Name, ".text", 6) == 0) { /* ".text" + NUL, as the sealer's name split */
            if (text != NULL) {
                return -1; /* sealer requires exactly one */
            }
            text = &sec[i];
        }
    }
    if (text == NULL || (text->Characteristics & IMAGE_SCN_MEM_WRITE) != 0u) {
        return -1;
    }

    uint64_t vsize = text->Misc.VirtualSize;
    uint64_t vaddr = text->VirtualAddress;
    if (vsize == 0u || vsize > text->SizeOfRawData || vaddr + vsize > size_of_image) {
        return -1;
    }

    *out_ptr = base + vaddr;
    *out_size = vsize;
    return 0;
}

#else
typedef int reshield_integrity_windows_unused_t;
#endif
