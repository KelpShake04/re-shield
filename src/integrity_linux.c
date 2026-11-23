#if defined(__linux__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <elf.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uintptr_t base_addr;
    int       found;
} main_image_ctx_t;

static int find_main_image_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    main_image_ctx_t *ctx = (main_image_ctx_t *)data;
    if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0') {
        ctx->base_addr = (uintptr_t)info->dlpi_addr;
        ctx->found = 1;
        return 1;
    }
    return 0;
}

int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    if (out_ptr == NULL || out_size == NULL) {
        return -1;
    }

    main_image_ctx_t img = { 0, 0 };
    dl_iterate_phdr(find_main_image_cb, &img);
    if (!img.found) {
        return -1;
    }

    FILE *fp = fopen("/proc/self/exe", "rb");
    if (fp == NULL) {
        return -1;
    }

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr) ||
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_shentsize != sizeof(Elf64_Shdr) ||
        ehdr.e_shoff == 0 || ehdr.e_shnum == 0 || ehdr.e_shstrndx >= ehdr.e_shnum) {
        fclose(fp);
        return -1;
    }

    size_t sh_table_size = (size_t)ehdr.e_shnum * sizeof(Elf64_Shdr);
    Elf64_Shdr *shdrs = (Elf64_Shdr *)malloc(sh_table_size);
    if (shdrs == NULL) {
        fclose(fp);
        return -1;
    }

    if (fseek(fp, (long)ehdr.e_shoff, SEEK_SET) != 0 ||
        fread(shdrs, 1, sh_table_size, fp) != sh_table_size) {
        free(shdrs);
        fclose(fp);
        return -1;
    }

    Elf64_Shdr strtab_hdr = shdrs[ehdr.e_shstrndx];
    char *strtab = (char *)malloc((size_t)strtab_hdr.sh_size + 1);
    if (strtab == NULL) {
        free(shdrs);
        fclose(fp);
        return -1;
    }

    if (fseek(fp, (long)strtab_hdr.sh_offset, SEEK_SET) != 0 ||
        fread(strtab, 1, (size_t)strtab_hdr.sh_size, fp) != (size_t)strtab_hdr.sh_size) {
        free(strtab);
        free(shdrs);
        fclose(fp);
        return -1;
    }
    strtab[strtab_hdr.sh_size] = '\0';

    int rc = -1;
    for (uint16_t i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_name < strtab_hdr.sh_size &&
            strcmp(strtab + shdrs[i].sh_name, ".text") == 0 &&
            shdrs[i].sh_size > 0) {
            *out_ptr = (const uint8_t *)(img.base_addr + (uintptr_t)shdrs[i].sh_addr);
            *out_size = (uint64_t)shdrs[i].sh_size;
            rc = 0;
            break;
        }
    }

    free(strtab);
    free(shdrs);
    fclose(fp);
    return rc;
}

#else
typedef int reshield_integrity_linux_unused_t;
#endif
