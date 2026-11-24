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
#include <sys/auxv.h>
#include <sys/stat.h>

typedef struct {
    uintptr_t         base_addr;
    const Elf64_Phdr *phdr;
    size_t            phnum;
    int               found;
} main_image_ctx_t;

/* The main image is the entry whose program headers are the ones the kernel passed in
 * AT_PHDR. Matching by an empty dlpi_name is wrong on musl, which fills the name with the
 * program path. Under `ld.so ./prog` AT_PHDR describes the loader, not prog, so nothing
 * matches and the check reports an error (fail closed) instead of hashing the wrong bytes. */
static int find_main_image_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    main_image_ctx_t *ctx = (main_image_ctx_t *)data;
    uintptr_t at_phdr = (uintptr_t)getauxval(AT_PHDR);
    if (at_phdr != 0 && (uintptr_t)info->dlpi_phdr == at_phdr) {
        ctx->base_addr = (uintptr_t)info->dlpi_addr;
        ctx->phdr = info->dlpi_phdr;
        ctx->phnum = info->dlpi_phnum;
        ctx->found = 1;
        return 1;
    }
    return 0;
}

/* The section headers come from the file on disk, which an attacker who can edit the file can
 * rewrite; the loader never reads them. So the range must lie entirely inside one
 * executable, non-writable PT_LOAD of the image that is actually mapped. This turns a bad
 * header into an error instead of a wild read or a redirect to unrelated memory. */
static int range_in_exec_segment(const main_image_ctx_t *img, uint64_t addr, uint64_t size) {
    if (size == 0u || addr + size < addr) {
        return 0;
    }
    for (size_t i = 0; i < img->phnum; i++) {
        const Elf64_Phdr *p = &img->phdr[i];
        if (p->p_type != PT_LOAD || (p->p_flags & PF_X) == 0u || (p->p_flags & PF_W) != 0u) {
            continue;
        }
        if (p->p_filesz <= p->p_memsz && p->p_vaddr <= addr &&
            addr - p->p_vaddr <= p->p_filesz && size <= p->p_filesz - (addr - p->p_vaddr)) {
            return 1;
        }
    }
    return 0;
}

int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size) {
    if (out_ptr == NULL || out_size == NULL) {
        return -1;
    }

    main_image_ctx_t img = { 0, NULL, 0, 0 };
    dl_iterate_phdr(find_main_image_cb, &img);
    if (!img.found) {
        return -1;
    }

    FILE *fp = fopen("/proc/self/exe", "rb");
    if (fp == NULL) {
        return -1;
    }

    struct stat st;
    if (fstat(fileno(fp), &st) != 0 || st.st_size <= 0) {
        fclose(fp);
        return -1;
    }
    uint64_t fsize = (uint64_t)st.st_size;

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
    if (ehdr.e_shoff > fsize || sh_table_size > fsize - ehdr.e_shoff) {
        fclose(fp);
        return -1;
    }
    Elf64_Shdr *shdrs = (Elf64_Shdr *)malloc(sh_table_size);
    if (shdrs == NULL) {
        fclose(fp);
        return -1;
    }

    if (fseeko(fp, (off_t)ehdr.e_shoff, SEEK_SET) != 0 ||
        fread(shdrs, 1, sh_table_size, fp) != sh_table_size) {
        free(shdrs);
        fclose(fp);
        return -1;
    }

    Elf64_Shdr strtab_hdr = shdrs[ehdr.e_shstrndx];
    if (strtab_hdr.sh_offset > fsize || strtab_hdr.sh_size > fsize - strtab_hdr.sh_offset) {
        free(shdrs);
        fclose(fp);
        return -1;
    }
    char *strtab = (char *)malloc((size_t)strtab_hdr.sh_size + 1);
    if (strtab == NULL) {
        free(shdrs);
        fclose(fp);
        return -1;
    }

    if (fseeko(fp, (off_t)strtab_hdr.sh_offset, SEEK_SET) != 0 ||
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
            if (!range_in_exec_segment(&img, shdrs[i].sh_addr, shdrs[i].sh_size)) {
                break;
            }
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
