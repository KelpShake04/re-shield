#if defined(__linux__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <elf.h>
#include <limits.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>

extern const void *reshield_internal_record_anchor(void);

typedef struct {
    uintptr_t         base_addr;
    const Elf64_Phdr *phdr;
    size_t            phnum;
    char              path[PATH_MAX]; /* file the image was loaded from */
    int               found;          /* the record's image was located */
    int               have_path;      /* path is set (else: ask /proc/self/maps) */
} module_image_ctx_t;

#define MAPS_LINE_MAX ((size_t)PATH_MAX + 128u) /* "lo-hi perms off dev inode" + path */

static int anchor_in_image(const struct dl_phdr_info *info, uintptr_t anchor) {
    for (size_t i = 0; i < info->dlpi_phnum; i++) {
        const Elf64_Phdr *p = &info->dlpi_phdr[i];
        uintptr_t lo = (uintptr_t)info->dlpi_addr + (uintptr_t)p->p_vaddr;
        if (p->p_type == PT_LOAD && anchor >= lo && anchor - lo < (uintptr_t)p->p_memsz) {
            return 1;
        }
    }
    return 0;
}

/* Reads one line of at most cap-1 bytes into buf (NUL-terminated, '\n' dropped).
 * Returns 1 for a whole line, 2 when the line was longer (the prefix is kept, the rest is
 * discarded), 0 at EOF or on a read error. */
static int read_line(FILE *fp, char *buf, size_t cap) {
    size_t n = 0;
    int truncated = 0;
    int c;
    while ((c = getc(fp)) != EOF && c != '\n') {
        if (n + 1 < cap) {
            buf[n++] = (char)c;
        } else {
            truncated = 1;
        }
    }
    if (ferror(fp) || (c == EOF && n == 0 && !truncated)) {
        return 0;
    }
    buf[n] = '\0';
    return truncated ? 2 : 1;
}

static int parse_hex(const char **pp, uintptr_t *out) {
    const char *p = *pp;
    uintptr_t v = 0;
    for (;; p++) {
        unsigned d;
        if (*p >= '0' && *p <= '9') {
            d = (unsigned)(*p - '0');
        } else if (*p >= 'a' && *p <= 'f') {
            d = (unsigned)(*p - 'a') + 10u;
        } else {
            break;
        }
        if (v >> (sizeof(v) * 8 - 4) != 0) {
            return 0; /* would overflow */
        }
        v = (v << 4) | d;
    }
    if (p == *pp) {
        return 0; /* no digits */
    }
    *pp = p;
    *out = v;
    return 1;
}

/* Fallback when the loader's name for the image is relative (dlopen("./x.so")): the kernel's
 * /proc/self/maps shows the absolute path of the file mapped at the anchor. Line format:
 * "lo-hi perms offset dev inode<spaces>path"; the path may contain spaces, so it is everything
 * after the fifth field. Only the mapping with lo <= anchor < hi is used. Fails closed (-1)
 * when that line is malformed or over-long, has no path or a non-absolute one (anonymous,
 * "[heap]"), or its file was deleted or replaced ("... (deleted)"). */
static int path_from_proc_maps(uintptr_t anchor, char *out, size_t cap) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        return -1;
    }
    char line[MAPS_LINE_MAX];
    int rc = -1;
    int r;
    while ((r = read_line(fp, line, sizeof(line))) != 0) {
        const char *p = line;
        uintptr_t lo, hi;
        if (!parse_hex(&p, &lo) || *p++ != '-' || !parse_hex(&p, &hi) || *p++ != ' ') {
            break;
        }
        if (anchor < lo || anchor >= hi) {
            continue;
        }
        if (r == 2) {
            break;
        }
        for (int field = 0; field < 4; field++) {
            while (*p != '\0' && *p != ' ') {
                p++;
            }
            while (*p == ' ') {
                p++;
            }
        }
        size_t len = strlen(p);
        if (p[0] != '/' || len >= cap || (len >= 10 && strcmp(p + len - 10, " (deleted)") == 0)) {
            break;
        }
        memcpy(out, p, len + 1);
        rc = 0;
        break;
    }
    fclose(fp);
    return rc;
}

/* The image to hash is the one that contains the integrity record (the anchor), not
 * necessarily the main program: re-shield may be linked into a shared library. Its file is
 * /proc/self/exe when it is the main image (the entry whose program headers are the ones the
 * kernel passed in AT_PHDR; matching by an empty dlpi_name is wrong on musl, which fills the
 * name with the program path), otherwise dlpi_name when absolute, otherwise, for a non-empty
 * relative name (dlopen("./x.so")), the absolute path /proc/self/maps gives for the anchor's
 * mapping (path_from_proc_maps, read after dl_iterate_phdr returns so it does not run under
 * the loader lock). An empty name stays an error: under `ld.so ./prog` AT_PHDR describes the
 * loader and the main map has no name, and that case fails closed instead of guessing. */
static int find_module_image_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    module_image_ctx_t *ctx = (module_image_ctx_t *)data;
    if (!anchor_in_image(info, (uintptr_t)reshield_internal_record_anchor())) {
        return 0;
    }
    uintptr_t at_phdr = (uintptr_t)getauxval(AT_PHDR);
    const char *path = NULL;
    if (at_phdr != 0 && (uintptr_t)info->dlpi_phdr == at_phdr) {
        path = "/proc/self/exe";
    } else if (info->dlpi_name != NULL && info->dlpi_name[0] == '/') {
        path = info->dlpi_name;
    } else if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0') {
        return 1; /* unnamed non-main image: fail closed */
    }
    /* The record's image was found either way; a path that does not fit leaves found 0. */
    if (path != NULL && strlen(path) >= sizeof(ctx->path)) {
        return 1;
    }
    if (path != NULL) {
        strcpy(ctx->path, path);
        ctx->have_path = 1;
    }
    ctx->base_addr = (uintptr_t)info->dlpi_addr;
    ctx->phdr = info->dlpi_phdr;
    ctx->phnum = info->dlpi_phnum;
    ctx->found = 1;
    return 1;
}

/* The section headers come from the file on disk, which an attacker who can edit the file can
 * rewrite; the loader never reads them. So the range must lie entirely inside one
 * executable, non-writable PT_LOAD of the image that is actually mapped. This turns a bad
 * header into an error instead of a wild read or a redirect to unrelated memory. */
static int range_in_exec_segment(const module_image_ctx_t *img, uint64_t addr, uint64_t size) {
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

    module_image_ctx_t img; /* no static state: callers may verify from several threads */
    memset(&img, 0, sizeof(img));
    dl_iterate_phdr(find_module_image_cb, &img);
    if (!img.found) {
        return -1;
    }
    if (!img.have_path &&
        path_from_proc_maps((uintptr_t)reshield_internal_record_anchor(), img.path,
                            sizeof(img.path)) != 0) {
        return -1;
    }

    FILE *fp = fopen(img.path, "rb");
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
