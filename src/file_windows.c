#ifdef _WIN32

#include "file_platform.h"

#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

/* Regular files only: UTF-8 path -> UTF-16, reparse points (symlinks, junctions) are
 * followed. Paths longer than MAX_PATH are not given a \\?\ prefix. */
int reshield_file_open_regular(const char *path, reshield_file_t *handle_out, uint64_t *size_out) {
    if (path == NULL || handle_out == NULL) {
        return -1;
    }
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (wlen <= 0) {
        return -1;
    }
    wchar_t *wpath = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
    if (wpath == NULL) {
        return -1;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wpath, wlen) != wlen) {
        free(wpath);
        return -1;
    }
    HANDLE h = CreateFileW(wpath, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }
    FILE_STANDARD_INFO info;
    if (GetFileType(h) != FILE_TYPE_DISK ||
        !GetFileInformationByHandleEx(h, FileStandardInfo, &info, sizeof(info)) ||
        info.Directory || info.EndOfFile.QuadPart < 0) {
        CloseHandle(h);
        return -1;
    }
    *handle_out = (reshield_file_t)h;
    if (size_out != NULL) {
        *size_out = (uint64_t)info.EndOfFile.QuadPart;
    }
    return 0;
}

intptr_t reshield_file_read(reshield_file_t handle, void *buf, size_t n) {
    DWORD want = n > 0x40000000u ? 0x40000000u : (DWORD)n;
    DWORD got = 0;
    if (!ReadFile((HANDLE)handle, buf, want, &got, NULL)) {
        return GetLastError() == ERROR_HANDLE_EOF ? 0 : -1;
    }
    return (intptr_t)got;
}

void reshield_file_close(reshield_file_t handle) {
    CloseHandle((HANDLE)handle);
}

#define WALK_PATH_MAX 4096u

typedef struct {
    wchar_t  path[WALK_PATH_MAX]; /* full UTF-16 path of the directory being read */
    char     rel[WALK_PATH_MAX];  /* base-relative UTF-8 path with '/' separators */
    unsigned max_depth;
    size_t   max_entries;
    size_t   count;
    int    (*visit)(const char *, void *);
    void    *ctx;
} walk_t;

static int is_sep(wchar_t c) {
    return c == L'\\' || c == L'/';
}

/* path[0..wlen) is the directory, rel[0..rlen) its relative UTF-8 name. Returns 0, 1 or -1. */
static int walk_dir(walk_t *w, size_t wlen, size_t rlen, unsigned depth) {
    size_t wsep = (wlen > 0 && is_sep(w->path[wlen - 1])) ? 0u : 1u;
    if (wlen + wsep + 2u > WALK_PATH_MAX) {
        return -1;
    }
    if (wsep) {
        w->path[wlen] = L'\\';
    }
    w->path[wlen + wsep] = L'*';
    w->path[wlen + wsep + 1u] = L'\0';
    WIN32_FIND_DATAW fd;
    /* Every existing directory yields at least "." and "..", so INVALID_HANDLE_VALUE is an error. */
    HANDLE h = FindFirstFileExW(w->path, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, 0);
    w->path[wlen] = L'\0';
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }
    size_t rsep = rlen > 0 ? 1u : 0u;
    int rc = 0;
    for (;;) {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            size_t wn = wcslen(fd.cFileName);
            char utf8[4 * MAX_PATH];
            int un = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fd.cFileName, -1,
                                         utf8, (int)sizeof(utf8), NULL, NULL);
            if (un <= 1 || wlen + wsep + wn + 1u > WALK_PATH_MAX ||
                rlen + rsep + (size_t)(un - 1) + 1u > WALK_PATH_MAX || ++w->count > w->max_entries) {
                rc = -1;
                break;
            }
            size_t child_w = wlen + wsep + wn;
            size_t child_r = rlen + rsep + (size_t)(un - 1);
            if (wsep) {
                w->path[wlen] = L'\\';
            }
            memcpy(w->path + wlen + wsep, fd.cFileName, (wn + 1u) * sizeof(wchar_t));
            if (rsep) {
                w->rel[rlen] = '/';
            }
            memcpy(w->rel + rlen + rsep, utf8, (size_t)un);
            /* A reparse point (symlink, junction) is an item even when it points at a directory. */
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                if (depth + 1u > w->max_depth) {
                    rc = -1;
                    break;
                }
                rc = walk_dir(w, child_w, child_r, depth + 1u);
            } else {
                rc = w->visit(w->rel, w->ctx) != 0 ? 1 : 0;
            }
            w->path[wlen] = L'\0';
            w->rel[rlen] = '\0';
            if (rc != 0) {
                break;
            }
        }
        if (!FindNextFileW(h, &fd)) {
            rc = GetLastError() == ERROR_NO_MORE_FILES ? 0 : -1;
            break;
        }
    }
    FindClose(h);
    return rc;
}

int reshield_dir_walk(const char *base_dir, unsigned max_depth, size_t max_entries,
                      int (*visit)(const char *rel_path, void *ctx), void *ctx) {
    if (visit == NULL) {
        return -1;
    }
    if (base_dir == NULL || base_dir[0] == '\0') {
        base_dir = ".";
    }
    walk_t *w = (walk_t *)malloc(sizeof(*w)); /* 12 KiB: keep it off the recursion stack */
    if (w == NULL) {
        return -1;
    }
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, base_dir, -1,
                                   w->path, (int)(WALK_PATH_MAX - 2u));
    if (wlen <= 1) {
        free(w);
        return -1;
    }
    size_t len = (size_t)wlen - 1u;
    while (len > 1u && is_sep(w->path[len - 1]) && w->path[len - 2] != L':') {
        w->path[--len] = L'\0';
    }
    w->rel[0] = '\0';
    w->max_depth = max_depth;
    w->max_entries = max_entries;
    w->count = 0;
    w->visit = visit;
    w->ctx = ctx;
    int rc = walk_dir(w, len, 0, 0);
    free(w);
    return rc;
}

#else
typedef int reshield_file_windows_unused_t;
#endif
