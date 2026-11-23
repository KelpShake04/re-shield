#ifdef _WIN32

#include "file_platform.h"

#include <stdlib.h>
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

#else
typedef int reshield_file_windows_unused_t;
#endif
