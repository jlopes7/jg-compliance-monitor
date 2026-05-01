//
// Created by Joao Gonzalez on 4/22/2026.
//

#include <windows.h>
#include <wchar.h>
#include <stdlib.h>

#define PCRE2_CODE_UNIT_WIDTH 16
#define PCRE2_STATIC
#include <windows/pcre2/pcre2.h>

#include "utils.h"

static wchar_t *trim_in_place(wchar_t *s) {
    wchar_t *end;

    while (*s == L' ' || *s == L'\t' || *s == L'\r' || *s == L'\n') {
        s++;
    }

    if (*s == L'\0') {
        return s;
    }

    end = s + wcslen(s);
    while (end > s &&
           (end[-1] == L' ' || end[-1] == L'\t' || end[-1] == L'\r' || end[-1] == L'\n')) {
        end--;
    }

    *end = L'\0';
    return s;
}

static LPWSTR wcsdup_local(LPCWSTR src) {
    size_t len;
    LPWSTR dst;

    if (!src) {
        return NULL;
    }

    len = wcslen(src);
    dst = (LPWSTR)calloc(len + 1, sizeof(wchar_t));
    if (!dst) {
        return NULL;
    }

    wcscpy_s(dst, len + 1, src);
    return dst;
}

errorcode_t split_trimmed_list(LPCWSTR input, LPWSTR **list_out, size_t *count_out) {
    wchar_t *buffer;
    wchar_t *context = NULL;
    wchar_t *token;
    LPWSTR *list = NULL;
    size_t count = 0;
    size_t capacity = 0;
    errorcode_t rc = ST_CODE_FAILURE;

    if (!input || !list_out || !count_out) {
        return ST_CODE_INVALID_PARAM;
    }

    *list_out = NULL;
    *count_out = 0;

    buffer = wcsdup_local(input);
    if (!buffer) {
        return ST_CODE_FAILURE;
    }

    token = wcstok(buffer, L",", &context);
    while (token) {
        wchar_t *trimmed = trim_in_place(token);

        if (*trimmed != L'\0') {
            LPWSTR copy;

            if (count == capacity) {
                size_t new_capacity = (capacity == 0) ? 4 : capacity * 2;
                LPWSTR *new_list = realloc(list, new_capacity * sizeof(*list));
                if (!new_list) {
                    rc = ST_CODE_FAILURE;
                    goto cleanup;
                }
                list = new_list;
                capacity = new_capacity;
            }

            copy = wcsdup_local(trimmed);
            if (!copy) {
                rc = ST_CODE_FAILURE;
                goto cleanup;
            }

            list[count++] = copy;
        }

        token = wcstok(NULL, L",", &context);
    }

    *list_out = list;
    *count_out = count;
    list = NULL;
    rc = ST_CODE_SUCCESS;

    cleanup:
        if (list) {
            size_t i;
            for (i = 0; i < count; i++) {
                free(list[i]);
            }
            free(list);
        }

    free(buffer);
    return rc;
}

errorcode_t fs_get_directory_from_path(LPCWSTR file_path, LPWSTR dir_path, size_t size) {
    wchar_t temp_path[MAXPATHLEN];
    wchar_t *last_sep;

    if (!file_path || !dir_path || size == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    // Copy input path to a temporary buffer so the original is not modified
    wcsncpy_s(temp_path, MAXPATHLEN, file_path, _TRUNCATE);

    // Find the last path separator
    last_sep = wcsrchr(temp_path, PATH_SEPARATOR[0]);
    if (!last_sep) {
        return ST_CODE_INVALID_PATH;
    }

    // Terminate at the last separator to keep only the directory
    *last_sep = EMPTY_CHAR;

    // Copy result to output buffer
    wcsncpy_s(dir_path, size, temp_path, _TRUNCATE);

    return ST_CODE_SUCCESS;
}

LPWSTR _wstrdup(LPCWSTR src) {
    size_t len;
    LPWSTR dst;

    if (!src) return NULL;

    len = wcslen(src);
    dst = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WCHAR) * (len + 1));
    if (!dst) return NULL;

    memcpy(dst, src, sizeof(WCHAR) * len);
    dst[len] = L'\0';

    return dst;
}

BOOL fs_resource_exists(LPCWSTR path, path_type_t type) {
    DWORD attrs;

    if (path == NULL || path[0] == L'\0') {
        return FALSE;
    }

    attrs = GetFileAttributesW(path);

    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    switch (type) {
        case CONTAINER:
            return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;

        case LEAF:
            return (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;

        case UNIDENTIFIED:
        default:
            return TRUE;
    }
}

BOOL fs_join_path(LPCWSTR basedir, LPCWSTR res, LPWSTR buffer, size_t buffer_cch) {
    size_t len;

    if (basedir == NULL || res == NULL || buffer == NULL || buffer_cch == 0) {
        return FALSE;
    }

    buffer[0] = L'\0';

    len = wcslen(basedir);

    if (len == 0 || res[0] == L'\0') {
        return FALSE;
    }

    if (basedir[len - 1] == PATH_SEPARATOR[0]) {
        return swprintf_s(
            buffer,
            buffer_cch,
            L"%ls%ls",
            basedir,
            res
        ) >= 0;
    }

    return swprintf_s(
        buffer,
        buffer_cch,
        L"%ls%ls%ls",
        basedir,
        PATH_SEPARATOR,
        res
    ) >= 0;
}

DWORD get_default_worker_count(DWORD procfracnum) {
    SYSTEM_INFO si;
    DWORD procnum;

    GetSystemInfo(&si);

    if (si.dwNumberOfProcessors == 0) {
        return 4; // defensive fallback, should not normally happen
    }

    procnum = si.dwNumberOfProcessors / procfracnum;
    if (procnum <= 0) procnum = 1;

    return procnum;
}

errorcode_t fs_retrieve_directory(LPCWSTR filepath, LPWSTR dir, uint8_t level) {
    wchar_t temp_path[MAX_PATH];
    wchar_t *last_sep;
    uint8_t i;

    if (filepath == NULL || dir == NULL || level == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    dir[0] = L'\0';

    if (filepath[0] == L'\0') {
        return ST_CODE_INVALID_PATH;
    }

    ZeroMemory(temp_path, sizeof(temp_path));

    if (wcscpy_s(temp_path, _LPWLEN(temp_path), filepath) != 0) {
        return ST_CODE_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < level; i++) {
        last_sep = wcsrchr(temp_path, PATH_SEPARATOR[0]);

        if (last_sep == NULL) {
            dir[0] = L'\0';
            return ST_CODE_INVALID_PATH;
        }

        *last_sep = EMPTY_CHAR;
    }

    if (wcscpy_s(dir, MAX_PATH, temp_path) != 0) {
        dir[0] = L'\0';
        return ST_CODE_BUFFER_TOO_SMALL;
    }

    return ST_CODE_SUCCESS;
}

BOOL fs_contains_signature(LPCWSTR path, LPCWSTR pattern) {
    wchar_t temp[MAX_PATH];
    wchar_t *context = NULL;
    wchar_t *token;

    if (path == NULL || pattern == NULL) {
        return FALSE;
    }

    if (path[0] == L'\0' || pattern[0] == L'\0') {
        return FALSE;
    }

    /*
     * Pattern must be a simple path-part signature.
     * It cannot contain path separators.
     */
    if (wcschr(pattern, L'\\') != NULL || wcschr(pattern, L'/') != NULL) {
        return FALSE;
    }

    ZeroMemory(temp, sizeof(temp));

    if (wcscpy_s(temp, _LPWLEN(temp), path) != 0) {
        return FALSE;
    }

    token = wcstok_s(temp, PATH_SEPARATOR, &context);

    while (token != NULL) {
        if (wcsstr(token, pattern) != NULL) {
            return TRUE;
        }

        token = wcstok_s(NULL, PATH_SEPARATOR, &context);
    }

    return FALSE;
}

errorcode_t ends_with(LPCWSTR base, LPCWSTR comp, BOOL *result, size_t len) {
    size_t base_len;
    size_t comp_len;

    if (base == NULL || comp == NULL || result == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    *result = FALSE;

    base_len = wcslen(base);
    comp_len = (len == 0) ? wcslen(comp) : len;

    if (comp_len == 0) {
        *result = TRUE;
        return ST_CODE_SUCCESS;
    }

    if (base_len < comp_len) {
        return ST_CODE_SUCCESS;
    }

    *result = (wcsncmp(base + (base_len - comp_len), comp, comp_len) == 0);

    return ST_CODE_SUCCESS;
}

LPWSTR utf8_to_wide_dup(const char *src) {
    int needed;
    LPWSTR dst;

    if (!src) return NULL;

    needed = MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0);
    if (needed <= 0) return NULL;

    dst = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WCHAR) * needed);
    if (!dst) return NULL;

    if (MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, needed) == 0) {
        HeapFree(GetProcessHeap(), 0, dst);
        return NULL;
    }

    return dst;
}

errorcode_t init_model_config(INIT_MODEL_CONFIG *config) {
    *config = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(init_model_config_t));
    if (!*config) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    return ST_CODE_SUCCESS;
}

errorcode_t end_model_config(INIT_MODEL_CONFIG config) {
    if (!config) return ST_CODE_SUCCESS;

    if ( !HeapFree(GetProcessHeap(), 0, config)) return ST_CODE_FAILED_TO_RELEASE_RES ;
    config = NULL;

    return ST_CODE_SUCCESS;
}

errorcode_t regex_match(LPCWSTR input, LPCWSTR pattern, BOOL *matched) {
    pcre2_code *re;
    pcre2_match_data *match_data;
    int errornumber, rc;
    PCRE2_SIZE erroroffset;

    if (!input || !pattern || !matched) {
        return ST_CODE_INVALID_PARAM;
    }

    *matched = FALSE;

    re = pcre2_compile(
        (PCRE2_SPTR16)pattern,
        PCRE2_ZERO_TERMINATED,
        PCRE2_UTF,
        &errornumber,
        &erroroffset,
        NULL
    );

    if (!re) {
        return ST_CODE_FAILED_OPERATION;
    }

    match_data = pcre2_match_data_create_from_pattern(re, NULL);
    if (!match_data) {
        pcre2_code_free(re);
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    rc = pcre2_match(
        re,
        (PCRE2_SPTR16)input,
        wcslen(input),
        0,
        0,
        match_data,
        NULL
    );

    if (rc >= 0) {
        *matched = TRUE;
    } else if (rc == PCRE2_ERROR_NOMATCH) {
        *matched = FALSE;
    } else {
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
        return ST_CODE_FAILED_OPERATION;
    }

    pcre2_match_data_free(match_data);
    pcre2_code_free(re);

    return ST_CODE_SUCCESS;
}

errorcode_t get_hostname(LPWSTR hostname, DWORD hostname_size) {
    DWORD size;

    if (!hostname || hostname_size == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(hostname, hostname_size * sizeof(WCHAR));

    size = hostname_size;

    if (!GetComputerNameW(hostname, &size)) {
        return ST_CODE_FAILED_OPERATION;
    }

    return ST_CODE_SUCCESS;
}

errorcode_t get_total_available_vm(ULONGLONG *available_bytes) {
    MEMORYSTATUSEX mem;

    if (!available_bytes) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(&mem, sizeof(mem));
    mem.dwLength = sizeof(mem);

    if (!GlobalMemoryStatusEx(&mem)) {
        return ST_CODE_FAILED_OPERATION;
    }

    /*
     * Available virtual address space for the calling process.
     */
    *available_bytes = mem.ullAvailVirtual;

    return ST_CODE_SUCCESS;
}

errorcode_t get_os_name_version(LPWSTR output, DWORD output_cch) {
    HKEY hkey;
    WCHAR product_name[256];
    WCHAR display_version[64];
    WCHAR build[64];
    DWORD ubr;
    DWORD size;
    DWORD type;

    if (!output || output_cch == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(output, output_cch * sizeof(WCHAR));
    ZeroMemory(product_name, sizeof(product_name));
    ZeroMemory(display_version, sizeof(display_version));
    ZeroMemory(build, sizeof(build));
    ubr = 0;

    if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0,
            KEY_READ,
            &hkey
        ) != ERROR_SUCCESS) {
        return ST_CODE_READ_READ_REGVAL;
        }

    size = sizeof(product_name);
    type = REG_SZ;
    RegQueryValueExW(hkey, L"ProductName", NULL, &type, (LPBYTE)product_name, &size);

    size = sizeof(display_version);
    type = REG_SZ;
    RegQueryValueExW(hkey, L"DisplayVersion", NULL, &type, (LPBYTE)display_version, &size);

    size = sizeof(build);
    type = REG_SZ;
    RegQueryValueExW(hkey, L"CurrentBuildNumber", NULL, &type, (LPBYTE)build, &size);

    size = sizeof(ubr);
    type = REG_DWORD;
    RegQueryValueExW(hkey, L"UBR", NULL, &type, (LPBYTE)&ubr, &size);

    RegCloseKey(hkey);

    if (product_name[0] == L'\0') {
        return ST_CODE_FAILED_OPERATION;
    }

    if (display_version[0] != L'\0' && build[0] != L'\0') {
        swprintf_s(
            output,
            output_cch,
            L"%ls %ls Build %ls.%lu",
            product_name,
            display_version,
            build,
            ubr
        );
    }
    else if (build[0] != L'\0') {
        swprintf_s(
            output,
            output_cch,
            L"%ls Build %ls.%lu",
            product_name,
            build,
            ubr
        );
    }
    else {
        wcsncpy_s(output, output_cch, product_name, _TRUNCATE);
    }

    return ST_CODE_SUCCESS;
}

errorcode_t get_os_version(LPWSTR output, DWORD output_cch) {
    OSVERSIONINFOEXW osvi;

    if (!output || output_cch == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(output, output_cch * sizeof(WCHAR));
    ZeroMemory(&osvi, sizeof(osvi));

    osvi.dwOSVersionInfoSize = sizeof(osvi);

#pragma warning(push)
#pragma warning(disable:4996)
    if (!GetVersionExW((OSVERSIONINFOW *)&osvi)) {
#pragma warning(pop)
        return ST_CODE_FAILED_OPERATION;
    }
#pragma warning(pop)

    swprintf_s(
        output,
        output_cch,
        L"%lu.%lu.%lu",
        osvi.dwMajorVersion,
        osvi.dwMinorVersion,
        osvi.dwBuildNumber
    );

    return ST_CODE_SUCCESS;
}

errorcode_t get_logical_core_count(DWORD *vcpu_count) {
    SYSTEM_INFO si;

    if (!vcpu_count) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(&si, sizeof(si));
    GetSystemInfo(&si);

    *vcpu_count = si.dwNumberOfProcessors;

    return ST_CODE_SUCCESS;
}

errorcode_t get_physical_core_count(DWORD *physical_core_count) {
    DWORD len = 0;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION ptr;
    DWORD offset;
    DWORD count = 0;

    if (!physical_core_count) {
        return ST_CODE_INVALID_PARAM;
    }

    *physical_core_count = 0;

    GetLogicalProcessorInformation(NULL, &len);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return ST_CODE_FAILED_OPERATION;
    }

    buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    if (!buffer) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    if (!GetLogicalProcessorInformation(buffer, &len)) {
        HeapFree(GetProcessHeap(), 0, buffer);
        return ST_CODE_FAILED_OPERATION;
    }

    ptr = buffer;
    offset = 0;

    while (offset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) <= len) {
        if (ptr->Relationship == RelationProcessorCore) {
            count++;
        }

        ptr++;
        offset += sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    }

    HeapFree(GetProcessHeap(), 0, buffer);

    *physical_core_count = count;

    return ST_CODE_SUCCESS;
}

errorcode_t get_env_var_val(LPCWSTR varname, LPWSTR value, DWORD value_cch) {
    DWORD needed;

    if (!varname || !value) {
        return ST_CODE_INVALID_PARAM;
    }

    value[0] = L'\0';

    needed = GetEnvironmentVariableW(varname, value, value_cch);

    if (needed == 0) {
        DWORD err = GetLastError();

        if (err == ERROR_ENVVAR_NOT_FOUND) {
            value[0] = L'\0';
            return ST_CODE_SUCCESS;
        }

        return ST_CODE_FAILED_OPERATION;
    }

    if (needed >= value_cch) {
        value[0] = L'\0';
        return ST_CODE_BUFFER_TOO_SMALL;
    }

    return ST_CODE_SUCCESS;
}

LPWSTR heap_wcsdup(LPCWSTR src) {
    size_t len;
    LPWSTR dst;

    if (!src) return NULL;

    len = wcslen(src);
    dst = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(wchar_t) * (len + 1));
    if (!dst) return NULL;

    wcscpy_s(dst, len + 1, src);
    return dst;
}

BOOL fs_compare_line_in_file(LPCWSTR filepath, LPCWSTR comparator, DWORD line_number) {
    FILE *fp = NULL;
    wchar_t line[BUFFER_SIZE];
    wchar_t last_line[BUFFER_SIZE];
    DWORD current_line = 0;
    errno_t err;

    if (!filepath || !comparator) {
        return FALSE;
    }

    line[0] = L'\0';
    last_line[0] = L'\0';

    err = _wfopen_s(&fp, filepath, L"r, ccs=UTF-8");
    if (err != 0 || fp == NULL) {
        return FALSE;
    }

    while (fgetws(line, _LPWLEN(line), fp)) {
        current_line++;

        line[wcscspn(line, LINE_BREAK)] = L'\0';
        wcsncpy_s(last_line, _LPWLEN(last_line), line, _TRUNCATE);

        if (current_line == line_number) {
            fclose(fp);
            return wcscmp(line, comparator) == 0;
        }
    }

    fclose(fp);

    /*
     * If requested line does not exist, compare with last file line.
     * Empty file -> last_line remains empty.
     */
    return _wcsicmp(last_line, comparator) == 0;
}

errorcode_t init_file_prop_read(LPCWSTR file, FILE_PROP_READER *reader) {
    FILE_PROP_READER local_reader;
    errno_t err;

    if (!file || !reader) {
        return ST_CODE_INVALID_PARAM;
    }

    *reader = NULL;

    if (!fs_resource_exists(file, LEAF)) {
        return ST_CODE_PROPFILE_DOESNTEXIST;
    }

    local_reader = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(file_prop_reader_t));
    if (!local_reader) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    err = _wfopen_s(&PTR(local_reader).fp, file, L"r, ccs=UTF-8");
    if (err != 0 || PTR(local_reader).fp == NULL) {
        HeapFree(GetProcessHeap(), 0, local_reader);
        return ST_CODE_IO_OPEN_FAILED;
    }

    PTR(local_reader).file = file;
    *reader = local_reader;

    return ST_CODE_SUCCESS;
}

errorcode_t end_file_prop_read(FILE_PROP_READER reader) {
    if (!reader) {
        return ST_CODE_SUCCESS;
    }

    if (reader->fp) {
        fclose(PTR(reader).fp);
        PTR(reader).fp = NULL;
    }

    HeapFree(GetProcessHeap(), 0, reader);

    return ST_CODE_SUCCESS;
}

static errorcode_t get_file_prop_val_from_reader(
    FILE_PROP_READER reader,
    LPCWSTR propname,
    LPWSTR buffer,
    DWORD buffer_cch
) {
    wchar_t line[BUFFER_SIZE];

    if (!reader || !PTR(reader).fp || !propname || !buffer || buffer_cch == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    buffer[0] = L'\0';

    rewind(PTR(reader).fp);

    while (fgetws(line, _LPWLEN(line), reader->fp)) {
        wchar_t *p;
        wchar_t *eq;
        wchar_t *key;
        wchar_t *value;
        size_t value_len;

        line[wcscspn(line, L"\r\n")] = L'\0';

        p = trim_in_place(line);

        if (*p == L'\0' || *p == L'#' || *p == L';') {
            continue;
        }

        eq = wcschr(p, L'=');
        if (!eq) {
            continue;
        }

        *eq = L'\0';

        key = trim_in_place(p);
        value = trim_in_place(eq + 1);

        if (wcscmp(key, propname) != 0) {
            continue;
        }

        value_len = wcslen(value);

        if (value_len >= 2 && value[0] == L'"' && value[value_len - 1] == L'"') {
            value[value_len - 1] = L'\0';
            value++;
        }

        if (wcslen(value) + 1 > buffer_cch) {
            return ST_CODE_BUFFER_TOO_SMALL;
        }

        wcsncpy_s(buffer, buffer_cch, value, _TRUNCATE);
        return ST_CODE_SUCCESS;
    }

    return ST_CODE_PROP_NOT_FOUND;
}

errorcode_t get_file_prop_val(
    LPCWSTR propname,
    LPWSTR buffer,
    DWORD buffer_cch,
    FILE_PROP_READER file
) {
    if (!file) {
        return ST_CODE_INVALID_PARAM;
    }

    return get_file_prop_val_from_reader(
        file,
        propname,
        buffer,
        buffer_cch
    );
}

errorcode_t wstr_tokenize(
    LPCWSTR input,
    LPCWSTR delim,
    LPWSTR **tokens_out,
    DWORD *count_out
) {
    LPWSTR buffer = NULL;
    LPWSTR context = NULL;
    LPWSTR token;
    LPWSTR *tokens = NULL;
    DWORD count = 0;
    DWORD capacity = 0;

    if (!input || !delim || !tokens_out || !count_out) {
        return ST_CODE_INVALID_PARAM;
    }

    *tokens_out = NULL;
    *count_out = 0;

    buffer = heap_wcsdup(input);
    if (!buffer) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    token = wcstok_s(buffer, delim, &context);

    while (token) {
        if (count == capacity) {
            DWORD new_capacity = (capacity == 0) ? 4 : capacity * 2;
            LPWSTR *new_tokens;
            if (tokens == NULL) {
                new_tokens = HeapAlloc(
                    GetProcessHeap(),
                    HEAP_ZERO_MEMORY,
                    new_capacity * sizeof(LPWSTR)
                );
            }
            else {
                new_tokens = HeapReAlloc(
                    GetProcessHeap(),
                    HEAP_ZERO_MEMORY,
                    tokens,
                    new_capacity * sizeof(LPWSTR)
                );
            }

            if (!new_tokens) {
                HeapFree(GetProcessHeap(), 0, buffer);
                return ST_CODE_MEMORY_ALLOCATION_FAILED;
            }

            tokens = new_tokens;
            capacity = new_capacity;
        }

        tokens[count] = heap_wcsdup(token);
        if (!tokens[count]) {
            for (DWORD i = 0; i < count; i++) {
                HeapFree(GetProcessHeap(), 0, tokens[i]);
            }

            HeapFree(GetProcessHeap(), 0, tokens);
            HeapFree(GetProcessHeap(), 0, buffer);

            return ST_CODE_MEMORY_ALLOCATION_FAILED;
        }

        count++;
        token = wcstok_s(NULL, delim, &context);
    }

    HeapFree(GetProcessHeap(), 0, buffer);

    *tokens_out = tokens;
    *count_out = count;

    return ST_CODE_SUCCESS;
}

void wstr_free_tokens(LPWSTR *tokens, DWORD count) {
    if (!tokens) return;

    for (DWORD i = 0; i < count; i++) {
        HeapFree(GetProcessHeap(), 0, tokens[i]);
    }

    HeapFree(GetProcessHeap(), 0, tokens);
}
