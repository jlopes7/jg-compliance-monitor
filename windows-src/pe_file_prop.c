//
// Created by Joao Gonzalez on 4/27/2026.
//

#include "windows/pe_file_prop.h"

#include <windows.h>
#include <winver.h>

#include "windows/logging.h"

errorcode_t pe_open(LPCWSTR filepath, PE_FILE *pe) {
    DWORD handle = 0;
    DWORD version_size;
    PE_FILE local_pe;
    LANGANDCODEPAGE *translation = NULL;
    UINT trans_len = 0;

    if (!filepath || !pe) {
        return ST_CODE_INVALID_PARAM;
    }

    *pe = NULL;

    version_size = GetFileVersionInfoSizeW(filepath, &handle);
    if (version_size == 0) {
        return ST_CODE_FAILED_OPERATION;
    }

    local_pe = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(pe_file_t));
    if (!local_pe) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    PTR(local_pe).version_block = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, version_size);
    if (!PTR(local_pe).version_block) {
        HeapFree(GetProcessHeap(), 0, local_pe);
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    PTR(local_pe).version_size = version_size;

    if (!GetFileVersionInfoW(filepath, 0, version_size, PTR(local_pe).version_block)) {
        pe_close(local_pe);
        return ST_CODE_FAILED_OPERATION;
    }

    if (!VerQueryValueW(
            PTR(local_pe).version_block,
            L"\\VarFileInfo\\Translation",
            (LPVOID *)&translation,
            &trans_len
        ) || trans_len < sizeof(LANGANDCODEPAGE)) {
        pe_close(local_pe);
        return ST_CODE_FAILED_OPERATION;
    }

    PTR(local_pe).language = translation[0].language;
    PTR(local_pe).codepage = translation[0].codepage;
    PTR(local_pe).file_name = filepath;

    *pe = local_pe;
    return ST_CODE_SUCCESS;
}

errorcode_t pe_get_prop_dword(
    PE_FILE pe,
    LPCWSTR prop_name,
    DWORD *value
) {
    VS_FIXEDFILEINFO *info = NULL;
    UINT len = 0;

    if (!pe || !prop_name || !value) {
        return ST_CODE_INVALID_PARAM;
    }

    *value = 0;

    if (!VerQueryValueW(
            PTR(pe).version_block,
            L"\\",
            (LPVOID *)&info,
            &len
        ) || !info || len < sizeof(VS_FIXEDFILEINFO)) {
        return ST_CODE_FAILED_OPERATION;
        }

    if (info->dwSignature != VS_FFI_SIGNATURE) {
        return ST_CODE_FAILED_OPERATION;
    }

    if (wcscmp(prop_name, PE_PROP_MAJORVERSION) == 0) {
        *value = HIWORD(info->dwFileVersionMS);
        return ST_CODE_SUCCESS;
    }

    if (wcscmp(prop_name, PE_PROP_MINORVERSION) == 0) {
        *value = LOWORD(info->dwFileVersionMS);
        return ST_CODE_SUCCESS;
    }

    if (wcscmp(prop_name, PE_PROP_BUILDVERSION) == 0) {
        *value = HIWORD(info->dwFileVersionLS);
        return ST_CODE_SUCCESS;
    }

    if (wcscmp(prop_name, PE_PROP_REVISIONVERSION) == 0) {
        *value = LOWORD(info->dwFileVersionLS);
        return ST_CODE_SUCCESS;
    }

    return ST_CODE_PROP_NOT_FOUND;
}

errorcode_t pe_get_prop(PE_FILE pe, LPCWSTR prop_name, LPWSTR value, size_t value_cch) {
    WCHAR query[256];
    LPWSTR prop_value = NULL;
    UINT prop_len = 0;

    if (!pe || !prop_name || !value || value_cch == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    value[0] = L'\0';

    swprintf_s(
        query,
        _LPWLEN(query),
        L"\\StringFileInfo\\%04x%04x\\%ls",
        PTR(pe).language,
        PTR(pe).codepage,
        prop_name
    );

    logmsg(LOGGING_NORMAL,
        L"[FS CRAWLER] Querying the file(%ls) PE for: %ls. Query: %ls",
                PTR(pe).file_name,
                prop_name,
                query);

    if (!VerQueryValueW(
            PTR(pe).version_block,
            query,
            (LPVOID *)&prop_value,
            &prop_len
        ) || !prop_value || prop_len == 0) {
        return ST_CODE_FAILED_OPERATION;
    }

    wcsncpy_s(value, value_cch, prop_value, _TRUNCATE);

    return ST_CODE_SUCCESS;
}

errorcode_t pe_close(PE_FILE pe) {
    if (!pe) {
        return ST_CODE_SUCCESS;
    }

    if (PTR(pe).version_block) {
        HeapFree(GetProcessHeap(), 0, PTR(pe).version_block);
        PTR(pe).version_block = NULL;
    }

    HeapFree(GetProcessHeap(), 0, pe);
    return ST_CODE_SUCCESS;
}
