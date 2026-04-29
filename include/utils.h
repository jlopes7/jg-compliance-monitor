//
// Created by Joao Gonzalez on 4/21/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_UTILS_H
#define JG_COMPLIANCE_MONITOR_UTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#if defined(WIN32)
#   include <wchar.h>
#   include <windows.h>
#endif

#include "errcodes.h"
#include "model/basemdl.h"

#define MAX_STRING_LEN          1024
#define INT_MAX_LEN     10

#define SMALL_BUFFER    0x00000010 /*16*/
#define LOW_BUFFER_SIZE 0x00000400 /*1K*/
#define BUFFER_SIZE	    0x00001000 /*4K*/
#define MID_BUFFER_SIZE	0x00008000 /*32K*/
#define MAX_BUFFER_SIZE	0x00100000 /*1M*/
#define MAX_LOG_FILE    0x00000400 /*1K*/


#define UNDEFINED_ATTRIBUTE     L"Unknown Value"

#if !defined (MAXPATHLEN)
#   define MAXPATHLEN	MAX_LOG_FILE
#endif
#if !defined (MAXARRAYSIZE)
#   define MAXARRAYSIZE	BUFFER_SIZE /*4KB arrays only*/
#endif

#if defined(_WIN32)
#   define LINE_BREAK       L"\r\n"
#   define PATH_SEPARATOR   L"\\"
#   define PATH_DELIMITER   L";"
#else
#   define LINE_BREAK       "\n"
#   define PATH_SEPARATOR   "/"
#   define PATH_DELIMITER   ";"
#endif
#define EMPTY_CHAR      L'\0'

#define PTR(X)              (*(X))

#define ARRAY_LEN_COUNT(arr)   (sizeof(arr) / sizeof((arr)[0]))

#if defined(_WIN32) || defined(_WIN64)
#   define SLEEP_S(ms) Sleep((ms) * 1000)
#   define SLEEP_MS(ms) Sleep((ms))
#   define CREATE_DIR(path) _wmkdir(path)
#else
#   include <unistd.h>   // Unix sleep function
#   define SLEEP_S(ms) usleep((ms) * 1000 * 1000)
#   define SLEEP_MS(ms) usleep((ms) * 1000)
#   define CREATE_DIR(path) mkdir(path, 0775)
#endif

#define _MEMZERO(var, size) memset( (var), 0, (size) )
#define _IS_SUCCESS(x)      ( ((x) == EXIT_SUCCESS) || ((x) == ST_CODE_SUCCESS) )
#define _IS_TRUE(X)         ( ((uint8_t)X) == 1 )
#define _MAP_FROM_EVTTOLOG_LVL(X)   ( (X) == LOGLEVEL_INFO || (X) == LOGLEVEL_WARN ) ? LOGGING_NORMAL : LOGGING_ERROR

#define _IS_TRUE_STRING(X) ( (X) != NULL && ( \
                             _wcsicmp((X), L"true") == 0 || \
                             _wcsicmp((X), L"yes") == 0 || \
                             _wcsicmp((X), L"active") == 0 || \
                             _wcsicmp((X), L"yep") == 0 ) )

#define _LPWLEN(s)          ( sizeof((s)) / sizeof((s)[0]) )

#define WSTRICMP(X, Y, L)   ((CompareStringOrdinal((X), (L), (Y), (L), TRUE)) == CSTR_EQUAL)

#define SWAP_ENDIAN(v)  ( (((v) >> 24) & 0x000000FF) | \
                          (((v) >> 8)  & 0x0000FF00) | \
                          (((v) << 8)  & 0x00FF0000) | \
                          (((v) << 24) & 0xFF000000) )

typedef enum path_type {
    CONTAINER,
    LEAF,
    UNIDENTIFIED
} path_type_t;

#if defined(WIN32)
errorcode_t split_trimmed_list(LPCWSTR input, LPWSTR **list_out, size_t *count_out);
errorcode_t get_directory_from_path(LPCWSTR file_path, LPWSTR dir_path, size_t size);
BOOL fs_resource_exists(LPCWSTR path, path_type_t type);
BOOL fs_join_path(LPCWSTR basedir, LPCWSTR res, LPWSTR buffer, size_t buffer_cch);
BOOL fs_contains_signature(LPCWSTR path, LPCWSTR pattern);

errorcode_t retrieve_directory(LPCWSTR filepath, LPWSTR dir, uint8_t level);
errorcode_t ends_with(LPCWSTR base, LPCWSTR comp, BOOL *result, size_t len);

LPWSTR _wstrdup(LPCWSTR src);
LPWSTR heap_wcsdup(LPCWSTR src);
LPWSTR utf8_to_wide_dup(const char *src);
DWORD get_default_worker_count(void);

errorcode_t regex_match(LPCWSTR input, LPCWSTR pattern, BOOL *matched);

errorcode_t init_model_config(INIT_MODEL_CONFIG *config);
errorcode_t end_model_config(INIT_MODEL_CONFIG config);

errorcode_t get_hostname(LPWSTR hostname, DWORD hostname_size);
errorcode_t get_total_available_vm(ULONGLONG *available_bytes);
errorcode_t get_os_name_version(LPWSTR output, DWORD output_cch);
errorcode_t get_os_version(LPWSTR output, DWORD output_cch);
errorcode_t get_logical_core_count(DWORD *vcpu_count);
errorcode_t get_physical_core_count(DWORD *physical_core_count);
errorcode_t get_env_var_val(LPCWSTR varname, LPWSTR value);
#endif

#endif //JG_COMPLIANCE_MONITOR_UTILS_H
