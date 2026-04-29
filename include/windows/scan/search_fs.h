//
// Created by Joao Gonzalez on 4/23/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_SEARCH_FS_H
#define JG_COMPLIANCE_MONITOR_SEARCH_FS_H

#include "utils.h"
#include "windows/win-queue.h"

#if defined(_WIN32)
#include <windows.h>
#endif

#define FS_SEARCH_MAX_WORKERS          0x00000010   /*16*/
#define FS_SEARCH_MIN_WORKERS          0x00000001   /*1*/
#define FS_SEARCH_QUEUE_CAPACITY       0x00001000   /*4096*/
#define FS_SEARCH_MAX_PATH_EX          0x00007FFF   /*32767*/
#define FS_SEARCH_PATH_CCH             0x00007FFF   /*32767*/

#define FS_QUEUE_NAME                  L"FS_SEARCH_Q"

#define GOOGLE_DRIVE_VOLUME_LABEL      L"Google Drive"

typedef struct _fs_search_stats {
    volatile LONG files_checked;
    volatile LONG dirs_checked;
    volatile LONG dirs_skipped;
    volatile LONG matches_found;
    volatile LONG access_denied;
} fs_search_stats_t;

typedef BOOL (*fs_search_match_cb)(
    LPCWSTR full_path,
    const WIN32_FIND_DATAW *find_data,
    void *user_ctx
);

typedef struct _fs_search_options {
    HANDLE stop_event;
    LPCWSTR target_name;            /* e.g., L"java.exe" */
    DWORD worker_count;             /* e.g., 1 ... 16 */
    BOOL fixed_drives_only;
    BOOL stop_on_first_match;
    fs_search_match_cb on_match;
    void *user_ctx;
} fs_search_options_t;

typedef struct _fs_runtime {
    fs_search_options_t options;
    fs_search_stats_t *stats;
    QUEUE queue;
    volatile LONG found;
} fs_runtime_t;

typedef struct _fs_worker_ctx {
    fs_runtime_t *runtime;
    SYSTEM_DETAILS *sysdetails;
} fs_worker_ctx_t;

typedef fs_runtime_t    *FS_RUNTIME;
typedef fs_worker_ctx_t *FS_WORKER_CTX;

errorcode_t fs_search_execute(const fs_search_options_t *options, fs_search_stats_t *stats);

#endif //JG_COMPLIANCE_MONITOR_SEARCH_FS_H
