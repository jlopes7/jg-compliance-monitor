//
// Created by Joao Gonzalez on 4/23/2026.
//

#include "windows/scan/search_fs.h"
#include "windows/logging.h"
#include "windows/db/agent_db.h"

#include <strsafe.h>
#include <tgmath.h>

#include "windows/evtlog.h"

static DWORD WINAPI fs_worker_thread(LPVOID param);
static void fs_free_queue_item(QUEUE_ITEM item);

static BOOL fs_should_stop(HANDLE stop_event) {
    return stop_event && WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0;
}

static BOOL fs_is_dot_dir(LPCWSTR name) {
    return wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0;
}

static BOOL fs_is_unc_path(LPCWSTR path) {
    return path && path[0] == L'\\' && path[1] == L'\\';
}

static BOOL fs_is_on_volume_label(LPCWSTR path, LPCWSTR expected_label) {
    WCHAR volume_root[MAX_PATH];
    WCHAR volume_name[MAX_PATH];

    if (!path || !expected_label) {
        return FALSE;
    }

    ZeroMemory(volume_root, sizeof(volume_root));
    ZeroMemory(volume_name, sizeof(volume_name));

    if (!GetVolumePathNameW(path, volume_root, _LPWLEN(volume_root))) {
        return FALSE;
    }

    if (!GetVolumeInformationW(
            volume_root,
            volume_name,
            _LPWLEN(volume_name),
            NULL,
            NULL,
            NULL,
            NULL,
            0)) {
        return FALSE;
            }

    return _wcsicmp(volume_name, expected_label) == 0;
}

static BOOL fs_is_google_drive_root(LPCWSTR root_path) {
    WCHAR drive_name[4];      // "G:"
    WCHAR device_path[BUFFER_SIZE];

    if (!root_path || wcslen(root_path) < 2 || root_path[1] != L':') {
        return FALSE;
    }

    ZeroMemory(drive_name, sizeof(drive_name));
    ZeroMemory(device_path, sizeof(device_path));

    drive_name[0] = root_path[0];
    drive_name[1] = L':';
    drive_name[2] = L'\0';

    if (QueryDosDeviceW(drive_name, device_path, _LPWLEN(device_path))) {
        logmsg(LOGGING_NORMAL, L"[FS CRAWLER] Drive %ls maps to device: %ls", drive_name, device_path);
        if (
            wcsstr(device_path, L"Google") != NULL ||
            wcsstr(device_path, L"DriveFS") != NULL ||
            wcsstr(device_path, L"GoogleDrive") != NULL
        ) {
            return TRUE;
        }
    }

    /*
     * Fallback: only check the root-level Google Drive layout.
     * This is more reliable than checking arbitrary path substrings.
     */
    WCHAR my_drive[MAX_PATH];
    WCHAR shared_drives[MAX_PATH];

    swprintf_s(my_drive, _LPWLEN(my_drive), L"%c:\\My Drive", root_path[0]);
    swprintf_s(shared_drives, _LPWLEN(shared_drives), L"%c:\\Shared drives", root_path[0]);

    if (GetFileAttributesW(my_drive) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(shared_drives) != INVALID_FILE_ATTRIBUTES) {
        return TRUE;
        }

    return FALSE;
}

// CHECKS IF IT NEEDS TO SKIP REMOTE DIRECTORIES !!! (i.e., SMB folders)
static BOOL fs_should_skip_dir(LPCWSTR path, const WIN32_FIND_DATAW *fd) {
    DWORD attrs;

    if (!path || fs_is_unc_path(path)) {
        return TRUE;
    }

    if (fs_is_on_volume_label(path, GOOGLE_DRIVE_VOLUME_LABEL)) {
        logmsg(LOGGING_WARN, L"[FS CRAWLER] Skipping Google Drive volume path: %ls", path);
        return TRUE;
    }

    if (fd && (fd->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        return TRUE;
    }

    attrs = GetFileAttributesW(path);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
        return TRUE;
    }

    return FALSE;
}

static BOOL fs_join_path(LPCWSTR base, LPCWSTR name, LPWSTR out, size_t out_cch) {
    size_t len;

    if (!base || !name || !out) return FALSE;

    len = wcslen(base);

    if (len > 0 && base[len - 1] == L'\\') {
        return SUCCEEDED(StringCchPrintfW(out, out_cch, L"%ls%ls", base, name));
    }

    return SUCCEEDED(StringCchPrintfW(out, out_cch, L"%ls%ls%ls", base, PATH_SEPARATOR, name));
}

static BOOL fs_make_pattern(LPCWSTR dir, LPWSTR out, size_t out_cch) {
    size_t len;

    if (!dir || !out) return FALSE;

    len = wcslen(dir);

    if (len > 0 && dir[len - 1] == L'\\') {
        return SUCCEEDED(StringCchPrintfW(out, out_cch, L"%ls*", dir));
    }

    return SUCCEEDED(StringCchPrintfW(out, out_cch, L"%ls\\*", dir));
}

static void fs_process_directory(FS_RUNTIME rt, SYSTEM_DETAILS * system_details, LPCWSTR dir_path) {
    WIN32_FIND_DATAW fd;
    HANDLE h_find;
    WCHAR pattern[FS_SEARCH_PATH_CCH];
    WCHAR full_path[FS_SEARCH_PATH_CCH];

    if (fs_should_stop(rt->options.stop_event)) {
        return;
    }

    if (!fs_make_pattern(dir_path, pattern, ARRAY_LEN_COUNT(pattern))) {
        return;
    }

    h_find = FindFirstFileExW(
        pattern,
        FindExInfoStandard,
        &fd,
        FindExSearchNameMatch,
        NULL,
        FIND_FIRST_EX_LARGE_FETCH
    );

    if (h_find == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            logmsg(LOGGING_WARN, L"It was not possible to traverse the following directory structure: %ls. Cause: ACCESS_DENIED", dir_path);
            InterlockedIncrement(&PTR(rt).stats->access_denied);
        }
        return;
    }

    do {
        if (fs_should_stop(PTR(rt).options.stop_event)) {
            break;
        }

        if (fs_is_dot_dir(fd.cFileName)) {
            continue;
        }

        if (!fs_join_path(dir_path, fd.cFileName, full_path, ARRAY_LEN_COUNT(full_path))) {
            continue;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            LPWSTR queued_path;
            errorcode_t result;

            InterlockedIncrement(&PTR(rt).stats->dirs_checked);

            if (fs_should_skip_dir(full_path, &fd)) {
                InterlockedIncrement(&PTR(rt).stats->dirs_skipped);
                continue;
            }

            queued_path = heap_wcsdup(full_path);
            if (!queued_path) {
                logmsg(LOGGING_ERROR, L"Failed to allocate the queue path (dup2) for the FS path: %ls. Skipping", full_path);
                continue;
            }

            result = inmem_queue_put(PTR(rt).queue, queued_path, PTR(rt).options.stop_event);
            if ( !_IS_SUCCESS(result) ) {
                if ( result == ST_CODE_QUEUE_IS_EMPTY_OR_CLOSED ) {
                    win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_WARN, L"Could not put the path into the queue (%ls) because it's already closed. Path: %ls", PTR(rt).queue->name, queued_path);
                }
                else {
                    logmsg(LOGGING_ERROR, L"It was not possible to put the directory [%ls] into the search queue", queued_path);
                }
                HeapFree(GetProcessHeap(), 0, queued_path);
            }
        }
        else {
            InterlockedIncrement(&PTR(rt).stats->files_checked);

            if (_wcsicmp(fd.cFileName, PTR(rt).options.target_name) == 0) {
                InterlockedIncrement(&PTR(rt).stats->matches_found);

                if (PTR(rt).options.on_match) {
                    PTR(rt).options.on_match(full_path, &fd, /*This is the SYSTEM DETAILS*/PTR(rt).options.user_ctx);
                    //PTR(rt).options.on_match(full_path, &fd, PTR(rt).queue);
                }
                else {
                    logmsg(LOGGING_NORMAL, L"[FSSCAN] Match found: %ls", full_path);
                    logmsg(LOGGING_NORMAL, L"[FSSCAN]--> Found an %ls within: %ls", PTR(rt).options.target_name, full_path);
                }

                if (PTR(rt).options.stop_on_first_match) {
                    InterlockedExchange(&rt->found, 1);
                    inmem_queue_close(rt->queue);
                    break;
                }
            }
        }

    }
    while (FindNextFileW(h_find, &fd));

    FindClose(h_find);
}

static DWORD WINAPI fs_worker_thread(LPVOID param) {
    FS_WORKER_CTX ctx = (FS_WORKER_CTX)param;
    FS_RUNTIME rt = PTR(ctx).runtime;
    SYSTEM_DETAILS *sysdetails = PTR(ctx).sysdetails;
    BOOL end_worker = FALSE;

    while (!end_worker) { /* RUNS FOREVER SORT OF SPEAK... */
        QUEUE_ITEM item = NULL;
        LPWSTR dir_path;
        errorcode_t rc;

        if (fs_should_stop(PTR(rt).options.stop_event)) {
            end_worker = !end_worker;
            continue;
        }

        if (PTR(rt).options.stop_on_first_match &&
            InterlockedCompareExchange(&PTR(rt).found, 0, 0) != 0) {
            end_worker = !end_worker;
            continue;
        }

        rc = inmem_queue_get(PTR(rt).queue, &item, PTR(rt).options.stop_event);
        if ( rc == ST_CODE_QUEUE_IS_EMPTY_OR_CLOSED || item == NULL) {
            end_worker = !end_worker; // normal completion, the queues are empty
            continue;
        }
        if (!_IS_SUCCESS(rc) || item == NULL) {
            logmsg(LOGGING_ERROR, L"Could not retrieve any items from the FS queue: %ls", PTR(rt).queue->name);
            end_worker = !end_worker;
            continue;
        }

        dir_path = (LPWSTR)item;

        fs_process_directory(rt, sysdetails, dir_path);

        HeapFree(GetProcessHeap(), 0, dir_path);
        inmem_queue_task_done(rt->queue);
    }

    return ST_CODE_SUCCESS;
}

static errorcode_t fs_seed_roots(FS_RUNTIME rt) {
    WCHAR drives[512];
    DWORD len;
    LPWSTR p;

    ZeroMemory(drives, sizeof(drives));

    len = GetLogicalDriveStringsW(ARRAY_LEN_COUNT(drives) - 1, drives);
    if (len == 0 || len >= ARRAY_LEN_COUNT(drives)) {
        win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_ERROR, L"Failed to retrieve the system logical drives. Execution failed, it will not continue. Please verify the user access restrictions, or policies");
        return ST_CODE_FAILED_OPERATION;
    }

    for (p = drives; *p; p += wcslen(p) + 1) {
        UINT type;
        LPWSTR root_copy;
        errorcode_t result;

        if (fs_should_stop(PTR(rt).options.stop_event)) {
            break;
        }

        type = GetDriveTypeW(p);

        if (type == DRIVE_REMOTE) {
            win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_WARN, L"The given drive is a remote drive: %ls. Crawler will skip it.", p);
            InterlockedIncrement(&PTR(rt).stats->dirs_skipped);
            continue;
        }

        if (PTR(rt).options.fixed_drives_only && type != DRIVE_FIXED) {
            continue;
        }

        if (fs_is_google_drive_root(p)) {
            logmsg(LOGGING_WARN, L"[FS CRAWLER] Skipping Google Drive root: %ls", p);
            InterlockedIncrement(&PTR(rt).stats->dirs_skipped);
            continue;
        }

        root_copy = heap_wcsdup(p);
        if (!root_copy) {
            logmsg(LOGGING_ERROR, L"Failed to allocate memeory (dup2) for the drive name: %ls", p);
            return ST_CODE_MEMORY_ALLOCATION_FAILED;
        }

        result = inmem_queue_put(PTR(rt).queue, root_copy, PTR(rt).options.stop_event);
        if ( !_IS_SUCCESS(result) ) {
            if ( result == ST_CODE_QUEUE_IS_EMPTY_OR_CLOSED ) {
                win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_WARN, L"The is closed, so no process could be made for the path: %ls", root_copy);
            }
            HeapFree(GetProcessHeap(), 0, root_copy);

            return result;
        }
    }

    return ST_CODE_SUCCESS;
}

errorcode_t fs_search_execute(const fs_search_options_t *options, fs_search_stats_t *stats) {
    fs_runtime_t rt;
    HANDLE workers[FS_SEARCH_MAX_WORKERS];
    fs_worker_ctx_t worker_ctx[FS_SEARCH_MAX_WORKERS];
    DWORD worker_count, i;
    errorcode_t rc;

    AGENT_DB agent_db;

    if (!options || !options->target_name || !stats) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(&rt, sizeof(rt));
    ZeroMemory(stats, sizeof(*stats));
    ZeroMemory(workers, sizeof(workers));
    ZeroMemory(worker_ctx, sizeof(worker_ctx));

    rt.options = *options;
    rt.stats = stats;

    worker_count = PTR(options).worker_count;
    if (worker_count == 0) worker_count = get_default_worker_count();
    if (worker_count > FS_SEARCH_MAX_WORKERS) worker_count = FS_SEARCH_MAX_WORKERS;

    logmsg(LOGGING_NORMAL, L"[FS CRAWLER] Number of worker threads: %d", worker_count);

    logmsg(LOGGING_NORMAL, L"[FS CRAWLER] Creating the processing queue: %ls", FS_QUEUE_NAME);
    rc = inmem_queue_create(&rt.queue, DEF_QUEUE_CAPACITY, FS_QUEUE_NAME);
    if (!_IS_SUCCESS(rc)) {
        return rc;
    }

    logmsg(LOGGING_NORMAL, L"[FS CRAWLER] Initializing the local agent database...");
    rc = agent_db_open(&agent_db);
    if ( !_IS_SUCCESS(rc) ) {
        return rc;
    }

    rc = agent_db_init_schema(agent_db);
    if ( !_IS_SUCCESS(rc) ) {
        agent_db_close(agent_db);
        return rc;
    }

    for (i = 0; i < worker_count; ++i) {
        worker_ctx[i].runtime = &rt;
        worker_ctx[i].sysdetails = PTR(options).user_ctx;


        workers[i] = CreateThread(
            NULL,
            0,
            fs_worker_thread,
            &worker_ctx[i],
            0,
            NULL
        );

        if (workers[i] == NULL) {
            win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_ERROR, L"Failed to create a worker thread (maybe the program stack is NULL). Processing queue name: %ls", worker_ctx[i].runtime->queue->name);
            inmem_queue_close(rt.queue);
            break;
        }
    }

    rc = fs_seed_roots(&rt);
    if (!_IS_SUCCESS(rc)) {
        inmem_queue_destroy(rt.queue, fs_free_queue_item);
        return rc;
    }

    for (i = 0; i < worker_count; ++i) {
        if (workers[i]) {
            WaitForSingleObject(workers[i], INFINITE);
            CloseHandle(workers[i]);
        }
    }

    logmsg(LOGGING_NORMAL, L"[FS CRAWLER] Closing the queue: %ls", FS_QUEUE_NAME);
    inmem_queue_destroy(rt.queue, fs_free_queue_item);

    logmsg(LOGGING_NORMAL, L"[FS CRAWLER] Closing the local agent database");
    agent_db_close(agent_db);

    return ST_CODE_SUCCESS;
}

static void fs_free_queue_item(QUEUE_ITEM item) {
    if (item) {
        HeapFree(GetProcessHeap(), 0, item);
    }
}