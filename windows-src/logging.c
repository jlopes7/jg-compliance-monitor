//
// Created by Joao Gonzalez on 4/22/2026.
//

#include "windows/ini_config.h"
#include "windows/winreg_config.h"
#include "windows/logging.h"

logging_t *_logging_config;
BOOL _is_initialized = FALSE;

static errorcode_t rotate_log_if_needed(LPCWSTR log_file_path);

static errorcode_t logging_write_raw(LPCWSTR line) {
    if (!_logging_config || !PTR(_logging_config).log_file_fp || !line) {
        return ST_CODE_INVALID_PARAM;
    }

    fwprintf(PTR(_logging_config).log_file_fp, L"%ls%ls", line, LINE_BREAK);

#if defined(_DEBUG_CONSOLE)
    fwprintf(stdout, L"%ls%ls", line, LINE_BREAK);
#endif

    return ST_CODE_SUCCESS;
}

static void logging_free_queue_item(QUEUE_ITEM item) {
    if (item) {
        HeapFree(GetProcessHeap(), 0, item);
    }
}

static DWORD logging_drain_queue(void) {
    DWORD drained = 0;

    while (_logging_config && PTR(_logging_config).queue) {
        QUEUE_ITEM item = NULL;
        errorcode_t rc;

        /*
         * Pass NULL as stop_event here.
         * The logging thread decides when to stop; the queue should still be
         * drainable even during shutdown.
         */
        rc = inmem_queue_get(PTR(_logging_config).queue, &item, NULL);

        if (!_IS_SUCCESS(rc) || item == NULL) {
            break;
        }

        logging_write_raw(item);
        HeapFree(GetProcessHeap(), 0, item);
        drained++;
    }

    if (drained > 0) {
        fflush(PTR(_logging_config).log_file_fp);

#if defined(_DEBUG_CONSOLE)
        fflush(stdout);
#endif
    }

    return drained;
}

static DWORD WINAPI logging_writer_thread(LPVOID param) {
    logging_t *cfg = (logging_t *)param;

    if (!cfg || !cfg->stop_event) {
        return ST_CODE_INVALID_PARAM;
    }

    while (WaitForSingleObject(PTR(cfg).stop_event, LOG_FLUSH_INTERVAL_MS) != WAIT_OBJECT_0) {
        logging_drain_queue();
    }

    /*
     * Final flush after shutdown is requested.
     */
    logging_drain_queue();

    return ST_CODE_SUCCESS;
}

errorcode_t logging_init(void) {
    wchar_t log_dir[MAX_LOG_FILE];
    wchar_t log_file[MAX_LOG_FILE];
    errorcode_t rc;

    _logging_config = malloc(sizeof(logging_t));
    if (!_logging_config) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }
    _MEMZERO(_logging_config, sizeof(logging_t));
    _MEMZERO(log_dir, sizeof(log_dir));
    _MEMZERO(log_file, sizeof(log_file));

    rc = read_registry_string(REG_LOG_LOCATION, log_file, MAX_LOG_FILE);
    if (!_IS_SUCCESS(rc)) {
        free(_logging_config);
        _logging_config = NULL;
        return rc;
    }

    rc = fs_get_directory_from_path(log_file, log_dir, _LPWLEN(log_dir));
    if (!_IS_SUCCESS(rc)) {
        free(_logging_config);
        _logging_config = NULL;
        return rc;
    }

    if (GetFileAttributesW(log_dir) == INVALID_FILE_ATTRIBUTES) {
        if (CREATE_DIR(log_dir) != 0) {
            free(_logging_config);
            _logging_config = NULL;
            return ST_CODE_IO_CREATEDIR_FAILED;
        }
    }

    size_t dirlen = wcsnlen(log_dir, _LPWLEN(log_dir));
    size_t filelen = wcsnlen(log_file, _LPWLEN(log_file));

    PTR(_logging_config).log_dir = malloc((dirlen + 1) * sizeof(wchar_t));
    PTR(_logging_config).log_file = malloc((filelen + 1) * sizeof(wchar_t));
    if (!PTR(_logging_config).log_dir || !PTR(_logging_config).log_file) {
        free(PTR(_logging_config).log_dir);
        free(PTR(_logging_config).log_file);
        free(_logging_config);
        _logging_config = NULL;
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    _MEMZERO(PTR(_logging_config).log_dir, (dirlen + 1) * sizeof(wchar_t));
    _MEMZERO(PTR(_logging_config).log_file, (filelen + 1) * sizeof(wchar_t));

    wcsncpy_s(PTR(_logging_config).log_dir, dirlen + 1, log_dir, _TRUNCATE);
    wcsncpy_s(PTR(_logging_config).log_file, filelen + 1, log_file, _TRUNCATE);

    // ROTATES THE FILE IF NEEDED (< 1MB)
    rc = rotate_log_if_needed(PTR(_logging_config).log_file);
    if (!_IS_SUCCESS(rc)) {
        free(PTR(_logging_config).log_dir);
        free(PTR(_logging_config).log_file);
        free(_logging_config);
        _logging_config = NULL;
        return rc;
    }

    errno_t err = _wfopen_s(&PTR(_logging_config).log_file_fp, PTR(_logging_config).log_file, L"a+");
    if (err != 0 || !PTR(_logging_config).log_file_fp) {
        free(PTR(_logging_config).log_dir);
        free(PTR(_logging_config).log_file);
        free(_logging_config);
        _logging_config = NULL;
        return ST_CODE_IO_OPEN_FAILED;
    }

    /* CONTROL THREAD */
    rc = inmem_queue_create(&PTR(_logging_config).queue, LOG_QUEUE_CAPACITY, LOG_QUEUE_NAME);
    if ( !_IS_SUCCESS(rc) ) {
        fclose(PTR(_logging_config).log_file_fp);
        free(PTR(_logging_config).log_dir);
        free(PTR(_logging_config).log_file);
        free(_logging_config);
        _logging_config = NULL;
        return rc;
    }

    PTR(_logging_config).stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!PTR(_logging_config).stop_event) {
        inmem_queue_destroy(PTR(_logging_config).queue, logging_free_queue_item);
        fclose(PTR(_logging_config).log_file_fp);
        free(PTR(_logging_config).log_dir);
        free(PTR(_logging_config).log_file);
        free(_logging_config);
        _logging_config = NULL;
        return ST_CODE_FAILED_CREATEEVENT;
    }

    PTR(_logging_config).writer_thread = CreateThread(
        NULL,
        0,
        logging_writer_thread,
        _logging_config,
        0,
        &PTR(_logging_config).writer_thread_id
    );

    if (!PTR(_logging_config).writer_thread) {
        CloseHandle(PTR(_logging_config).stop_event);
        inmem_queue_destroy(PTR(_logging_config).queue, logging_free_queue_item);
        fclose(PTR(_logging_config).log_file_fp);
        free(PTR(_logging_config).log_dir);
        free(PTR(_logging_config).log_file);
        free(_logging_config);
        _logging_config = NULL;
        return ST_CODE_FAILED_CREATETHREAD;
    }

    fwprintf(PTR(_logging_config).log_file_fp, L"--------------------------------------------------%ls", LINE_BREAK);
    fwprintf(PTR(_logging_config).log_file_fp, L"-          JG AGENT EXECUTION INITIALIZED        -%ls", LINE_BREAK);
    fwprintf(PTR(_logging_config).log_file_fp, L"--------------------------------------------------%ls", LINE_BREAK);
#if defined(_DEBUG_CONSOLE)
    fwprintf(stdout, L"--------------------------------------------------%ls", LINE_BREAK);
    fwprintf(stdout, L"-          JG AGENT EXECUTION INITIALIZED        -%ls", LINE_BREAK);
    fwprintf(stdout, L"--------------------------------------------------%ls", LINE_BREAK);
#endif

    _is_initialized = TRUE;
    return ST_CODE_SUCCESS;
}

errorcode_t logmsg(level_t lvl, LPCWSTR format, ...) {
    wchar_t timestamp[32];
    wchar_t message[LOG_LINE_CCH];
    wchar_t line[LOG_LINE_CCH];
    va_list args;
    LPWSTR queued_line;
    size_t line_len;
    errorcode_t rc;

    if (!_is_initialized || !_logging_config || !PTR(_logging_config).queue || !format) {
        return ST_CODE_SUCCESS;
    }

    ZeroMemory(timestamp, sizeof(timestamp));
    ZeroMemory(message, sizeof(message));
    ZeroMemory(line, sizeof(line));

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_s(&tm_info, &now);
    wcsftime(timestamp, _LPWLEN(timestamp), L"%Y-%m-%d %H:%M:%S", &tm_info);

    va_start(args, format);
    vswprintf_s(message, _LPWLEN(message), format, args);
    va_end(args);

    switch (lvl) {
        case LOGGING_ERROR:
            swprintf_s(line, _LPWLEN(line), L"[%ls] (ERROR) %ls", timestamp, message);
            break;

        case LOGGING_WARN:
            swprintf_s(line, _LPWLEN(line), L"[%ls] (WARN) %ls", timestamp, message);
            break;

        case LOGGING_NORMAL:
        default:
            swprintf_s(line, _LPWLEN(line), L"[%ls] (INFO) %ls", timestamp, message);
            break;
    }

    line_len = wcslen(line);
    queued_line = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(wchar_t) * (line_len + 1));
    if (!queued_line) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    wcscpy_s(queued_line, line_len + 1, line);

    rc = inmem_queue_put(PTR(_logging_config).queue, queued_line, NULL);
    if (!_IS_SUCCESS(rc)) {
        HeapFree(GetProcessHeap(), 0, queued_line);

        /*
         * Do not call logmsg() here.
         * That would recurse back into the logging queue.
         */
        return rc;
    }

    return ST_CODE_SUCCESS;
}

/**
 * @deprecated To be removed later, only here for reference
 * TODO: Remove later!
 */
static errorcode_t logmsg_old(level_t lvl, LPCWSTR format, ...) {
    wchar_t timestamp[32];
    va_list args;
#if defined(_DEBUG_CONSOLE)
    va_list args_copy;
#endif

    // For now, if the logging system was not initialized, simply return success!
    if ( !_is_initialized || !PTR(_logging_config).log_file_fp ) {
        //return ST_CODE_CONFIGURATION_NOTINIT; -- TODO: Review this later
        return ST_CODE_SUCCESS;
    }

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_s(&tm_info, &now);
    wcsftime(timestamp, _LPWLEN(timestamp), L"%Y-%m-%d %H:%M:%S", &tm_info);

    // Write log entry
    va_start(args, format);
    fwprintf(PTR(_logging_config).log_file_fp, L"[%ls] ", timestamp);
#if defined(_DEBUG_CONSOLE)
    fwprintf(stdout, L"[%ls] ", timestamp);
#endif
    switch (lvl) {
        case LOGGING_NORMAL: {
            fwprintf(PTR(_logging_config).log_file_fp, L"(INFO) ");
#if defined(_DEBUG_CONSOLE)
            fwprintf(stdout, L"(INFO) ");
#endif
            break;
        }
        case LOGGING_ERROR: {
            fwprintf(PTR(_logging_config).log_file_fp, L"(ERROR) ");
#if defined(_DEBUG_CONSOLE)
            fwprintf(stdout, L"(ERROR) ");
#endif
            break;
        }
    }
#if defined(_DEBUG_CONSOLE)
    va_copy(args_copy, args);
#endif

    vfwprintf(PTR(_logging_config).log_file_fp, format, args);
#if defined(_DEBUG_CONSOLE)
    vfwprintf(stdout, format, args_copy);
    va_end(args_copy);
#endif

    fwprintf(PTR(_logging_config).log_file_fp, LINE_BREAK);
    fflush(PTR(_logging_config).log_file_fp);
#if defined(_DEBUG_CONSOLE)
    fwprintf(stdout, LINE_BREAK);
    fflush(stdout);
#endif

    va_end(args);

    return ST_CODE_SUCCESS;
}

errorcode_t logging_end(void) {
    logging_t *cfg = _logging_config;

    if (!cfg) {
        _is_initialized = FALSE;
        return ST_CODE_SUCCESS;
    }

    /*
     * Prevent new log messages from being queued.
     */
    _is_initialized = FALSE;

    /*
     * Wake the writer thread and tell it to finish.
     */
    if (PTR(cfg).queue) {
        inmem_queue_close(PTR(cfg).queue);
    }

    if (PTR(cfg).stop_event) {
        SetEvent(PTR(cfg).stop_event);
    }

    /*
     * Wait until the writer thread drains remaining entries.
     */
    if (PTR(cfg).writer_thread) {
        WaitForSingleObject(PTR(cfg).writer_thread, INFINITE);
        CloseHandle(PTR(cfg).writer_thread);
        PTR(cfg).writer_thread = NULL;
    }

    /*
     * Defensive final drain. Usually the writer thread already did this.
     */
    logging_drain_queue();

    if (PTR(cfg).queue) {
        inmem_queue_destroy(PTR(cfg).queue, logging_free_queue_item);
        PTR(cfg).queue = NULL;
    }

    if (PTR(cfg).stop_event) {
        CloseHandle(PTR(cfg).stop_event);
        PTR(cfg).stop_event = NULL;
    }

    if (PTR(cfg).log_file_fp) {
        fflush(PTR(cfg).log_file_fp);
        fclose(PTR(cfg).log_file_fp);
        PTR(cfg).log_file_fp = NULL;
    }

    free(PTR(cfg).log_dir);
    free(PTR(cfg).log_file);
    free(cfg);

    _logging_config = NULL;

    return ST_CODE_SUCCESS;
}

static errorcode_t rotate_log_if_needed(LPCWSTR log_file_path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULARGE_INTEGER file_size;
    SYSTEMTIME st;
    wchar_t rotated_path[MAX_LOG_FILE];
    int written;

    if (!log_file_path) {
        return ST_CODE_INVALID_PARAM;
    }

    if (!GetFileAttributesExW(log_file_path, GetFileExInfoStandard, &fad)) {
        DWORD err = GetLastError();

        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            return ST_CODE_SUCCESS;
        }

        return ST_CODE_IO_STAT_FAILED;
    }

    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        return ST_CODE_INVALID_PATH;
    }

    file_size.HighPart = fad.nFileSizeHigh;
    file_size.LowPart  = fad.nFileSizeLow;

    if (file_size.QuadPart <= LOG_ROTATE_SIZE_BYTES) {
        return ST_CODE_SUCCESS;
    }

    GetLocalTime(&st);

    written = swprintf_s(
        rotated_path,
        _LPWLEN(rotated_path),
        L"%ls.%04u%02u%02u_%02u%02u%02u",
        log_file_path,
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond
    );

    if (written < 0) {
        return ST_CODE_BUFFER_TOO_SMALL;
    }

    if (!MoveFileW(log_file_path, rotated_path)) {
        return ST_CODE_IO_RENAME_FAILED;
    }

    return ST_CODE_SUCCESS;
}

#if defined(_DEBUG_CONSOLE)
void debug_jvmlist_tabularform(SYSTEM_DETAILS system_details) {
    DWORD i;

    if (system_details == NULL) {
        logmsg(LOGGING_WARN, L"[DEBUG][JVM] system_details is NULL");
        return;
    }

    logmsg(LOGGING_NORMAL,
        L"%-4ls | %-50ls | %-25ls | %-15ls | %-30ls | %-20ls | %-20ls | %-15ls | %-5ls | %-5ls | %-30ls | %-5ls | %-5ls | %-5ls | %-7ls",
        L"IDX",
        L"installation_path",
        L"publisher",
        L"license_type",
        L"legal_copyright",
        L"fullversion_jdk",
        L"fullversion_win",
        L"runtime_version",
        L"major",
        L"minor",
        L"product_name",
        L"is_jdk",
        L"is_jre",
        L"is_ojdk",
        L"is_oracle"
    );

    logmsg(LOGGING_NORMAL,
        L"----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

    for (i = 0; i < PTR(system_details).jvm_count; i++) {
        JVM_DETAILS jvm = PTR(system_details).jvm[i];

        if (jvm == NULL) {
            logmsg(LOGGING_WARN, L"[DEBUG][JVM] JVM entry %lu is NULL", i);
            continue;
        }

        logmsg(LOGGING_NORMAL,
            L"%-4lu | %-50.50ls | %-25.25ls | %-15.15ls | %-30.30ls | %-20.20ls | %-20.20ls | %-15.15ls | %-5lu | %-5lu | %-30.30ls | %-5ls | %-5ls | %-5ls | %-7ls",
            (i + 1),
            DBG_NULLSTR(PTR(jvm).installation_path),
            DBG_NULLSTR(PTR(jvm).publisher),
            DBG_NULLSTR(PTR(jvm).license_type),
            DBG_NULLSTR(PTR(jvm).legal_copyright),
            DBG_NULLSTR(PTR(jvm).fullversion_jdk),
            DBG_NULLSTR(PTR(jvm).fullversion_win),
            DBG_NULLSTR(PTR(jvm).runtime_version),
            PTR(jvm).major_version,
            PTR(jvm).minor_version,
            DBG_NULLSTR(PTR(jvm).product_name),
            PTR(jvm).is_jdk ? L"TRUE" : L"FALSE",
            PTR(jvm).is_jre ? L"TRUE" : L"FALSE",
            PTR(jvm).is_ojdk ? L"TRUE" : L"FALSE",
            PTR(jvm).is_oracle ? L"TRUE" : L"FALSE"
        );
    }
}
#endif
