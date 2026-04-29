//
// Created by Joao Gonzalez on 4/23/2026.
//

#include "windows/scan/scan_agent.h"
#include "windows/scan/search_fs.h"

#include "windows/logging.h"
#include "windows/evtlog.h"

static uint32_t _timeout_counter = 0;

static BOOL fs_scan_match_callback (
    LPCWSTR full_path,
    const WIN32_FIND_DATAW *find_data,
    LPVOID user_ctx
) {
    SYSTEM_DETAILS *system_details = (SYSTEM_DETAILS*)user_ctx;

    logmsg(LOGGING_NORMAL, L"[FSSCAN] Found target file: %ls", full_path);
    /* TODO: Act on found evidence !  */

    return TRUE;
}

static BOOL fs_scan_run_once(HANDLE stop_event, SYSTEM_DETAILS *sysdetails) {
    fs_search_options_t options;
    fs_search_stats_t stats;
    errorcode_t result;

    ULONGLONG started_ms;
    ULONGLONG finished_ms;
    double elapsed_seconds;

    if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) {
        return FALSE;
    }

    // Start the counter...
    started_ms = GetTickCount64();

    logmsg(LOGGING_NORMAL, L"Running the FS scan...");
    ZeroMemory(&options, sizeof(options));
    ZeroMemory(&stats, sizeof(stats));

    options.stop_event = stop_event;
    options.target_name = L"java.exe"; /*HARDCODED FOR NOW! We will only support Java discovery*/
    options.worker_count = get_default_worker_count();
    options.fixed_drives_only = TRUE;
    options.stop_on_first_match = FALSE;
    options.on_match = fs_scan_match_callback;
    options.user_ctx = sysdetails;

    logmsg(LOGGING_NORMAL, L"[FSSCAN] Running filesystem scan for: %ls", options.target_name);

    result = fs_search_execute(&options, &stats);

    // Ends execution timer!
    finished_ms = GetTickCount64();
    elapsed_seconds = (double)(finished_ms - started_ms) / 1000.0;

    if (!_IS_SUCCESS(result)) {
        win_evt_log_id_fmt(
            JG_EVENT_ID_GENERIC,
            LOGLEVEL_ERROR,
            L"Filesystem scan failed. Error code: %d",
            result
        );

        return FALSE;
    }

    // Stats:
    logmsg(
        LOGGING_NORMAL,
        L"[FSSCAN] Scan completed -> elapsed=%.3f seconds ; files=%ld ; dirs=%ld ; skipped=%ld ; matches=%ld ; access_denied=%ld",
        elapsed_seconds,
        stats.files_checked,
        stats.dirs_checked,
        stats.dirs_skipped,
        stats.matches_found,
        stats.access_denied
    );

    return TRUE;
}

DWORD WINAPI fs_scan_agent_thread(LPVOID param) {
    BOOL endscan = FALSE;
    agent_thread_ctx_t *ctx = (agent_thread_ctx_t *) param;
    SYSTEM_DETAILS systemdetails = NULL;

    errorcode_t result;

    if (ctx == NULL || PTR(ctx).stop_event == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    logmsg(
        LOGGING_NORMAL,
        L"[FSSCAN] Agent started. interval_ms=%lu heartbeat_ms=%lu",
        PTR(ctx).interval_ms,
        PTR(ctx).heartbeat_ms
    );

    // Parse the system details model
    result = parse_model_system(&systemdetails);
    if ( !_IS_SUCCESS(result) ) {
        win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_ERROR, L"Failed to parse the system information. Error code: %d", result);
        return ST_CODE_FAILED_PARSE_MODEL;
    }

    while (!endscan && WaitForSingleObject(PTR(ctx).stop_event, 0) != WAIT_OBJECT_0) {
        if ( _timeout_counter >= PTR(ctx).interval_ms || _timeout_counter == 0 ) {
            endscan = !fs_scan_run_once(ctx->stop_event, &systemdetails);

            clean_jvm_data(&systemdetails);
            logmsg(LOGGING_NORMAL, L"[FSSCAN] The JVM data was cleaned for the next execution!");

            _timeout_counter = 1;
        }

        /**
         * Pings every something seconds, but the execution will only be executed after the
         * timeout is reached - by default 2 hours
         */
        if (!endscan) {
            DWORD rc = WaitForSingleObject(PTR(ctx).stop_event, PTR(ctx).heartbeat_ms);
            endscan = ( rc == WAIT_OBJECT_0 );
        }

        _timeout_counter += PTR(ctx).heartbeat_ms;
    }

    win_evt_log(L"[FSSCAN] Agent stopped.", LOGLEVEL_WARN);

    return ST_CODE_SUCCESS;
}
