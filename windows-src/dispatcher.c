//
// Created by Joao Gonzalez on 4/22/2026.
//

#include "windows/dispatcher.h"
#include "windows/config.h"
#include "windows/winreg_config.h"
#include "windows/evtlog.h"
#include "windows/logging.h"

#include "windows/scan/scan_agent.h"

// Dispatch the threads
static dispatcher_state_t g_dispatcher_state;
static uint8_t number_of_active_processes = 0;

errorcode_t dispatcher_start(HANDLE stop_event) {
    errorcode_t result;
    CONFIG config;
    get_config(&config);

    if ( PTR(config).global->inventory_scan_ctrl ) { // STARTS THE INVENTORY SCAN THREAD !
        DWORD timeout_internval;
        result = read_registry_dword(REG_FSSCANTO, &timeout_internval);
        if ( !_IS_SUCCESS( result ) ) {
            win_evt_log_id_fmt(JG_EVENT_ID_DISPATCHER, LOGLEVEL_WARN,
                L"Failed to read the time out flag for the FS scan. Missing registry entry: %ls", REG_FSSCANTO);
            logmsg(LOGGING_NORMAL, L"Failed to load the polling time out from the registry, assuming 2 hours by default");

            timeout_internval = DEFAULT_POLLING_INTERVAL;
        }

        logmsg(LOGGING_NORMAL, L"[+] Creating the FS scan process. Process name: %ls", PROCESSNAME_FSSCAN);
        g_dispatcher_state.fs_scan = (agent_thread_ctx_t) {
            .stop_event     = stop_event,
            .interval_ms    = timeout_internval,
            .heartbeat_ms   = DEFAULT_SYNC_HB_MS,
            .name           = PROCESSNAME_FSSCAN,
            .thread_proc    = fs_scan_agent_thread
        };
        g_dispatcher_state.fs_scan_active = TRUE;
        number_of_active_processes++;
    }

    if ( PTR(config).global->inventory_scan_ctrl ) {
        // TODO: STARTS THE PROCESS SCAN THREAD !
        /*g_dispatcher_state.proc_scan = (agent_thread_ctx_t) {
            .stop_event     = stop_event,
            .interval_ms    = DEFAULT_POLLING_INTERVAL,
            .heartbeat_ms   = DEFAULT_SYNC_HB_MS,
            .name           = PROCESSNAME_PROCSCAN,
            .thread_proc    = proc_scan_agent_thread
        };
        g_dispatcher_state.proc_scan_active = TRUE;
        number_of_active_processes++;*/
    }

    if ( PTR(config).global->cve_scan_ctrl ) {
        // TODO: STARTS THE CVE CPE PROCESS
        /*g_dispatcher_state.cve_scan = (agent_thread_ctx_t) {
            .stop_event     = stop_event,
            .interval_ms    = DEFAULT_POLLING_INTERVAL,
            .heartbeat_ms   = DEFAULT_SYNC_HB_MS,
            .name           = PROCESSNAME_CVESCAN,
            .thread_proc    = cve_pde_agent_thread
        };
        g_dispatcher_state.cve_scan_active = TRUE;
        number_of_active_processes++;*/
    }

    if ( number_of_active_processes == 0 ) {
        win_evt_log_id_fmt(JG_EVENT_ID_DISPATCHER, LOGLEVEL_WARN,
                       L"No active agent processes found. The service will not start.");

        return ST_CODE_NOACTIVE_AGENTS;
    }

    logmsg(LOGGING_NORMAL, L"Found %d processes. Starting the process threads!", number_of_active_processes);

    /*
     * ==================================
     *  FS SCAN AGENT PROCESS DEFINITION
     * ==================================
     */
    if ( g_dispatcher_state.fs_scan_active ) {
        win_evt_log_id_fmt(JG_EVENT_ID_DISPATCHER, LOGLEVEL_WARN, L"Starting the FS scanning agent process...");
        g_dispatcher_state.fs_scan.thread_handle = CreateThread(
            NULL,
            0,  /* It could be a good idea in the future to identify a fixed size of the Stack */
            g_dispatcher_state.fs_scan.thread_proc,
            &g_dispatcher_state.fs_scan,
            0,
            &g_dispatcher_state.fs_scan.thread_id
        );

        if (g_dispatcher_state.fs_scan.thread_handle == NULL) {
            win_evt_log_id(L"It was not possible to to start the FS scan process", JG_EVENT_ID_DISPATCHER, LOGLEVEL_ERROR);
            SetEvent(stop_event);
            dispatcher_stop();
            return ST_CODE_FAILED_AGENT_CRTPRCS;
        }

        win_evt_log_id(L"FS Scan agent process triggered successfully!", JG_EVENT_ID_DISPATCHER, LOGLEVEL_INFO);
    }
    // TODO: Implement the other processes (for now just fails)
    else {
        win_evt_log_id(L"The only currently implemented process is for the FS Scan", JG_EVENT_ID_DISPATCHER, LOGLEVEL_WARN);
        SetEvent(stop_event);
        dispatcher_stop();
        return ST_CODE_UNSUPPORTED_OPERATION;
    }

    return ST_CODE_SUCCESS;
}

errorcode_t dispatcher_stop(void) {
    HANDLE handles[3];
    uint8_t counter = 0;

    logmsg(LOGGING_NORMAL, L" --> Closing all the processes thread handles");

    if ( g_dispatcher_state.fs_scan_active ) {
        if (g_dispatcher_state.fs_scan.thread_handle != NULL) {
            handles[counter++] = g_dispatcher_state.fs_scan.thread_handle;
        }
    }
    if ( g_dispatcher_state.proc_scan_active ) {
        if (g_dispatcher_state.proc_scan.thread_handle != NULL) {
            handles[counter++] = g_dispatcher_state.proc_scan.thread_handle;
        }
    }
    if ( g_dispatcher_state.cve_scan_active ) {
        if (g_dispatcher_state.cve_scan.thread_handle != NULL) {
            handles[counter++] = g_dispatcher_state.cve_scan.thread_handle;
        }
    }

    if (counter > 0) {
        WaitForMultipleObjects(counter, handles, TRUE, INFINITE);
    }

    if (g_dispatcher_state.fs_scan.thread_handle != NULL) {
        logmsg(LOGGING_NORMAL, L" --> Stopping the FS scan process");
        CloseHandle(g_dispatcher_state.fs_scan.thread_handle);
        g_dispatcher_state.fs_scan.thread_handle = NULL;
    }
    if (g_dispatcher_state.proc_scan.thread_handle != NULL) {
        logmsg(LOGGING_NORMAL, L" --> Stopping the process thread");
        CloseHandle(g_dispatcher_state.proc_scan.thread_handle);
        g_dispatcher_state.proc_scan.thread_handle = NULL;
    }
    if (g_dispatcher_state.cve_scan.thread_handle != NULL) {
        logmsg(LOGGING_NORMAL, L" --> Stopping the process thread");
        CloseHandle(g_dispatcher_state.cve_scan.thread_handle);
        g_dispatcher_state.cve_scan.thread_handle = NULL;
    }

    win_evt_log_id(L"All agent processes were freed successfully!", JG_EVENT_ID_DISPATCHER, LOGLEVEL_WARN);

    return ST_CODE_SUCCESS;
}
