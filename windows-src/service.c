//
// Created by Joao Gonzalez on 4/21/2026.
//

#include "windows/service.h"
#include "windows/evtlog.h"
#include "windows/dispatcher.h"
#include "windows/logging.h"
#include "windows/config.h"

static BOOL g_debug_mode = FALSE;
static BOOL g_control_mode = FALSE;

static SERVICE_STATUS_HANDLE g_service_status_handle = NULL;
static SERVICE_STATUS g_service_status;

static HANDLE g_service_stop_event = NULL;

/* LOCAL FUNCTIONS PROTOS */
static VOID WINAPI service_main(DWORD argc, LPWSTR *argv);
static DWORD WINAPI service_ctrl_handler(DWORD control, DWORD event_type, LPVOID event_data, LPVOID context);
static BOOL service_update_status(DWORD current_state, DWORD win32_exit_code, DWORD wait_hint);

#if defined(_DEBUG_CONSOLE)
static BOOL WINAPI debug_console_ctrl_handler(DWORD ctrl_type);
#endif

static errorcode_t service_start_runtime(void);
static DWORD service_wait_for_stop(void);
static void service_stop_runtime(void);

int service_dispatch(void) {
    SERVICE_TABLE_ENTRYW service_table[] = {
        { (LPWSTR)SERVICE_NAME, service_main },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherW(service_table)) {
        win_evt_log(L"Failed to start the Ctrl Dispatcher!", LOGLEVEL_ERROR);
        return (int)GetLastError();
    }

    logmsg(LOGGING_NORMAL, L"The service dispatcher was defined successfully for the service: %ls", SERVICE_NAME);

    return EXIT_SUCCESS;
}

static VOID WINAPI service_main(DWORD argc, LPWSTR *argv) {
    DWORD wait_result;

    (void)argc;
    (void)argv;

    ZeroMemory(&g_service_status, sizeof(g_service_status));
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    g_service_status_handle = RegisterServiceCtrlHandlerExW(
        SERVICE_NAME,
        service_ctrl_handler,
        NULL
    );

    if (g_service_status_handle == NULL) {
        win_evt_log(L"Failed to create the service HANDLE. Service was not initiated", LOGLEVEL_ERROR);
        return;
    }

    if (!service_update_status(SERVICE_START_PENDING, NO_ERROR, 3000)) {
        win_evt_log(L"Failed to update the service status. Service was not initiated", LOGLEVEL_ERROR);
        return;
    }

    if (service_start_runtime() != ST_CODE_SUCCESS) {
        service_update_status(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    if (!service_update_status(SERVICE_RUNNING, NO_ERROR, 0)) {
        win_evt_log(L"Failed to start the service", LOGLEVEL_ERROR);
        service_stop_runtime();
        return;
    }

    logmsg(LOGGING_NORMAL, L"Service %ls started successfully", SERVICE_NAME);

    /*
     * Listen to STOP EVENTS for the Service
     */
    wait_result = service_wait_for_stop();
    if (wait_result != WAIT_OBJECT_0) {
        win_evt_log(L"WaitForSingleObject failed while waiting for stop event.", LOGLEVEL_ERROR);
    }

    if (!service_update_status(SERVICE_STOP_PENDING, NO_ERROR, 3000)) {
        win_evt_log_id(L"Failed to update service status to STOP_PENDING.",
                       JG_EVENT_ID_STOPSERVICE, LOGLEVEL_ERROR);
    }
    service_stop_runtime();

    service_update_status(SERVICE_STOPPED, NO_ERROR, 0);

    // Release the configuration
    release_config();
}

static DWORD WINAPI service_ctrl_handler(DWORD control, DWORD event_type, LPVOID event_data, LPVOID context) {
    (void)event_type;
    (void)event_data;
    (void)context;

    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            if (!service_update_status(SERVICE_STOP_PENDING, NO_ERROR, 3000)) {
                win_evt_log_id(L"Failed to update service status to STOP_PENDING.",
                               JG_EVENT_ID_STOPSERVICE, LOGLEVEL_ERROR);
            }

            /*
             * TODO: Implement the shutdown logic here
             */

            if (g_service_stop_event != NULL) {
                if (!SetEvent(g_service_stop_event)) {
                    win_evt_log_id(L"Failed to signal stop event.",
                                   JG_EVENT_ID_STOPSERVICE, LOGLEVEL_ERROR);
                    return GetLastError();
                }
            }

            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static BOOL service_update_status(DWORD current_state, DWORD win32_exit_code, DWORD wait_hint) {
    static DWORD checkpoint = 1;

    if (g_debug_mode) {
        return TRUE;
    }

    g_service_status.dwCurrentState = current_state;
    g_service_status.dwWin32ExitCode = win32_exit_code;
    g_service_status.dwWaitHint = wait_hint;

    switch (current_state) {
        case SERVICE_START_PENDING:
        case SERVICE_STOP_PENDING:
            g_service_status.dwControlsAccepted = 0;
            g_service_status.dwCheckPoint = checkpoint++;
            break;

        case SERVICE_RUNNING:
            g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
            g_service_status.dwCheckPoint = 0;
            checkpoint = 1;
            break;

        case SERVICE_STOPPED:
            g_service_status.dwControlsAccepted = 0;
            g_service_status.dwCheckPoint = 0;
            checkpoint = 1;
            break;

        default:
            g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
            g_service_status.dwCheckPoint = 0;

    }

    return SetServiceStatus(g_service_status_handle, &g_service_status);
}

static void service_stop_runtime(void) {
    /*
     * TODO: Implement
     * Example:
     *   - stop worker threads
     *   - flush state
     *   - release resources
     */
    g_control_mode = TRUE;

    if (g_service_stop_event != NULL) {
        SetEvent(g_service_stop_event);
    }

    dispatcher_stop();

    if (g_service_stop_event != NULL) {
        CloseHandle(g_service_stop_event);
        g_service_stop_event = NULL;
    }

    win_evt_log_id(L"Service stopped successfully!", JG_EVENT_ID_STOPSERVICE, LOGLEVEL_INFO);
}
static DWORD service_wait_for_stop(void) {
    if (g_service_stop_event == NULL) {
        SetLastError(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    }

    logmsg(LOGGING_NORMAL, L"Registered the stop event for the Service %ls", SERVICE_NAME);

    return WaitForSingleObject(g_service_stop_event, INFINITE);
}
static errorcode_t service_start_runtime(void) {
    errorcode_t result;
    g_service_stop_event = CreateEventW(NULL, TRUE, FALSE, SERVICE_STOP_EVENT_NAME);
    if (g_service_stop_event == NULL) {
        win_evt_log_id(L"Failed to create service stop event.", JG_EVENT_ID_STARTSERVICE, LOGLEVEL_ERROR);
        return ST_CODE_FAILED_CREATEEVENT;
    }

    /*
     * TODO: IMPLEMENTATION OF THE SERVICE MONITOR HERE!!!
     * Example:
     *   - config load
     *   - worker thread creation
     *   - startup checks
     */
    // Start the dispatch for the agent processes
    result = dispatcher_start(g_service_stop_event);
    if ( !_IS_SUCCESS(result) ) {
        win_evt_log_id(L"Failed to dispatch the agent execution!", JG_EVENT_ID_STARTSERVICE, LOGLEVEL_ERROR);
        return ST_CODE_FAILED_DISPATCH_AGENTPROC;
    }

    win_evt_log_id(L"Agent Service started successfully!", JG_EVENT_ID_STARTSERVICE, LOGLEVEL_INFO);
    return ST_CODE_SUCCESS;
}

#if defined(_DEBUG_CONSOLE)
static BOOL WINAPI debug_console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            wprintf(L"[DEBUG] Stop requested from console.\n");

            if (g_service_stop_event != NULL) {
                SetEvent(g_service_stop_event);
            }
            return TRUE;

        default:
            return FALSE;
    }
}

int service_run_debug(void) {
    DWORD wait_result;

    g_debug_mode = TRUE;

    wprintf(L"[DEBUG] Starting service in console mode...\n");

    if (!SetConsoleCtrlHandler(debug_console_ctrl_handler, TRUE)) {
        wprintf(L"[DEBUG] Failed to install console control handler. Error=%lu\n", GetLastError());
        return (int)GetLastError();
    }

    ZeroMemory(&g_service_status, sizeof(g_service_status));
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    if (service_start_runtime() != ST_CODE_SUCCESS) {
        wprintf(L"[DEBUG] service_start_runtime() failed.\n");
        return EXIT_FAILURE;
    }

    wprintf(L"[DEBUG] Service is running. Press Ctrl+C to stop.\n");

    wait_result = service_wait_for_stop();
    if (wait_result != WAIT_OBJECT_0) {
        wprintf(L"[DEBUG] WaitForSingleObject failed. Error=%lu\n", GetLastError());
        win_evt_log_id(L"Debug mode wait failed.", JG_EVENT_ID_STOPSERVICE, LOGLEVEL_ERROR);
    }

    service_stop_runtime();
    // Release the configuration
    release_config();

    wprintf(L"[DEBUG] Service stopped.\n");
    return ST_CODE_SUCCESS;
}
#endif
