//
// Created by joaol on 4/21/2026.
//

#include "windows/classif_json.h"
#include "windows/config.h"
#include "windows/service.h"
#include "windows/evtlog.h"
#include "windows/logging.h"

int wmain(void) {
    // Initialize the logging system
    errorcode_t rc;
    int exit_code;

    rc = logging_init();
    if ( !_IS_SUCCESS(rc) ) {
        win_evt_log_id_fmt(JG_EVENT_ID_INIDEFINITION,
                      LOGLEVEL_ERROR,
                       L"COULD NOT INITIALIZE THE LOGGING SYSTEM. THE AGENT WILL STILL RUN, BUT LOGGING IS NOT ACTIVATE.%ls Error code: %d",
                           LINE_BREAK,
                           rc);
    }

    // Initialize the internal configuration
    rc = init_config();
    if ( !_IS_SUCCESS(rc) ) {
        return rc;
    }

    // TODO: Add additional initializations...

    logmsg(LOGGING_NORMAL, L"Agent initial initialization completed successfully.");

#ifdef _DEBUG_CONSOLE
    exit_code = service_run_debug();
#else
    exit_code = service_dispatch();
#endif

    win_evt_log(L"Agent process was triggered to exit", LOGLEVEL_WARN);
    logging_end();

    return exit_code;
}