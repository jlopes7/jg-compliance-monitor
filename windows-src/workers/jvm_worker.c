//
// Created by Joao Gonzalez on 4/29/2026.
//

#include "windows/service/jvm_worker.h"

#include "windows/config.h"
#include "windows/logging.h"

errorcode_t jvm_worker_run(SYSTEM_DETAILS *system_details, LPCWSTR jvmPath) {
    errorcode_t rc;
    if (!PTR(system_details) || !jvmPath) {
        return ST_CODE_INVALID_PARAM;
    }

    // Add a new JVM to the list
    rc = jvm_parse_model(PTR(system_details), jvmPath);
    if ( !_IS_SUCCESS(rc) ) {
        logmsg(LOGGING_ERROR, L"-- jvm_parse_model: jvm_path=%ls failed", jvmPath);
    }

    return ST_CODE_SUCCESS;
}
