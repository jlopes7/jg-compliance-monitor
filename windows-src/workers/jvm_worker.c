//
// Created by Joao Gonzalez on 4/29/2026.
//

#include "windows/service/jvm_worker.h"

#include "windows/config.h"
#include "windows/logging.h"

errorcode_t jvm_worker_run(SYSTEM_DETAILS *system_details, LPCWSTR jvmPath, HANDLE stop_event) {
    errorcode_t rc;
    if (!PTR(system_details) || !jvmPath) {
        return ST_CODE_INVALID_PARAM;
    }

    if ( jvm_verify_valid_installpath(jvmPath, stop_event) ) {
        // Add a new JVM to the list
        rc = jvm_parse_model(PTR(system_details), (LPVOID)jvmPath, stop_event);
        if ( !_IS_SUCCESS(rc) ) {
            logmsg(LOGGING_ERROR, L"-- jvm_parse_model: jvm_path=%ls failed", jvmPath);
        }
    }

    return ST_CODE_SUCCESS;
}

BOOL jvm_verify_valid_installpath(LPCWSTR jvmPath, HANDLE stop_event) {
    BOOL result = TRUE;
    wchar_t jvm_file_path[MAX_PATH];
    wchar_t newpath[MAX_PATH];

    if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) {
        return FALSE;
    }

    ZeroMemory(jvm_file_path, sizeof(jvm_file_path));
    ZeroMemory(newpath, sizeof(newpath));

    fs_retrieve_directory(jvmPath, newpath, 3); // From jdk1.8.0_351/jre/bin/java.exe, goes two levels, e.g., to jdk1.8.0_351/
    if ( fs_join_path(newpath, L"jre\\bin\\java.exe", jvm_file_path, MAX_PATH) ) {
        result = !(fs_contains_signature(newpath, L"jdk") && fs_resource_exists(jvm_file_path, LEAF));
    }
    else {
        logmsg(LOGGING_WARN, L"-- jvm_parse_model: could merge jvm_path=%ls to jre\\bin\\java.exe", newpath);
    }

    return result;
}
