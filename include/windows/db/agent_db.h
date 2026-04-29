//
// Created by Joao Gonzalez on 4/26/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_AGENT_DB_H
#define JG_COMPLIANCE_MONITOR_AGENT_DB_H

#include <windows.h>
#include <stdint.h>

#include "windows/sqlite3.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _IS_DBOPER_SUCCEEDED(rc) ( ((rc) == SQLITE_OK) )

typedef struct agent_db_t {
    sqlite3 *handle;
} agent_db_t;

typedef agent_db_t *AGENT_DB;

typedef struct fs_scan_result_t {
    const wchar_t *path;
    const wchar_t *path_hash;

    const wchar_t *file_name;
    const wchar_t *extension;

    int64_t size_bytes;
    int64_t modified_time_utc;

    const wchar_t *product_name;
    const wchar_t *product_version;
    const wchar_t *vendor_name;

    const wchar_t *classification_status;

    int64_t first_seen_utc;
    int64_t last_seen_utc;

    const wchar_t *scan_run_id;
} fs_scan_result_t;

typedef fs_scan_result_t *FS_SCAN_RESULT;

errorcode_t agent_db_open(AGENT_DB *db);
errorcode_t agent_db_init_schema(AGENT_DB db);
errorcode_t agent_db_upsert_fs_result(AGENT_DB db, const FS_SCAN_RESULT result);
errorcode_t agent_db_close(AGENT_DB db);

#ifdef __cplusplus
}
#endif

#endif //JG_COMPLIANCE_MONITOR_AGENT_DB_H
