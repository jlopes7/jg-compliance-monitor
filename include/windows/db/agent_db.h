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

    //LPCWSTR db_name;
    LPCWSTR db_path;
} agent_db_t;

typedef agent_db_t *AGENT_DB;

errorcode_t agent_db_open(AGENT_DB *db);
errorcode_t agent_db_init_schema(AGENT_DB db);
errorcode_t agent_db_close(AGENT_DB db);

errorcode_t agent_db_prepare(AGENT_DB db, const char *sql, sqlite3_stmt **stmt);
errorcode_t agent_db_bind_text16_or_null(sqlite3_stmt *stmt, int index,  LPCWSTR value);
errorcode_t agent_db_bind_int64(sqlite3_stmt *stmt, int index, int64_t value);
errorcode_t agent_db_exec_sql(AGENT_DB db, const char *sql);
errorcode_t agent_db_step_done(sqlite3_stmt *stmt);
errorcode_t agent_db_finalize(sqlite3_stmt *stmt);

#ifdef __cplusplus
}
#endif

#endif //JG_COMPLIANCE_MONITOR_AGENT_DB_H
