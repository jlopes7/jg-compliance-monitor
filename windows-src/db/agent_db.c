//
// Created by Joao Gonzalez on 4/26/2026.
//

#include "windows/db/agent_db.h"

#include "windows/logging.h"
#include "windows/winreg_config.h"

/**
 * The tiny SQL DDL for the Agent persistence. These entries are used for Batch
 * processing later in the code
 */
const char *AGENT_DB_DDL =
        "CREATE TABLE IF NOT EXISTS fs_scan_result ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    path TEXT NOT NULL,"
        "    path_hash TEXT NOT NULL UNIQUE,"
        "    file_name TEXT,"
        "    extension TEXT,"
        "    size_bytes INTEGER,"
        "    modified_time_utc INTEGER,"
        "    product_name TEXT,"
        "    product_version TEXT,"
        "    vendor_name TEXT,"
        "    classification_status TEXT NOT NULL DEFAULT 'pending',"
        "    first_seen_utc INTEGER NOT NULL,"
        "    last_seen_utc INTEGER NOT NULL,"
        "    scan_run_id TEXT"
        ");"

        "CREATE INDEX IF NOT EXISTS idx_fs_scan_result_last_seen "
        "ON fs_scan_result(last_seen_utc);"

        "CREATE INDEX IF NOT EXISTS idx_fs_scan_result_classification_status "
        "ON fs_scan_result(classification_status);";

static errorcode_t agent_db_exec_sql(AGENT_DB db, const char *sql) {
    char *errmsg = NULL;
    errorcode_t result;

    if (db == NULL || PTR(db).handle == NULL || sql == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    logmsg(LOGGING_NORMAL, L"[DB] About the execute the SQL query for the agent local database: %S", sql);
    result = sqlite3_exec(PTR(db).handle, sql, NULL, NULL, &errmsg);
    if ( !_IS_DBOPER_SUCCEEDED(result) ) {
        if (errmsg != NULL) {
            logmsg(LOGGING_ERROR, L"[DB] Failed to run the SQL instruction: %S. Details: %S", sql, errmsg);
            sqlite3_free(errmsg);
        }

        return ST_CODE_DB_EXEC_FAILED;
    }

    return ST_CODE_SUCCESS;
}

static errorcode_t agent_db_bind_text16_or_null(sqlite3_stmt *stmt, int index,  LPCWSTR value) {
    errorcode_t result;

    if (stmt == NULL || index <= 0) {
        return ST_CODE_INVALID_PARAM;
    }

    if (value == NULL) {
        result = sqlite3_bind_null(stmt, index);
    }
    else {
        result = sqlite3_bind_text16(stmt, index, value, -1, SQLITE_TRANSIENT);
    }

    if ( !_IS_DBOPER_SUCCEEDED(result) ) {
        logmsg(LOGGING_ERROR, L"[DB] Failed to the prepared statement for the string value: %ls", value);
        return ST_CODE_DB_BIND_FAILED;
    }

    return ST_CODE_SUCCESS;
}

static errorcode_t agent_db_bind_int64(sqlite3_stmt *stmt, int index, int64_t value) {
    errorcode_t result;

    if (stmt == NULL || index <= 0) {
        return ST_CODE_INVALID_PARAM;
    }

    result = sqlite3_bind_int64(stmt, index, (sqlite3_int64) value);
    if ( !_IS_DBOPER_SUCCEEDED(result) ) {
        logmsg(LOGGING_ERROR, L"[DB] Failed to the prepared statement for the int64 value: %d", value);
        return ST_CODE_DB_BIND_FAILED;
    }

    return ST_CODE_SUCCESS;
}

errorcode_t agent_db_open(AGENT_DB *db) {
    AGENT_DB local_db;
    errorcode_t result;
    wchar_t db_path[MAX_PATH];

    ZeroMemory(db_path, sizeof(db_path));
    read_registry_string(REG_AGENTCACHEDB, db_path, MAX_PATH);

    if (db == NULL || db_path[0] == L'\0') {
        return ST_CODE_INVALID_PARAM;
    }

    logmsg(LOGGING_NORMAL, L"[DB] Opening agent database: %ls", db_path);

    PTR(db) = NULL;

    local_db = (AGENT_DB) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(agent_db_t));
    if (local_db == NULL) {
        return ST_CODE_OUT_OF_MEMORY;
    }

    result = sqlite3_open16(db_path, &PTR(local_db).handle);
    if ( !_IS_DBOPER_SUCCEEDED(result) ) {
        if (PTR(local_db).handle != NULL) {
            sqlite3_close(PTR(local_db).handle);
            PTR(local_db).handle = NULL;
        }

        logmsg(LOGGING_ERROR, L"[DB] Failed to open local agent database: %ls", db_path);
        HeapFree(GetProcessHeap(), 0, local_db);
        return ST_CODE_DB_OPEN_FAILED;
    }

    /*
     * WAL mode is generally a good default for a local agent database.
     * It allows better read/write behaviour than the default rollback journal.
     */
    agent_db_exec_sql(local_db, "PRAGMA journal_mode=WAL;");
    agent_db_exec_sql(local_db, "PRAGMA synchronous=NORMAL;");
    agent_db_exec_sql(local_db, "PRAGMA foreign_keys=ON;");

    PTR(db) = local_db;

    return ST_CODE_SUCCESS;
}

errorcode_t agent_db_close(AGENT_DB db) {
    if (db == NULL) {
        return ST_CODE_SUCCESS;
    }

    if (PTR(db).handle != NULL) {
        sqlite3_close(PTR(db).handle);
        db->handle = NULL;
    }

    HeapFree(GetProcessHeap(), 0, db);

    return ST_CODE_SUCCESS;
}

errorcode_t agent_db_init_schema(AGENT_DB db) {
    if (db == NULL || PTR(db).handle == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    return agent_db_exec_sql(db, AGENT_DB_DDL);
}
