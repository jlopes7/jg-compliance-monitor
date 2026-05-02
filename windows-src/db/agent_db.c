//
// Created by Joao Gonzalez on 4/26/2026.
//

#include "windows/logging.h"
#include "windows/winreg_config.h"
#include "windows/db/db_model.h"
#include "windows/db/agent_db.h"

errorcode_t agent_db_exec_sql(AGENT_DB db, const char *sql) {
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

errorcode_t agent_db_bind_text16_or_null(sqlite3_stmt *stmt, int index,  LPCWSTR value) {
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

errorcode_t agent_db_bind_int64(sqlite3_stmt *stmt, int index, int64_t value) {
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

errorcode_t agent_db_prepare(AGENT_DB db, const char *sql, sqlite3_stmt **stmt) {
    int rc;

    if (db == NULL || PTR(db).handle == NULL || sql == NULL || stmt == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    PTR(stmt) = NULL;

    rc = sqlite3_prepare_v2(PTR(db).handle, sql, -1, stmt, NULL);
    if (rc != SQLITE_OK) {
        logmsg(
            LOGGING_ERROR,
            L"[DB] Failed to prepare SQL statement: %S. Details: %S",
            sql,
            sqlite3_errmsg(PTR(db).handle)
        );

        return ST_CODE_DB_PREPARE_FAILED;
    }

    return ST_CODE_SUCCESS;
}

errorcode_t agent_db_step_done(sqlite3_stmt *stmt) {
    int rc;
    sqlite3 *handle;

    if (stmt == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    handle = sqlite3_db_handle(stmt);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        logmsg(
            LOGGING_ERROR,
            L"[DB] Failed to execute prepared statement. SQLite rc=%d. Details: %S",
            rc,
            handle ? sqlite3_errmsg(handle) : "unknown"
        );

        return ST_CODE_DB_EXEC_FAILED;
    }

    return ST_CODE_SUCCESS;
}

errorcode_t agent_db_finalize(sqlite3_stmt *stmt) {
    int rc;

    if (stmt == NULL) {
        return ST_CODE_SUCCESS;
    }

    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        return ST_CODE_DB_EXEC_FAILED;
    }

    return ST_CODE_SUCCESS;
}

errorcode_t agent_db_open(AGENT_DB *db) {
    AGENT_DB local_db;
    errorcode_t result;

    NEW_LPWSTR(db_path, MAX_STRING_LEN);

    read_registry_string(REG_AGENTCACHEDB, db_path, MAX_STRING_LEN);

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

    PTR(local_db).db_path = heap_wcsdup(db_path);

    /*
     * WAL mode is generally a good default for a local agent database.
     * It allows better read/write behaviour than the default rollback journal.
     */
    result = agent_db_exec_sql(local_db, "PRAGMA journal_mode=WAL;");
    result |= agent_db_exec_sql(local_db, "PRAGMA synchronous=NORMAL;");
    result |= agent_db_exec_sql(local_db, "PRAGMA foreign_keys=ON;");

    if (!_IS_SUCCESS(result)) {
        return ST_CODE_DB_FAILEDPARSE_OPEN;
    }

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

    HeapFree(GetProcessHeap(), 0, (LPVOID)PTR(db).db_path);
    //HeapFree(GetProcessHeap(), 0, (LPVOID)PTR(db).db_name);
    HeapFree(GetProcessHeap(), 0, (LPVOID)db);

    return ST_CODE_SUCCESS;
}

errorcode_t agent_db_init_schema(AGENT_DB db) {
    errorcode_t result;
    if (db == NULL || PTR(db).handle == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    logmsg(LOGGING_NORMAL, L"[DB] Initializing agent database: %ls", PTR(db).db_path);

    result = agent_db_exec_sql(db, k_system_db_ddl);
    if (!_IS_SUCCESS(result)) {
        logmsg(LOGGING_ERROR, L"[DB] Failed to create the 'agent_system' entity: %ls. Code", k_system_db_ddl, result);
        return result;
    }
    result = agent_db_exec_sql(db, k_jvmdetails_db_ddl);
    if (!_IS_SUCCESS(result)) {
        logmsg(LOGGING_ERROR, L"[DB] Failed to create the 'agent_jvm_details' entity: %ls. Code", k_jvmdetails_db_ddl, result);
        return result;
    }

    result = agent_db_exec_sql(db, k_productinfo_db_ddl);
    if (!_IS_SUCCESS(result)) {
        logmsg(LOGGING_ERROR, L"[DB] Failed to create the 'agent_product_details' entity: %ls. Code", k_productinfo_db_ddl, result);
        return result;
    }

    return ST_CODE_SUCCESS;
}
