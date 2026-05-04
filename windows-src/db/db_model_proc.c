//
// Created by Joao Gonzalez on 5/2/2026.
//

#include "utils.h"
#include "windows/db/agent_db.h"
#include "windows/db/db_model_proc.h"

#include <bcrypt.h>
#include <wctype.h>

#include "windows/logging.h"

#define DB_TRY(EXPR)                         \
    do {                                     \
        result = (EXPR);                     \
        if (!_IS_SUCCESS(result)) {          \
            goto cleanup;                    \
        }                                    \
    } while (0)

static errorcode_t hash_string(LPCWSTR strtobh, LPWSTR buffer, DWORD buffer_cch) {
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_HASH_HANDLE h_hash = NULL;
    BYTE hash[SHA1_HASH_CCH];
    NTSTATUS status;
    DWORD i;
    LPCWSTR start;
    LPCWSTR end;
    static const wchar_t hex[] = L"0123456789abcdef";

    DWORD normalized_cch;
    NEW_LPWSTR(normalized, BUFFER_SIZE);

    if (!strtobh || !buffer) {
        return ST_CODE_INVALID_PARAM;
    }

    buffer[0] = L'\0';

    if (buffer_cch < SHA256_HEX_CCH) {
        return ST_CODE_BUFFER_TOO_SMALL;
    }

    start = strtobh;
    while (*start == L' ' || *start == L'\t' || *start == L'\r' || *start == L'\n') {
        start++;
    }

    end = start + wcslen(start);
    while (end > start &&
           (end[-1] == L' ' || end[-1] == L'\t' || end[-1] == L'\r' || end[-1] == L'\n')) {
        end--;
    }

    normalized_cch = (DWORD)(end - start);

    if (normalized_cch >= BUFFER_SIZE) {
        return ST_CODE_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < normalized_cch; i++) {
        normalized[i] = (wchar_t)towlower(start[i]);
    }
    normalized[normalized_cch] = L'\0';

    status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0) {
        return ST_CODE_FAILED_OPERATION;
    }

    status = BCryptCreateHash(h_alg, &h_hash, NULL, 0, NULL, 0, 0);
    if (status >= 0) {
        status = BCryptHashData(
            h_hash,
            (PUCHAR)normalized,
            normalized_cch * sizeof(wchar_t),
            0
        );
    }

    if (status >= 0) {
        status = BCryptFinishHash(h_hash, hash, sizeof(hash), 0);
    }

    if (h_hash) {
        BCryptDestroyHash(h_hash);
    }

    if (h_alg) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
    }

    if (status < 0) {
        return ST_CODE_FAILED_OPERATION;
    }

    for (i = 0; i < sizeof(hash); i++) {
        buffer[i * 2]     = hex[(hash[i] >> 4) & 0x0F];
        buffer[i * 2 + 1] = hex[hash[i] & 0x0F];
    }

    buffer[SHA256_HEX_CCH -1] = L'\0';

    return ST_CODE_SUCCESS;
}

static errorcode_t db_bind_bool(sqlite3_stmt *stmt, int index, BOOL value) {
    return agent_db_bind_int64(stmt, index, value ? 1 : 0);
}

static errorcode_t db_now_utc_iso(LPWSTR buffer, DWORD buffer_cch) {
    SYSTEMTIME st;
    int written;

    if (buffer == NULL || buffer_cch < DB_UTC_ISO_CCH) {
        return ST_CODE_BUFFER_TOO_SMALL;
    }

    GetSystemTime(&st);

    written = swprintf_s(
        buffer,
        buffer_cch,
        L"%04hu-%02hu-%02huT%02hu:%02hu:%02huZ",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond
    );

    if (written < 0) {
        return ST_CODE_FAILED_OPERATION;
    }

    return ST_CODE_SUCCESS;
}

static errorcode_t db_hash_pair(
    LPCWSTR left,
    LPCWSTR right,
    LPWSTR buffer,
    DWORD buffer_cch
) {
    wchar_t combined[BUFFER_SIZE];
    int written;

    if (left == NULL || right == NULL || buffer == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    written = swprintf_s(
        combined,
        ARRAY_LEN_COUNT(combined),
        L"%ls|%ls",
        left,
        right
    );

    if (written < 0) {
        return ST_CODE_BUFFER_TOO_SMALL;
    }

    return hash_string(combined, buffer, buffer_cch);
}

errorcode_t db_agent_system_insert(AGENT_DB db, SYSTEM_DETAILS sysdetails, LPWSTR hostname_hash) {
    sqlite3_stmt *stmt = NULL;
    errorcode_t result = ST_CODE_SUCCESS;
    errorcode_t fin_result;

    int64_t now_epoch;
    int index = 1;

    NEW_LPWSTR(hostname, MAX_COMPUTERNAME_LENGTH + 1);
    NEW_LPWSTR(now_iso, DB_UTC_ISO_CCH);

    ZeroMemory(hostname_hash, SHA256_HEX_CCH);

    if (db == NULL || PTR(db).handle == NULL || sysdetails == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    result = get_hostname(hostname, ARRAY_LEN_COUNT(hostname));
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = hash_string(hostname, hostname_hash, SHA256_HEX_CCH);
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = db_now_utc_iso(now_iso, ARRAY_LEN_COUNT(now_iso));
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    now_epoch = (int64_t)time(NULL);

    result = agent_db_prepare(db, k_agent_system_upsert_dml, &stmt);
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, hostname_hash));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, hostname));

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, sysdetails->os));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, sysdetails->version));

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, sysdetails->env_path));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, sysdetails->env_javahome));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, sysdetails->env_path_installpath));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, sysdetails->env_path_version));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, sysdetails->env_javahome_installpath));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, sysdetails->env_javahome_version));

    DB_TRY(db_bind_bool(stmt, index++, sysdetails->is_env_path_broken));
    DB_TRY(db_bind_bool(stmt, index++, sysdetails->is_env_javahome_broken));

    DB_TRY(agent_db_bind_int64(stmt, index++, (int64_t)sysdetails->num_vcores));
    DB_TRY(agent_db_bind_int64(stmt, index++, (int64_t)sysdetails->num_physical_cores));
    DB_TRY(agent_db_bind_int64(stmt, index++, (int64_t)sysdetails->vm_size));
    DB_TRY(agent_db_bind_int64(stmt, index++, (int64_t)sysdetails->jvm_count));
    DB_TRY(agent_db_bind_int64(stmt, index++, 0));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, L"pending"));

    DB_TRY(agent_db_bind_int64(stmt, index++, now_epoch));
    DB_TRY(agent_db_bind_int64(stmt, index++, now_epoch));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, AGENT_SYSTEM_SCAN_RUN_ID));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, now_iso));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, now_iso));

    DB_TRY(agent_db_step_done(stmt));

cleanup:
    fin_result = agent_db_finalize(stmt);
    if (_IS_SUCCESS(result) && !_IS_SUCCESS(fin_result)) {
        result = fin_result;
    }

    return result;
}

errorcode_t db_agent_jvm_insert(AGENT_DB db, JVM_DETAILS jvmdetails, LPCWSTR hostname_hash, LPWSTR installpath_hash) {
    sqlite3_stmt *stmt = NULL;
    errorcode_t result = ST_CODE_SUCCESS;
    errorcode_t fin_result;

    int index = 1;

    NEW_LPWSTR(now_iso, DB_UTC_ISO_CCH);

    if (db == NULL || PTR(db).handle == NULL || jvmdetails == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    if (jvmdetails->installation_path == NULL || jvmdetails->installation_path[0] == L'\0') {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(installpath_hash, SHA256_HEX_CCH);

    result = hash_string(
        jvmdetails->installation_path,
        installpath_hash,
        SHA256_HEX_CCH
    );

    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = db_now_utc_iso(now_iso, ARRAY_LEN_COUNT(now_iso));
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = agent_db_prepare(db, k_agent_jvm_upsert_dml, &stmt);
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, installpath_hash));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, hostname_hash));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, jvmdetails->installation_path));

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, jvmdetails->publisher));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, jvmdetails->license_type));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, jvmdetails->legal_copyright));

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, jvmdetails->fullversion_jdk));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, jvmdetails->fullversion_win));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, jvmdetails->runtime_version));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, jvmdetails->build_type));

    DB_TRY(agent_db_bind_int64(stmt, index++, (int64_t)jvmdetails->major_version));
    DB_TRY(agent_db_bind_int64(stmt, index++, (int64_t)jvmdetails->minor_version));

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, jvmdetails->product_name));

    DB_TRY(db_bind_bool(stmt, index++, jvmdetails->is_jdk));
    DB_TRY(db_bind_bool(stmt, index++, jvmdetails->is_jre));
    DB_TRY(db_bind_bool(stmt, index++, jvmdetails->is_ojdk));
    DB_TRY(db_bind_bool(stmt, index++, jvmdetails->is_oracle));

    DB_TRY(agent_db_bind_int64(stmt, index++, DB_SYNC_NOT_SYNCED));
    DB_TRY(agent_db_bind_int64(stmt, index++, DB_JVM_REMOVE_CTRL_FIRST_READ));

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, now_iso));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, now_iso));

    DB_TRY(agent_db_step_done(stmt));

cleanup:
    fin_result = agent_db_finalize(stmt);
    if (_IS_SUCCESS(result) && !_IS_SUCCESS(fin_result)) {
        result = fin_result;
    }

    return result;
}

errorcode_t db_agent_productinfo_insert(AGENT_DB db, JVM_DETAILS jvmdetails, LPCWSTR installpath_hash) {
    sqlite3_stmt *stmt = NULL;
    errorcode_t result = ST_CODE_SUCCESS;
    errorcode_t fin_result;

    PRODUCT_INFO product;

    wchar_t display_name_hash[SHA256_HEX_CCH];
    wchar_t now_iso[DB_UTC_ISO_CCH];

    int index = 1;

    if (db == NULL || PTR(db).handle == NULL || jvmdetails == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    if (jvmdetails->installation_path == NULL || jvmdetails->installation_path[0] == L'\0') {
        return ST_CODE_INVALID_PARAM;
    }

    product = jvmdetails->product_info;
    if (product == NULL || product->display_name == NULL || product->display_name[0] == L'\0') {
        return ST_CODE_INVALID_PARAM;
    }

    /*
     * This intentionally hashes install_path + display_name instead of only
     * display_name. Otherwise two JVM installs with the same DisplayName could
     * collapse into one agent_product_details row.
     */
    result = db_hash_pair(
        jvmdetails->installation_path,
        product->display_name,
        display_name_hash,
        ARRAY_LEN_COUNT(display_name_hash)
    );

    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = db_now_utc_iso(now_iso, ARRAY_LEN_COUNT(now_iso));
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = agent_db_prepare(db, k_agent_productinfo_upsert_dml, &stmt);
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, display_name_hash));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, installpath_hash));

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, product->display_name));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, product->display_version));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, product->tel_help));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, product->install_date));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, product->publisher));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, product->url));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, product->uninstall_instr));

    DB_TRY(agent_db_bind_int64(stmt, index++, (int64_t)product->major_version));
    DB_TRY(agent_db_bind_int64(stmt, index++, (int64_t)product->minor_version));

    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, now_iso));
    DB_TRY(agent_db_bind_text16_or_null(stmt, index++, now_iso));

    DB_TRY(agent_db_step_done(stmt));

cleanup:
    fin_result = agent_db_finalize(stmt);
    if (_IS_SUCCESS(result) && !_IS_SUCCESS(fin_result)) {
        result = fin_result;
    }

    return result;
}

static BOOL db_hash_in_list(LPCWSTR hash, LPWSTR hash_list, DWORD hash_count) {
    DWORD i;

    if (hash == NULL || hash_list == NULL) {
        return FALSE;
    }

    for (i = 0; i < hash_count; i++) {
        LPCWSTR current_hash = hash_list + ((SIZE_T)i * SHA256_HEX_CCH);

        if (current_hash[0] == L'\0') {
            continue;
        }

        if (wcscmp(hash, current_hash) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static errorcode_t db_build_active_jvm_hash_list(SYSTEM_DETAILS sysdetails, LPWSTR *hash_list_out, DWORD *hash_count_out) {
    LPWSTR hash_list = NULL;
    DWORD i;
    DWORD hash_count = 0;
    SIZE_T alloc_cch;
    errorcode_t result;

    if (sysdetails == NULL || hash_list_out == NULL || hash_count_out == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    PTR(hash_list_out) = NULL;
    PTR(hash_count_out) = 0;

    if (PTR(sysdetails).jvm_count == 0 || PTR(sysdetails).jvm == NULL) {
        return ST_CODE_SUCCESS;
    }

    alloc_cch = (SIZE_T)PTR(sysdetails).jvm_count * SHA256_HEX_CCH;

    hash_list = HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        alloc_cch * sizeof(wchar_t)
    );
    if (hash_list == NULL) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    for (i = 0; i < PTR(sysdetails).jvm_count; i++) {
        JVM_DETAILS jvm;
        LPWSTR hash_slot;

        jvm = PTR(sysdetails).jvm[i];
        if (jvm == NULL ||
            PTR(jvm).installation_path == NULL ||
            PTR(jvm).installation_path[0] == L'\0') continue;

        hash_slot = hash_list + ((SIZE_T)hash_count * SHA256_HEX_CCH);

        result = hash_string(
            PTR(jvm).installation_path,
            hash_slot,
            SHA256_HEX_CCH
        );

        if (!_IS_SUCCESS(result)) {
            HeapFree(GetProcessHeap(), 0, hash_list);
            return result;
        }

        hash_count++;
    }

    PTR(hash_list_out)  = hash_list;
    PTR(hash_count_out) = hash_count;

    return ST_CODE_SUCCESS;
}

errorcode_t db_agent_pair_jvminstances(AGENT_DB db, SYSTEM_DETAILS sysdetails, LPCWSTR hostname_hash) {
    sqlite3_stmt *select_stmt = NULL;
    sqlite3_stmt *update_stmt = NULL;

    LPWSTR active_hash_list = NULL;
    DWORD active_hash_count = 0;

    errorcode_t result = ST_CODE_SUCCESS;
    errorcode_t fin_select_result;
    errorcode_t fin_update_result;

    int step_rc;
    int remove_ctrl;

    NEW_LPWSTR(now_iso, DB_UTC_ISO_CCH);

    if (db == NULL ||
        PTR(db).handle == NULL ||
        sysdetails == NULL ||
        hostname_hash == NULL ||
        hostname_hash[0] == L'\0') {
        return ST_CODE_INVALID_PARAM;
    }

    result = db_now_utc_iso(now_iso, ARRAY_LEN_COUNT(now_iso));
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = db_build_active_jvm_hash_list(
        sysdetails,
        &active_hash_list,
        &active_hash_count
    );

    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = agent_db_prepare(
        db,                                         /* Database object reference */
        k_agent_jvm_select_hashes_by_system_dml,    /* Select all the JVM hashes per system hash */
        &select_stmt
    );
    if (!_IS_SUCCESS(result)) {
        goto cleanup;
    }

    result = agent_db_prepare(
        db,
        k_agent_jvm_pair_state_update_dml,
        &update_stmt
    );
    if (!_IS_SUCCESS(result)) {
        goto cleanup;
    }

    DB_TRY(agent_db_bind_text16_or_null(select_stmt, 1, hostname_hash));

    while ((step_rc = sqlite3_step(select_stmt)) == SQLITE_ROW) {
        LPCWSTR db_installpath_hash;

        /*
         * sqlite3_column_text16() returns memory owned by SQLite.
         * It remains valid until the statement is stepped/reset/finalized.
         */
        db_installpath_hash = (LPCWSTR)sqlite3_column_text16(select_stmt, 0);
        if (db_installpath_hash == NULL || db_installpath_hash[0] == L'\0') {
            continue;
        }

        if (db_hash_in_list(db_installpath_hash, active_hash_list, active_hash_count)) {
            remove_ctrl = DB_JVM_REMOVE_STILLEXISTS;
        }
        else {
            remove_ctrl = DB_JVM_REMOVE_CTRL_REMOVED;

            logmsg(LOGGING_WARN, L"[DB] It looks like the given JVM was removed, does not exist anymore (Updating): %ls", db_installpath_hash);
        }

        sqlite3_reset(update_stmt);
        sqlite3_clear_bindings(update_stmt);

        DB_TRY(agent_db_bind_int64(update_stmt, 1, remove_ctrl));
        DB_TRY(agent_db_bind_text16_or_null(update_stmt, 2, now_iso));
        DB_TRY(agent_db_bind_text16_or_null(update_stmt, 3, hostname_hash));
        DB_TRY(agent_db_bind_text16_or_null(update_stmt, 4, db_installpath_hash));

        DB_TRY(agent_db_step_done(update_stmt));
    }

    if (step_rc != SQLITE_DONE) {
        result = ST_CODE_DB_EXEC_FAILED;
        goto cleanup;
    }

cleanup:
    fin_select_result = agent_db_finalize(select_stmt);
    fin_update_result = agent_db_finalize(update_stmt);

    if (active_hash_list != NULL) {
        HeapFree(GetProcessHeap(), 0, active_hash_list);
    }

    if (_IS_SUCCESS(result) && !_IS_SUCCESS(fin_select_result)) {
        result = fin_select_result;
    }

    if (_IS_SUCCESS(result) && !_IS_SUCCESS(fin_update_result)) {
        result = fin_update_result;
    }

    return result;
}
