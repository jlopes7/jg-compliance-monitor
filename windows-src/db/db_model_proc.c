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

errorcode_t db_agent_system_insert(AGENT_DB db, SYSTEM_DETAILS sysdetails) {
    sqlite3_stmt *stmt = NULL;
    errorcode_t result = ST_CODE_SUCCESS;
    errorcode_t fin_result;

    int64_t now_epoch;
    int index = 1;

    NEW_LPWSTR(hostname, MAX_COMPUTERNAME_LENGTH + 1);
    NEW_LPWSTR(hostname_hash, SHA256_HEX_CCH);
    NEW_LPWSTR(now_iso, DB_UTC_ISO_CCH);

    if (db == NULL || PTR(db).handle == NULL || sysdetails == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    result = get_hostname(hostname, ARRAY_LEN_COUNT(hostname));
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = hash_string(hostname, hostname_hash, ARRAY_LEN_COUNT(hostname_hash));
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

errorcode_t db_agent_jvm_insert(AGENT_DB db, JVM_DETAILS jvmdetails) {
    sqlite3_stmt *stmt = NULL;
    errorcode_t result = ST_CODE_SUCCESS;
    errorcode_t fin_result;

    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1];
    wchar_t hostname_hash[SHA256_HEX_CCH];
    wchar_t installpath_hash[SHA256_HEX_CCH];
    wchar_t now_iso[DB_UTC_ISO_CCH];

    int index = 1;

    if (db == NULL || PTR(db).handle == NULL || jvmdetails == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    if (jvmdetails->installation_path == NULL || jvmdetails->installation_path[0] == L'\0') {
        return ST_CODE_INVALID_PARAM;
    }

    result = get_hostname(hostname, ARRAY_LEN_COUNT(hostname));
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = hash_string(hostname, hostname_hash, ARRAY_LEN_COUNT(hostname_hash));
    if (!_IS_SUCCESS(result)) {
        return result;
    }

    result = hash_string(
        jvmdetails->installation_path,
        installpath_hash,
        ARRAY_LEN_COUNT(installpath_hash)
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
    DB_TRY(agent_db_bind_int64(stmt, index++, DB_REMOVE_FIRST_READ));

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

errorcode_t db_agent_productinfo_insert(AGENT_DB db, JVM_DETAILS jvmdetails) {
    sqlite3_stmt *stmt = NULL;
    errorcode_t result = ST_CODE_SUCCESS;
    errorcode_t fin_result;

    PRODUCT_INFO product;

    wchar_t installpath_hash[SHA256_HEX_CCH];
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

    result = hash_string(
        jvmdetails->installation_path,
        installpath_hash,
        ARRAY_LEN_COUNT(installpath_hash)
    );

    if (!_IS_SUCCESS(result)) {
        return result;
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
