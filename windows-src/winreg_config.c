//
// Created by Joao Gonzalez on 4/22/2026.
//

#include "utils.h"
#include "windows/winreg_config.h"
#include "windows/evtlog.h"

errorcode_t ensure_registry_path() {
    HKEY hKey;
    errorcode_t result = RegCreateKeyEx(HKEY_LOCAL_MACHINE, REG_PATH, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) {
        win_evt_log_id_fmt(JG_EVENT_ID_REGMAINTENANCE, LOGLEVEL_ERROR, L"Failed to create/open registry key: %ld\n", result);
        return ST_CODE_CREATEUPT_REGKEY;
    }
    RegCloseKey(hKey);

    return ST_CODE_SUCCESS;
}

/**
 * Write or update a string or DWORD to the Windows registry
 */
errorcode_t crtupt_registry_value(LPCWSTR key_name, const void *value, DWORD type) {
    HKEY hKey;
    errorcode_t result;

    result = ensure_registry_path();
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }

    //logmsg(LOGGING_NORMAL, "Saving the registry key: %s := %s", key_name, value);
    result = RegCreateKeyEx(HKEY_LOCAL_MACHINE, REG_PATH, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if ( !_IS_SUCCESS(result) ) {
        win_evt_log_id_fmt(JG_EVENT_ID_REGMAINTENANCE, LOGLEVEL_ERROR, L"Failed to create/open registry key: %ld", result);
        return ST_CODE_CREATEUPT_REGKEY;
    }

    result = RegSetValueEx(hKey, key_name, 0, type, (const BYTE*)value, (type == REG_SZ) ? (DWORD)(strlen((const char*)value) + 1) : sizeof(DWORD));
    RegCloseKey(hKey);

    if ( !_IS_SUCCESS(result) ) {
        win_evt_log_id_fmt(JG_EVENT_ID_REGMAINTENANCE, LOGLEVEL_ERROR, L"Failed to set/update registry value: %ld", result);
        return ST_CODE_CREATEUPT_REGKEY;
    }

    return ST_CODE_SUCCESS;
}

/**
 * Read a string value from the registry
 */
errorcode_t read_registry_string(LPCWSTR key_name, LPWSTR buffer, DWORD buffer_size) {
    HKEY hKey;
    errorcode_t result;
    DWORD type = REG_SZ;

    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_PATH, 0, KEY_READ, &hKey);
    if ( !_IS_SUCCESS(result) ) {
        win_evt_log_id_fmt(JG_EVENT_ID_REGMAINTENANCE, LOGLEVEL_ERROR, L"Failed to open registry key: %ld", result);
        return ST_CODE_READ_READ_REGVAL;
    }

    result = RegQueryValueEx(hKey, key_name, NULL, &type, (LPBYTE)buffer, &buffer_size);
    RegCloseKey(hKey);

    if ( !_IS_SUCCESS(result) ) {
        win_evt_log_id_fmt(JG_EVENT_ID_REGMAINTENANCE, LOGLEVEL_ERROR, L"Failed to read registry value: %ld", result);
        return ST_CODE_READ_READ_REGVAL;
    }

    return ST_CODE_SUCCESS;
}

/**
 * Read a DWORD (date) value from the registry
 */
errorcode_t read_registry_dword(LPCWSTR key_name, DWORD *value) {
    HKEY hKey;
    errorcode_t result;
    DWORD type = REG_DWORD;
    DWORD size = sizeof(DWORD);

    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_PATH, 0, KEY_READ, &hKey);
    if ( !_IS_SUCCESS(result) ) {
        win_evt_log_id_fmt(JG_EVENT_ID_REGMAINTENANCE, LOGLEVEL_ERROR, L"Failed to open registry key: %ld", result);
        return ST_CODE_READ_READ_REGVAL;
    }

    result = RegQueryValueEx(hKey, key_name, NULL, &type, (LPBYTE)value, &size);
    RegCloseKey(hKey);

    if ( !_IS_SUCCESS(result) ) {
        win_evt_log_id_fmt(JG_EVENT_ID_REGMAINTENANCE, LOGLEVEL_ERROR, L"Failed to read registry value: %ld\n", result);
        return ST_CODE_READ_READ_REGVAL;
    }

    return ST_CODE_SUCCESS;
}
