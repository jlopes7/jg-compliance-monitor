//
// Created by Joao Gonzalez on 4/22/2026.
//

#include "utils.h"
#include "windows/winreg_config.h"
#include "windows/evtlog.h"
#include "windows/logging.h"

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

static BOOL reg_path_matches_install_location(LPCWSTR install_path, LPCWSTR reg_install_location) {
    if (!install_path || !reg_install_location) {
        return FALSE;
    }

    if (install_path[0] == L'\0' || reg_install_location[0] == L'\0') {
        return FALSE;
    }

    /*
     * Match either way:
     * - java.exe path contains InstallLocation
     * - InstallLocation contains detected installation root
     */
    return wcsstr(install_path, reg_install_location) != NULL ||
           wcsstr(reg_install_location, install_path) != NULL;
}

static LPWSTR reg_strdup_value(HKEY hKey, LPCWSTR value_name) {
    DWORD type = 0;
    DWORD cb = 0;
    LPWSTR out = NULL;
    LONG rc;

    rc = RegQueryValueExW(hKey, value_name, NULL, &type, NULL, &cb);
    if (rc != ERROR_SUCCESS || cb == 0) {
        return NULL;
    }

    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return NULL;
    }

    out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb + sizeof(wchar_t));
    if (!out) {
        return NULL;
    }

    rc = RegQueryValueExW(hKey, value_name, NULL, &type, (LPBYTE)out, &cb);
    if (rc != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, out);
        return NULL;
    }

    return out;
}

static DWORD read_registry_dword_ex(HKEY hKey, LPCWSTR value_name) {
    DWORD type = REG_DWORD;
    DWORD value = 0;
    DWORD cb = sizeof(DWORD);

    if (RegQueryValueExW(hKey, value_name, NULL, &type, (LPBYTE)&value, &cb) != ERROR_SUCCESS) {
        return 0;
    }

    if (type != REG_DWORD) {
        return 0;
    }

    return value;
}

errorcode_t populate_product_from_uninstall_key(HKEY hKey, PRODUCT_INFO product) {
    DWORD major;
    DWORD minor;

    if (!hKey || !product) {
        return ST_CODE_INVALID_PARAM;
    }

    PTR(product).contact          = reg_strdup_value(hKey, REG_UNINSTALL_KEY_CONTACT);
    PTR(product).display_name     = reg_strdup_value(hKey, REG_UNINSTALL_KEY_DISPLAYNAME);
    PTR(product).display_version  = reg_strdup_value(hKey, REG_UNINSTALL_KEY_DISPLAYVERSION);
    PTR(product).tel_help         = reg_strdup_value(hKey, REG_UNINSTALL_KEY_HELPTELEPHONE);
    PTR(product).install_date     = reg_strdup_value(hKey, REG_UNINSTALL_KEY_INSTALLDATE);
    PTR(product).publisher        = reg_strdup_value(hKey, REG_UNINSTALL_KEY_PUBLISHER);
    PTR(product).uninstall_instr  = reg_strdup_value(hKey, REG_UNINSTALL_KEY_UNINSTALLSTRING);
    PTR(product).url              = reg_strdup_value(hKey, REG_UNINSTALL_KEY_URLINFOABOUT);

    major = read_registry_dword_ex(hKey, REG_UNINSTALL_KEY_MAJVER);
    minor = read_registry_dword_ex(hKey, REG_UNINSTALL_KEY_MINVER);

    PTR(product).major_version = (uint8_t)major;
    PTR(product).minor_version = (uint8_t)minor;

    return ST_CODE_SUCCESS;
}

static errorcode_t search_uninstall_view(
    LPCWSTR install_path,
    PRODUCT_INFO product,
    REGSAM view_flag,
    HANDLE stop_event
) {
    HKEY hUninstall;
    DWORD index = 0;
    WCHAR subkey_name[MAX_PATH];
    DWORD subkey_cch;
    LONG rc;

    rc = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        REG_UNINSTALL_PATH,
        0,
        KEY_READ | view_flag,
        &hUninstall
    );

    if (rc != ERROR_SUCCESS) {
        return ST_CODE_READ_READ_REGVAL;
    }

    for (;;) {
        HKEY hProduct;
        LPWSTR install_location;

        if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) {
            RegCloseKey(hUninstall);
            return ST_CODE_SUCCESS;
        }

        subkey_cch = _LPWLEN(subkey_name);
        ZeroMemory(subkey_name, sizeof(subkey_name));

        rc = RegEnumKeyExW(
            hUninstall,
            index++,
            subkey_name,
            &subkey_cch,
            NULL,
            NULL,
            NULL,
            NULL
        );

        if (rc == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (rc != ERROR_SUCCESS) {
            continue;
        }

        rc = RegOpenKeyExW(
            hUninstall,
            subkey_name,
            0,
            KEY_READ | view_flag,
            &hProduct
        );

        if (rc != ERROR_SUCCESS) {
            continue;
        }

        install_location = reg_strdup_value(hProduct, REG_UNINSTALL_KEY_INSTALLOCATION);

        if (install_location && reg_path_matches_install_location(install_path, install_location)) {
            HeapFree(GetProcessHeap(), 0, install_location);
            populate_product_from_uninstall_key(hProduct, product);
            RegCloseKey(hProduct);
            RegCloseKey(hUninstall);
            return ST_CODE_SUCCESS;
        }

        if (install_location) {
            HeapFree(GetProcessHeap(), 0, install_location);
        }

        RegCloseKey(hProduct);
    }

    RegCloseKey(hUninstall);
    return ST_CODE_REGKEY_NOT_FOUND;
}

errorcode_t read_uninstall_product_by_install_location(LPCWSTR install_path, PRODUCT_INFO product, HANDLE stop_event) {
    errorcode_t rc;

    if (!install_path || !product) {
        return ST_CODE_INVALID_PARAM;
    }

    //ZeroMemory(product, sizeof(product_details_t));

    rc = search_uninstall_view(install_path, product, KEY_WOW64_64KEY, stop_event);
    if ( _IS_SUCCESS(rc) ) {
        return ST_CODE_SUCCESS;
    }

    // If it's any other error, return the error
    if (rc != ST_CODE_REGKEY_NOT_FOUND) {
        logmsg(LOGGING_WARN, L"[REGVAL] Failed to find a product related to the installation path at the Windows registry: %ls", install_path);
        return rc;
    }
    else {
        logmsg(LOGGING_WARN, L"[REGVAL] No product related to the installation path in the 64-bit registry entry: %ls", install_path);
    }

    rc = search_uninstall_view(install_path, product, KEY_WOW64_32KEY, stop_event);
    if (_IS_SUCCESS(rc)) {
        return ST_CODE_SUCCESS;
    }

    return rc;
}


