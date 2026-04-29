//
// Created by Joao Gonzalez on 4/22/2026.
//

#include "windows/winreg_config.h"
#include "windows/evtlog.h"
#include "windows/ini_config.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <shlobj.h>

#include "windows/logging.h"

static wchar_t _config_ini[BUFFER_SIZE];

errorcode_t ensure_ini_exists() {
    ZeroMemory(_config_ini, sizeof(_config_ini));

    errorcode_t rc = read_registry_string(REG_CONFIG_LOCATION, _config_ini, MAX_STRING_LEN);
    if (!_IS_SUCCESS(rc)) {
        win_evt_log_id_fmt(JG_EVENT_ID_INIDEFINITION, LOGLEVEL_ERROR,
                           L"Failed to read registry value for INI path: %ls", REG_CONFIG_LOCATION);
        return rc;
    }

    // Just open to verify if the file exists
    FILE *wfp = _wfopen(_config_ini, L"r, ccs=UTF-8");
    if (!wfp) {
        win_evt_log_id_fmt(JG_EVENT_ID_INIDEFINITION, LOGLEVEL_ERROR, L"INI file not found, copying default template...");
        return ST_CODE_INIFILE_DOESNT_EXIST;
    }

    fclose(wfp);
    return ST_CODE_SUCCESS;
}

errorcode_t read_ini_value(LPCWSTR section, LPCWSTR key, LPWSTR output, size_t output_size) {
    FILE *file;
    wchar_t line[BUFFER_SIZE];
    errorcode_t result;
    size_t wanted_key_len;
    int in_section = 0;
    int found = 0;

    if (!section || !key || !output || output_size == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    wanted_key_len = wcslen(key);
    output[0] = L'\0';
    line[0] = L'\0';

    result = ensure_ini_exists();
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }

    //logmsg(LOGGING_NORMAL, "Reading INI configuration [SECT(%s)->KEY(%s)] from the file: %s", section, key, config_path);
    errno_t err = _wfopen_s(&file, _config_ini, L"r, ccs=UTF-8");
    if( err != 0 || file == NULL ) {
        win_evt_log_id_fmt(JG_EVENT_ID_INIDEFINITION, LOGLEVEL_ERROR, L"The file %ls could not be opened. Error code: %d", _config_ini, err);
        return ST_CODE_FAILED_TO_READINIVAL;
    }

    while (fgetws(line, _LPWLEN(line), file)) {
        wchar_t *p = line;
        wchar_t *eq = NULL;
        size_t sec_len;
        size_t key_len;

        line[wcscspn(line, LINE_BREAK)] = L'\0';

        while (*p == L' ' || *p == L'\t') p++;
        if (*p == L'\0' || *p == L';' || *p == L'#') continue;

        if (*p == L'[') {
            sec_len = wcslen(section);
            in_section = (
                wcsncmp(p + 1, section, sec_len) == 0 &&
                p[1 + sec_len] == L']'
            );

            continue;
        }

        if (!in_section) continue;

        eq = wcschr(p, L'=');
        if (!eq) continue;

        key_len = (size_t)(eq - p);

        while (key_len > 0 && (p[key_len - 1] == L' ' || p[key_len - 1] == L'\t')) {
            key_len--;
        }

        if (wanted_key_len == key_len && wcsncmp(p, key, key_len) == 0) {
            wchar_t *value = eq + 1;
            wchar_t *end;

            while (*value == L' ' || *value == L'\t') {
                value++;
            }

            end = value + wcslen(value);
            while (end > value && (end[-1] == L' ' || end[-1] == L'\t')) {
                --end;
            }
            *end = L'\0';

            wcsncpy_s(output, output_size, value, _TRUNCATE);
            found = 1;
            break;
        }
    }

    fclose(file);

    if (!found) {
        win_evt_log_id_fmt(JG_EVENT_ID_INIDEFINITION, LOGLEVEL_ERROR, L"The INI configuration key could not be found: SECTION[%ls] ; KEY[%ls]", section, key);
        return ST_CODE_INI_KEY_NOT_FOUND;
    }

    logmsg(LOGGING_NORMAL, L"+ Value being retrieved by the INI configuration(%ls, %ls): [%ls]", section, key, output);

    return ST_CODE_SUCCESS;
}