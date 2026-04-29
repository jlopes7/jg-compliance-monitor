#include "windows/classif_json.h"

#include "windows/evtlog.h"
#include "windows/logging.h"
#include "windows/winreg_config.h"

errorcode_t classif_json_open(cJSON **root) {
    FILE *fp;
    errno_t err;
    errorcode_t rc;
    long size;
    wchar_t json_path[MAX_PATH];
    char *buffer;
    size_t read_count;

    if (!root) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(json_path, MAX_PATH);

    *root = NULL;

    rc = read_registry_string(REG_PATTERN_CLASSIF_FILE, json_path, MAX_PATH);
    if ( !_IS_SUCCESS(rc) ) {
        return ST_CODE_READ_READ_REGVAL;
    }

    logmsg(LOGGING_NORMAL, L"[PATTERN CLASSIF] Open JSON classification file: %ls", json_path);
    err = _wfopen_s(&fp, json_path, L"rb");
    if (err != 0 || !fp) {
        return ST_CODE_IO_OPEN_FAILED;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return ST_CODE_IO_STAT_FAILED;
    }

    size = ftell(fp);
    if (size <= 0) {
        fclose(fp);
        return ST_CODE_FAILED_OPERATION;
    }

    rewind(fp);

    buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)size + 1);
    if (!buffer) {
        fclose(fp);
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    read_count = fread(buffer, 1, (size_t)size, fp);
    fclose(fp);

    if (read_count != (size_t)size) {
        HeapFree(GetProcessHeap(), 0, buffer);
        return ST_CODE_FAILED_OPERATION;
    }

    *root = cJSON_Parse(buffer);
    HeapFree(GetProcessHeap(), 0, buffer);

    if (!PTR(root)) {
        win_evt_log(L"[CLASSIF_JSON] Failed to parse JSON.", LOGLEVEL_ERROR);
        return ST_CODE_IO_READ_FAILED;
    }

    return ST_CODE_SUCCESS;
}

errorcode_t classif_json_parse(cJSON *root, PATTERN_MODEL *model) {
    cJSON *entries;
    int entry_count;
    int i;

    if (!root || !model) {
        return ST_CODE_INVALID_PARAM;
    }

    logmsg(LOGGING_NORMAL, L"[PATTERN CLASSIF] Parsing and reading the pattern classification json configuration");

    *model = NULL;

    entries = cJSON_GetObjectItemCaseSensitive(root, EL_JSON_ENTRIES);
    if (!cJSON_IsArray(entries)) {
        return ST_CODE_FAILED_PARSE_JSON;
    }

    entry_count = cJSON_GetArraySize(entries);

    *model = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(pattern_model_t));
    if (!*model) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    PTR(*model).entry_list = HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(PATTERN_ENTRY) * ((SIZE_T)entry_count + 1)
    );

    if (!PTR(*model).entry_list) {
        HeapFree(GetProcessHeap(), 0, *model);
        *model = NULL;
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    PTR(*model).entry_list_size = entry_count;

    logmsg(LOGGING_NORMAL, L"[PATTERN CLASSIF] Number of classifications found: %d product entries", PTR(*model).entry_list_size);

    for (i = 0; i < entry_count; i++) {
        cJSON *entry_json;
        cJSON *name_json;
        cJSON *regexs_json;
        int regex_count;
        int j;
        PATTERN_ENTRY entry;

        entry_json = cJSON_GetArrayItem(entries, i);
        if (!cJSON_IsObject(entry_json)) {
            continue;
        }

        name_json = cJSON_GetObjectItemCaseSensitive(entry_json, EL_JSON_NAME);
        regexs_json = cJSON_GetObjectItemCaseSensitive(entry_json, EL_JSON_REGEXS);

        /*
         * If the JSON has one entry using "Regexs" instead of "RegExs".
         * Accept both spellings.
         */
        if (!regexs_json) {
            regexs_json = cJSON_GetObjectItemCaseSensitive(entry_json, "Regexs");
        }

        if (!cJSON_IsString(name_json) || !cJSON_IsArray(regexs_json)) {
            continue;
        }

        regex_count = cJSON_GetArraySize(regexs_json);

        entry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(pattern_entry_t));
        if (!entry) {
            classif_pattern_model_free(*model);
            *model = NULL;
            return ST_CODE_MEMORY_ALLOCATION_FAILED;
        }

        PTR(entry).product_name = utf8_to_wide_dup(PTR(name_json).valuestring);
        PTR(entry).pattern_array_size = regex_count;
        if (!PTR(entry).product_name) {
            HeapFree(GetProcessHeap(), 0, entry);
            classif_pattern_model_free(*model);
            *model = NULL;
            return ST_CODE_MEMORY_ALLOCATION_FAILED;
        }

        PTR(entry).pattern_array = HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(LPCWSTR) * ((SIZE_T)regex_count + 1)
        );

        if (!PTR(entry).pattern_array) {
            HeapFree(GetProcessHeap(), 0, (LPVOID)PTR(entry).product_name);
            HeapFree(GetProcessHeap(), 0, entry);
            classif_pattern_model_free(*model);
            *model = NULL;
            return ST_CODE_MEMORY_ALLOCATION_FAILED;
        }

        for (j = 0; j < regex_count; j++) {
            cJSON *regex_json = cJSON_GetArrayItem(regexs_json, j);

            if (cJSON_IsString(regex_json)) {
                PTR(entry).pattern_array[j] = utf8_to_wide_dup(PTR(regex_json).valuestring);

                if (!PTR(entry).pattern_array[j]) {
                    classif_pattern_model_free(*model);
                    *model = NULL;
                    return ST_CODE_MEMORY_ALLOCATION_FAILED;
                }
            }
        }

        PTR(*model).entry_list[i] = entry;
    }

    return ST_CODE_SUCCESS;
}

errorcode_t classif_json_close(cJSON *root) {
    if (root) {
        cJSON_Delete(root);
    }

    return ST_CODE_SUCCESS;
}

errorcode_t classif_pattern_model_free(PATTERN_MODEL model) {
    size_t i;

    if (!model) {
        return ST_CODE_SUCCESS;
    }

    if (model->entry_list) {
        for (i = 0; model->entry_list[i] != NULL; i++) {
            PATTERN_ENTRY entry = model->entry_list[i];

            if (entry) {
                size_t j;

                if (entry->pattern_array) {
                    for (j = 0; entry->pattern_array[j] != NULL; j++) {
                        HeapFree(GetProcessHeap(), 0, (LPVOID)entry->pattern_array[j]);
                    }

                    HeapFree(GetProcessHeap(), 0, entry->pattern_array);
                }

                HeapFree(GetProcessHeap(), 0, (LPVOID)entry->product_name);
                HeapFree(GetProcessHeap(), 0, entry);
            }
        }

        HeapFree(GetProcessHeap(), 0, model->entry_list);
    }

    HeapFree(GetProcessHeap(), 0, model);

    return ST_CODE_SUCCESS;
}