//
// Created by Joao Gonzalez on 4/28/2026.
//

#include "utils.h"
#include "windows/config.h"
#include "windows/logging.h"
#include "windows/winreg_config.h"

static errorcode_t parse_model_jvm_product(CONFIG config, LPCWSTR jvmPath, LPWSTR productName, size_t productNameCch) {
    size_t local_counter = 0;
    BOOL end_matched = FALSE;

    if ( !config || !jvmPath || !productName || productNameCch == 0 ) {
        return ST_CODE_INVALID_PARAM;
    }

    productName[0] = L'\0';

    for (; !end_matched && local_counter < PTR(config).model_config->model->entry_list_size; local_counter++) {
        size_t internal_counter = 0;
        size_t entrylst_size = PTR(config).model_config->model->entry_list[local_counter]->pattern_array_size;
        PATTERN_ENTRY entry = config->model_config->model->entry_list[local_counter];

        if (!entry || !PTR(entry).product_name || !PTR(entry).pattern_array) {
            continue;
        }

        for ( ; !end_matched && internal_counter < entrylst_size; internal_counter++) {
            if (!entry->pattern_array[internal_counter]) {
                continue;
            }

            regex_match(jvmPath, PTR(entry).pattern_array[internal_counter], &end_matched);

            if ( end_matched ) {
                wcsncpy_s(productName, productNameCch, entry->product_name, _TRUNCATE);
                logmsg(LOGGING_NORMAL, L"[MODEL PARSER] The jvm instance (%ls) matched the product: %ls", jvmPath, productName);
            }
        }
    }

    if ( productName[0] == L'\0' ) {
        wcsncpy_s(productName, productNameCch, L"Unknown Product", _TRUNCATE);
    }

    logmsg(LOGGING_NORMAL, L"[MODEL PARSER] Product associated with the JVM instance(%ls): %ls", jvmPath, productName);

    return ST_CODE_SUCCESS;
}

static BOOL free_jvm_details(JVM_DETAILS jvm) {
    if (!jvm) return TRUE;

    free((void *)PTR(jvm).installation_path);
    free((void *)PTR(jvm).publisher);
    free((void *)PTR(jvm).license_type);
    free((void *)PTR(jvm).fullversion_jdk);
    free((void *)PTR(jvm).fullversion_win);
    free((void *)PTR(jvm).env_path_installpath);
    free((void *)PTR(jvm).env_path_version);
    free((void *)PTR(jvm).env_javahome_installpath);
    free((void *)PTR(jvm).env_javahome_version);
    free((void *)PTR(jvm).product_name);

    if ( PTR(jvm).product_info ) {
        HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).product_info->contact);
        HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).product_info->display_name);
        HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).product_info->display_version);
        HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).product_info->install_date);
        HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).product_info->publisher);
        HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).product_info->tel_help);
        HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).product_info->uninstall_instr);
        HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).product_info->url);

        HeapFree(GetProcessHeap(), 0, PTR(jvm).product_info);
        PTR(jvm).product_info = NULL;
    }

    return HeapFree(GetProcessHeap(), 0, jvm);
}

errorcode_t clean_jvm_data(SYSTEM_DETAILS *sysdetails) {
    DWORD counter = 0;
    if (!PTR(sysdetails) || !PTR(*sysdetails).jvm ) {
        return ST_CODE_INVALID_PARAM;
    }

    for ( ; counter < PTR(*sysdetails).jvm_count ; counter++ ) {
        LPCWSTR jvminstance = PTR(*sysdetails).jvm[counter]->installation_path;
        if ( !free_jvm_details(PTR(*sysdetails).jvm[counter]) ) {
            logmsg(LOGGING_ERROR, L"[MODEL PARSER] Could not release the JVM instance: %ls - This could represent a leakage in the process", jvminstance);
        }
    }

    HeapFree(GetProcessHeap(), 0, PTR(*sysdetails).jvm);
    PTR(*sysdetails).jvm = NULL;
    PTR(*sysdetails).jvm_count = 0;
    PTR(*sysdetails).jvm_capacity = 0;

    logmsg(LOGGING_NORMAL, L"[MODEL PARSER] Cleaned the JVM state for the next run.");

    return ST_CODE_SUCCESS;
}

errorcode_t parse_model_system(SYSTEM_DETAILS *sysdetails) {
    ULONGLONG avail_vm;
    WCHAR os_info[128];
    WCHAR os_version[64];
    WCHAR env_path[MID_BUFFER_SIZE];
    WCHAR env_javahome[MID_BUFFER_SIZE];
    DWORD vcores;
    DWORD physical_cores;

    errorcode_t result;

    ZeroMemory(env_path, sizeof(env_path));
    ZeroMemory(env_javahome, sizeof(env_javahome));

    *sysdetails = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(system_details_t));
    if (!*sysdetails) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    result = get_total_available_vm(&avail_vm);
    if ( !_IS_SUCCESS(result) ) {
        logmsg(LOGGING_WARN, L"-- parse_model_system: get_total_available_vm failed. RC: %d", result);
    }
    else {
        PTR(*sysdetails).vm_size = avail_vm;
    }

    result = get_os_version(os_version, _LPWLEN(os_version));
    if ( !_IS_SUCCESS(result) ) {
        logmsg(LOGGING_WARN, L"-- parse_model_system: get_os_version failed. RC: %d", result);
    }
    else {
        PTR(*sysdetails).version = _wstrdup(os_version);
    }

    result = get_os_name_version(os_info, _LPWLEN(os_info));
    if ( !_IS_SUCCESS(result) ) {
        logmsg(LOGGING_WARN, L"-- parse_model_system: get_os_name_version failed. RC: %d", result);
    }
    else {
        PTR(*sysdetails).os = _wstrdup(os_info);
    }

    result = get_logical_core_count(&vcores);
    if ( !_IS_SUCCESS(result) ) {
        logmsg(LOGGING_WARN, L"-- parse_model_system: get_logical_core_count failed. RC: %d", result);
    }
    else {
        PTR(*sysdetails).num_vcores = vcores;
    }

    result = get_physical_core_count(&physical_cores);
    if ( !_IS_SUCCESS(result) ) {
        logmsg(LOGGING_WARN, L"-- parse_model_system: get_physical_core_count failed. RC: %d", result);
    }
    else {
        PTR(*sysdetails).num_physical_cores = physical_cores;
    }

    // Process the environment variable paths
    result = get_env_var_val(ENV_VAR_PATH, env_path);
    result |= get_env_var_val(ENV_VAR_JAVAHOME, env_javahome);
    if ( !_IS_SUCCESS(result) ) {
        logmsg(LOGGING_WARN, L"Failed to retrieve either environment variables PATH or(and) JAVA_HOME. Maybe the JAVA_HOME variable is empty? Code: %d", result);
    }

    PTR(*sysdetails).env_javahome = _wstrdup(env_javahome);
    PTR(*sysdetails).env_path = _wstrdup(env_path);

    // Buffer counter and capacity
    PTR(*sysdetails).local_user = L"NOT SUPPORTED AT CUR VERSION";
    PTR(*sysdetails).jvm_capacity = LOW_BUFFER_SIZE;
    PTR(*sysdetails).jvm_count = 0;

    // Locker initialization
    InitializeCriticalSection(&PTR(*sysdetails).jvm_lock);

    return ST_CODE_SUCCESS;
}

errorcode_t add_jvm_instance(SYSTEM_DETAILS *sysdetails, CONFIG config, LPCWSTR jvmPath) {
    wchar_t product_loc[MAX_PATH];
    JVM_DETAILS *new_list;
    DWORD new_capacity;
    JVM_DETAILS item;
    PRODUCT_INFO product_info = NULL;

    errorcode_t result;

    if (!sysdetails || !PTR(sysdetails) || !jvmPath) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(product_loc, sizeof(product_loc));

    if (!PTR(*sysdetails).jvm) {
        PTR(*sysdetails).jvm = HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(JVM_DETAILS) * PTR(*sysdetails).jvm_capacity
        );

        if (!PTR(*sysdetails).jvm) {
            return ST_CODE_MEMORY_ALLOCATION_FAILED;
        }
    }

    if (PTR(*sysdetails).jvm_count >= PTR(*sysdetails).jvm_capacity) {
        new_capacity = PTR(*sysdetails).jvm_capacity == 0
                            ? LOW_BUFFER_SIZE
                            : PTR(*sysdetails).jvm_capacity * 2;

        new_list = HeapReAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            PTR(*sysdetails).jvm,
            sizeof(JVM_DETAILS) * new_capacity
        );

        if (!new_list) {
            return ST_CODE_MEMORY_ALLOCATION_FAILED;
        }

        PTR(*sysdetails).jvm = new_list;
        PTR(*sysdetails).jvm_capacity = new_capacity;
    }

    item = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(jvm_details_t));
    if (!item) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }
    PTR(*sysdetails).jvm[PTR(*sysdetails).jvm_count] = item;

    if (!PTR(*sysdetails).jvm[PTR(*sysdetails).jvm_count]) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    /*
     * LOAD THE PRODUCT DETAILS
     * -------------------------
     */
    result = parse_product_info(jvmPath, &product_info, PTR(*sysdetails).stop_event);
    if ( IS_REG_NOTFOUND(result) ) {
        result = parse_model_jvm_product(config, jvmPath, product_loc, _LPWLEN(product_loc));
        if ( !_IS_SUCCESS(result) ) {
            logmsg(LOGGING_WARN, L"-- add_jvm_instance: Failed to parse product. RC: %d", result);
        }
        PTR(*sysdetails).jvm[PTR(*sysdetails).jvm_count]->product_name = _wcsdup(product_loc);

        // Product info manual configuration
        PTR(product_info).display_name    = _wcsdup(product_loc);
        PTR(product_info).contact         = UNDEFINED_ATTRIBUTE;
        PTR(product_info).display_version = UNDEFINED_ATTRIBUTE;
        PTR(product_info).install_date    = UNDEFINED_ATTRIBUTE;
        PTR(product_info).publisher       = UNDEFINED_ATTRIBUTE;
        PTR(product_info).tel_help        = UNDEFINED_ATTRIBUTE;
        PTR(product_info).uninstall_instr = UNDEFINED_ATTRIBUTE;
        PTR(product_info).url             = UNDEFINED_ATTRIBUTE;
    }
    else {
        PTR(*sysdetails).jvm[PTR(*sysdetails).jvm_count]->product_name = _wcsdup(PTR(product_info).display_name);
    }

    // TODO: Continue processing the JVM

    // PLACE THE COUNTER TO THE NEXT ELEMENT !
    PTR(*sysdetails).jvm_count++;

    return ST_CODE_SUCCESS;
}

errorcode_t jvm_parse_model(SYSTEM_DETAILS sysdetails, LPVOID lpData, HANDLE stop_event) {
    CONFIG config;
    LPCWSTR jvmPath;
    errorcode_t result;

    if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) {
        return ST_CODE_SUCCESS;
    }

    if (!sysdetails || !lpData) {
        logmsg(LOGGING_ERROR, L"-- parse_model: NULL arguments");
        return ST_CODE_INVALID_PARAM;
    }

    jvmPath = (LPCWSTR)lpData;
    logmsg(LOGGING_NORMAL, L"[MODEL PARSER]: About to parse the JVM model: %ls", jvmPath);

    result = get_config(&config);
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }

    // Add the new JVM
    result = add_jvm_instance(&sysdetails, config, jvmPath);
    if ( !_IS_SUCCESS(result) ) {
        logmsg(LOGGING_WARN, L"-- add_jvm_instance: Failed to append JVM instance: %ls. RC: %d", jvmPath, result);
    }

    return ST_CODE_SUCCESS;
}

errorcode_t parse_product_info(LPCWSTR install_path, PRODUCT_INFO *product, HANDLE stop_event) {
    errorcode_t rc;

    if (!install_path || !product) {
        return ST_CODE_INVALID_PARAM;
    }

    // Allocates the product structure
    PTR(product) = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(product_details_t));

    rc = read_uninstall_product_by_install_location(install_path, PTR(product), stop_event);
    if (!_IS_SUCCESS(rc)) {
        logmsg(LOGGING_WARN,
               L"[MODEL PARSER] No uninstall registry product matched install path: %ls",
               install_path);
        return rc;
    }

    logmsg(LOGGING_NORMAL,
           L"[MODEL PARSER] Registry product matched. DisplayName=%ls Version=%ls Publisher=%ls",
           PTR(product)->display_name ?     PTR(product)->display_name : L"",
           PTR(product)->display_version ?  PTR(product)->display_version : L"",
           PTR(product)->publisher ?        PTR(product)->publisher : L"");

    return ST_CODE_SUCCESS;
}
