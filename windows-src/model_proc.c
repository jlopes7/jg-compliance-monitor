//
// Created by Joao Gonzalez on 4/28/2026.
//

#include "utils.h"
#include "windows/config.h"
#include "windows/logging.h"
#include "windows/pe_file_prop.h"
#include "windows/winreg_config.h"

static errorcode_t parse_jvm_license_type(JVM_DETAILS jvm) {
    errorcode_t result;
    DWORD major_version, minor_version;
    wchar_t jvm_base_path[MAX_PATH],
            jvm_lic_path[MAX_PATH],
            jvm_jdk_path[MAX_PATH];
    BOOL license_already_parsed = FALSE;

    if (!jvm) {
        return ST_CODE_INVALID_PARAM;
    }

    major_version = PTR(jvm).major_version;
    minor_version = PTR(jvm).minor_version;
    if (minor_version == 0 || major_version == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(jvm_base_path, sizeof(jvm_base_path));
    ZeroMemory(jvm_lic_path, sizeof(jvm_lic_path));
    ZeroMemory(jvm_jdk_path, sizeof(jvm_jdk_path));

    // Try to resolve the license from the license file
    result = fs_retrieve_directory(PTR(jvm).installation_path, jvm_base_path, 2);
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }
    if ( fs_join_path(jvm_base_path, L"LICENSE", jvm_jdk_path, MAX_PATH) ) {
        if ( fs_resource_exists(jvm_jdk_path, LEAF) ) {
            fs_join_path(jvm_base_path, L"LICENSE", jvm_lic_path, MAX_PATH);
        }
        else {
            fs_join_path(jvm_base_path, L"legal\\java.base\\LICENSE", jvm_lic_path, MAX_PATH);
        }

        if ( fs_resource_exists(jvm_lic_path, LEAF) ) {
            if ( fs_compare_line_in_file(jvm_lic_path, GPLV2_FIRST_LINE_DEF, 1) ) {
                license_already_parsed = TRUE;

                PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_OJDK);
            }
        }
    }

    // We will have to evaluate the major and minor versions
    if ( !license_already_parsed ) {
        if ( _wcsicmp(PTR(jvm).publisher, L"Oracle Corporation") == 0 ) {
            if ( major_version <= 7 ) {
                switch (major_version) {
                    case 7:
                        if ( minor_version <= 80 ) PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_BCLA);
                        else PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_BCLAWEXTSUP);
                        break;

                    case 6:
                        if ( minor_version <= 45 ) PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_BCLA);
                        else PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_BCLAWEXTSUP);
                        break;

                    default:
                        PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_BCLA);
                }
            }
            else if ( major_version == 8 ) {
                if ( minor_version <= 202 ) PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_BCLA);
                else PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_OTNLA);
            }
            else if ( major_version == 9 || major_version == 10 ) {
                PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_BCLA);
            }
            else if ( major_version < 17 ) { // 11 ~ 16
                PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_OTNLA);
            }
            else {
                if ( major_version == 17 ) {
                    if ( minor_version <= 12 ) PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_NFTC);
                    else PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_OTNLA);
                }
                else {
                    PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_NFTC);
                }
            }
        }
        else if ( _wcsicmp(PTR(jvm).publisher, UNDEFINED_ATTRIBUTE) == 0 ) {
            PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_UNKNOWN);
        }
        else {
            // GPL OJDK
            PTR(jvm).license_type = heap_wcsdup(LIC_TYPE_OJDK);
        }
    }

    return ST_CODE_SUCCESS;
}

static errorcode_t parse_jvm_pe_rel_model(LPCWSTR jvmPath, JVM_DETAILS jvm) {
    errorcode_t result;
    PE_FILE pe_details = NULL;
    FILE_PROP_READER prop_reader = NULL;

    uint8_t back_counter = 2;
    BOOL    found_release_file = FALSE;

    DWORD   major_version = 0,
            minor_version = 0;
    wchar_t full_version[SMALL_BUFFER];
    wchar_t publisher_comp[SMALL_BUFFER],
            legal_copyright[SMALL_BUFFER];
    wchar_t release_file_path[LOW_BUFFER_SIZE],
            release_file_dir[LOW_BUFFER_SIZE];

    if (!jvmPath || !jvm) {
        return ST_CODE_INVALID_PARAM;
    }

    ZeroMemory(publisher_comp, sizeof(publisher_comp));
    ZeroMemory(legal_copyright, sizeof(legal_copyright));

    result = pe_open(jvmPath, &pe_details);
    if ( !_IS_SUCCESS(result) ) {
        logmsg(LOGGING_WARN, L"[PE FILE DETAILS] Failed to retrieve the PE information for the JVM file given as parameter: %ls", jvmPath);
        return result;
    }

    // FULL VERSION, MAJOR AND MINOR VERSIONS
    result = pe_get_prop_dword(pe_details, PE_PROP_MAJORVERSION, &major_version);
    if ( _IS_SUCCESS(result) ) {
        PTR(jvm).major_version = major_version;
    }
    result = pe_get_prop_dword(pe_details, PE_PROP_MINORVERSION, &minor_version);
    if ( _IS_SUCCESS(result) ) {
        if ( minor_version == 0 ) {
            pe_get_prop_dword(pe_details, PE_PROP_BUILDVERSION, &minor_version);
        }

        // Fix the trailing "0" after the end of windows version (anything higher than 700 would have a "0" attached to the minor)
        if ( minor_version >= 700 && minor_version % 10 == 0 ) {
            minor_version /= 10;
        }
        PTR(jvm).minor_version = minor_version;
    }

    result = pe_get_prop(pe_details, PE_PROP_COMPANY_NAME, publisher_comp, SMALL_BUFFER);
    if ( _IS_SUCCESS(result) ) {
        PTR(jvm).publisher = heap_wcsdup(publisher_comp);
    }
    else {
        logmsg(LOGGING_WARN, L"[PE FILE DETAILS] Could not find or retrieve the value associated with the PE property: %ls. Error code: %d", PE_PROP_COMPANY_NAME, result);
        PTR(jvm).publisher = heap_wcsdup(UNDEFINED_ATTRIBUTE);
    }

    result = pe_get_prop(pe_details, PE_PROP_LEGAL_COPYRIGHT, legal_copyright, SMALL_BUFFER);
    if ( _IS_SUCCESS(result) ) {
        PTR(jvm).legal_copyright = heap_wcsdup(legal_copyright);
    }
    else {
        logmsg(LOGGING_WARN, L"[PE FILE DETAILS] Could not find or retrieve the value associated with the PE property: %ls. Error code: %d", PE_PROP_LEGAL_COPYRIGHT, result);
        PTR(jvm).legal_copyright = heap_wcsdup(UNDEFINED_ATTRIBUTE);
    }

    result = pe_get_prop(pe_details, PE_PROP_FILE_VERSION, full_version, SMALL_BUFFER);
    if ( _IS_SUCCESS(result) ) {
        PTR(jvm).fullversion_win = heap_wcsdup(full_version);
    }
    else {
        logmsg(LOGGING_WARN, L"[PE FILE DETAILS] Could not find or retrieve the value associated with the PE property: %ls. Error code: %d", PE_PROP_FILE_VERSION, result);
        PTR(jvm).fullversion_win = heap_wcsdup(UNDEFINED_ATTRIBUTE);
    }

    // Close the PE file format handle
    pe_close(pe_details);


    // Work the properties from the RELEASE file
    for ( ; !found_release_file && back_counter < 4 /*Go up only 2 levels*/; back_counter++ ) {
        ZeroMemory(release_file_path, sizeof(release_file_path));
        ZeroMemory(release_file_dir, sizeof(release_file_dir));

        result = fs_retrieve_directory(jvmPath, release_file_dir, back_counter);
        if ( _IS_SUCCESS(result) ) {
            if ( fs_join_path(release_file_dir, L"RELEASE", release_file_path, LOW_BUFFER_SIZE) ) {
                found_release_file = fs_resource_exists(release_file_path, LEAF);
            }
        }
    }
    // Found the release file, let's start the read of the properties
    if ( found_release_file ) {
        result = init_file_prop_read(release_file_path, &prop_reader);
        if ( _IS_SUCCESS(result) ) {
            wchar_t java_version[LOW_BUFFER_SIZE],
                    java_runtime_version[LOW_BUFFER_SIZE],
                    build_type[LOW_BUFFER_SIZE];

            ZeroMemory(java_version, sizeof(java_version));
            ZeroMemory(java_runtime_version, sizeof(java_runtime_version));
            ZeroMemory(build_type, sizeof(build_type));

            result = get_file_prop_val(JVM_RELEASE_PROP_JAVA_VERSION, java_version, LOW_BUFFER_SIZE, prop_reader);
            if ( _IS_SUCCESS(result) ) {
                PTR(jvm).fullversion_jdk = heap_wcsdup(java_version);
            }
            else {
                logmsg(LOGGING_WARN, L"[JVM PROPS] Could not find or retrieve the value associated with the property: %ls. Error code: %d", JVM_RELEASE_PROP_JAVA_VERSION, result);
                PTR(jvm).fullversion_jdk = heap_wcsdup(UNDEFINED_ATTRIBUTE);
            }

            result = get_file_prop_val(JVM_RELEASE_PROP_JAVA_RUNTIME_VERSION, java_runtime_version, LOW_BUFFER_SIZE, prop_reader);
            if ( _IS_SUCCESS(result) ) {
                PTR(jvm).runtime_version = heap_wcsdup(java_runtime_version);
            }
            else {
                logmsg(LOGGING_WARN, L"[JVM PROPS] Could not find or retrieve the value associated with the property: %ls. Error code: %d", JVM_RELEASE_PROP_JAVA_RUNTIME_VERSION, result);
                PTR(jvm).runtime_version = heap_wcsdup(UNDEFINED_ATTRIBUTE);
            }

            result = get_file_prop_val(JVM_RELEASE_PROP_BUILD_TYPE, build_type, LOW_BUFFER_SIZE, prop_reader);
            if ( _IS_SUCCESS(result) ) {
                PTR(jvm).build_type = heap_wcsdup(build_type);
            }
            else {
                logmsg(LOGGING_WARN, L"[JVM PROPS] Could not find or retrieve the value associated with the property: %ls. Error code: %d", JVM_RELEASE_PROP_BUILD_TYPE, result);
                PTR(jvm).build_type = heap_wcsdup(UNDEFINED_ATTRIBUTE);
            }

            end_file_prop_read(prop_reader);
        }
    }
    else {
        logmsg(LOGGING_WARN, L"[JVM PROPS] The JVM release file could not be found. That means a few properties will not be filled for the JVM. The data maybe incomplete: (full_version_jdk, runtime_version and build_type)");
        PTR(jvm).fullversion_jdk = heap_wcsdup(UNDEFINED_ATTRIBUTE);
        PTR(jvm).runtime_version = heap_wcsdup(UNDEFINED_ATTRIBUTE);
        PTR(jvm).build_type = heap_wcsdup(UNDEFINED_ATTRIBUTE);
    }

    return ST_CODE_SUCCESS;
}

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

    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).env_path_installpath);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).env_path_version);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).env_javahome_installpath);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).env_javahome_version);

    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).installation_path);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).license_type);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).publisher);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).product_name);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).fullversion_jdk);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).fullversion_win);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).runtime_version);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).build_type);
    HeapFree(GetProcessHeap(), 0, (void *)PTR(jvm).legal_copyright);

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
    if (!sysdetails || !*sysdetails || !PTR(*sysdetails).jvm) {
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

    PTR(*sysdetails).env_javahome = heap_wcsdup(env_javahome);
    PTR(*sysdetails).env_path = heap_wcsdup(env_path);

    // Buffer counter and capacity
    PTR(*sysdetails).local_user = heap_wcsdup(L"NOT SUPPORTED AT CUR VERSION");
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

    // Copy the JVM installation path for the JVM definition
    PTR(item).installation_path = heap_wcsdup(jvmPath);

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
        PTR(item).product_name = heap_wcsdup(product_loc);

        if ( product_info == NULL ) {
            product_info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(product_details_t));
            if (!product_info) {
                free_jvm_details(item);
                return ST_CODE_MEMORY_ALLOCATION_FAILED;
            }
        }

        // Product info manual configuration
        PTR(product_info).display_name    = heap_wcsdup(product_loc);
        PTR(product_info).contact         = heap_wcsdup(UNDEFINED_ATTRIBUTE);
        PTR(product_info).display_version = heap_wcsdup(UNDEFINED_ATTRIBUTE);
        PTR(product_info).install_date    = heap_wcsdup(UNDEFINED_ATTRIBUTE);
        PTR(product_info).publisher       = heap_wcsdup(UNDEFINED_ATTRIBUTE);
        PTR(product_info).tel_help        = heap_wcsdup(UNDEFINED_ATTRIBUTE);
        PTR(product_info).uninstall_instr = heap_wcsdup(UNDEFINED_ATTRIBUTE);
        PTR(product_info).url             = heap_wcsdup(UNDEFINED_ATTRIBUTE);
    }
    else if (_IS_SUCCESS(result) && product_info) {
        PTR(item).product_name = heap_wcsdup(PTR(product_info).display_name);
    }
    else {
        free_jvm_details(item);
        return result;
    }
    PTR(item).product_info = product_info;

    /*
     * LOAD THE PE AND RELEASE INFORMATION
     * ------------------------------------
     */
    result = parse_jvm_pe_rel_model(jvmPath, item);
    if (!_IS_SUCCESS(result)) {
        logmsg(LOGGING_WARN, L"-- add_jvm_instance: Failed to parse the PE and RELEASE model for: %ls. RC: %d", jvmPath, result);
    }

    /*
     * LOAD THE JVM LICENSE DETAILS
     * ----------------------------
     */
    result = parse_jvm_license_type(item);
    if (!_IS_SUCCESS(result)) {
        logmsg(LOGGING_WARN, L"-- add_jvm_instance: Failed to parse the license information for the JVM: %ls. RC: %d", jvmPath, result);
    }

    // TODO: Continue processing the JVM

    PTR(*sysdetails).jvm[PTR(*sysdetails).jvm_count] = item;
    if (!PTR(*sysdetails).jvm[PTR(*sysdetails).jvm_count]) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }
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
    if (!PTR(product)) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    rc = read_uninstall_product_by_install_location(install_path, PTR(product), stop_event);
    if (!_IS_SUCCESS(rc)) {
        logmsg(LOGGING_WARN,
               L"[MODEL PARSER] No uninstall registry product matched install path: %ls",
               install_path);
        HeapFree(GetProcessHeap(), 0, (void*)PTR(product));
        PTR(product) = NULL;

        return rc;
    }

    logmsg(LOGGING_NORMAL,
           L"[MODEL PARSER] Registry product matched. DisplayName=%ls Version=%ls Publisher=%ls",
           PTR(product)->display_name ?     PTR(product)->display_name : L"",
           PTR(product)->display_version ?  PTR(product)->display_version : L"",
           PTR(product)->publisher ?        PTR(product)->publisher : L"");

    return ST_CODE_SUCCESS;
}
