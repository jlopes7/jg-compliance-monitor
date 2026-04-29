//
// Created by Joao Gonzalez on 4/22/2026.
//

#include "windows/config.h"
#include "windows/winreg_config.h"
#include "windows/evtlog.h"
#include "windows/ini_config.h"
#include "windows/logging.h"
#include "windows/classif_json.h"

static CONFIG internal_config;
static int8_t initialized = 0;

static product_type_t parse_product_type(LPCWSTR product_name) {
    size_t len = wcslen(product_name);

    if ( WSTRICMP(product_name, PRODUCTNAME_JAVA, len) ) {
        return PRODUCT_TYPE_JAVA;
    }
    else if ( WSTRICMP(product_name, PRODUCTNAME_ALL, len) ) {
        return PRODUCT_TYPE_ALL;
    }

    logmsg(LOGGING_ERROR, L"The given product name is not supported: %ld. Will assume ALL products", product_name);
    win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_WARN, L"The given product name is not supported: %ld. The agent will assume ALL products", product_name);

    return PRODUCT_TYPE_ALL;
}

errorcode_t init_config() {
    wchar_t config_path[BUFFER_SIZE];
    wchar_t product_names[BUFFER_SIZE];

    wchar_t flag_inventory_scan[BUFFER_SIZE],
            flag_process_scan[BUFFER_SIZE],
            flag_cve_scan[BUFFER_SIZE];

    errorcode_t result;

    logmsg(LOGGING_NORMAL, L"Reading the internal Agent configuration (INI)");

    result = read_registry_string(REG_CONFIG_LOCATION, config_path, BUFFER_SIZE);
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }

    // Creates the allocations
    internal_config = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(config_t));
    PTR(internal_config).global = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(global_config_t));
    PTR(internal_config).security = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(security_config_t));

    PTR(internal_config).global->active_operation     = calloc(BUFFER_SIZE, sizeof(wchar_t));
    PTR(internal_config).global->configuration_regkey = calloc(BUFFER_SIZE, sizeof(wchar_t));

    // Read the INI configurations on the Global section
    result = read_ini_value(SECTION_NAME_GLOBAL, PARAM_KEY_ACTIVE_OPERATION, PTR(internal_config).global->active_operation, BUFFER_SIZE);
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }
    logmsg(LOGGING_NORMAL, L"- [Global] ActiveOperation: %ls", PTR(internal_config).global->active_operation);

    result = read_ini_value(SECTION_NAME_GLOBAL, PARAM_KEY_CONFIGURATION_KEY, PTR(internal_config).global->configuration_regkey, BUFFER_SIZE);
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }
    logmsg(LOGGING_NORMAL, L"- [Global] ConfigurationKey: %ls", PTR(internal_config).global->configuration_regkey);

    // Process the list of configurations
    result = read_ini_value(SECTION_NAME_GLOBAL, PARAM_KEY_MONITOR_PRODUCTS, product_names, BUFFER_SIZE);
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }
    // list all the products
    result = split_trimmed_list(product_names,
                                &PTR(internal_config).global->monitor_products,
                                &PTR(internal_config).global->monitor_products_size);
    if (!_IS_SUCCESS(result)) {
        win_evt_log_id(L"Failed to parse the list of supported products", JG_EVENT_ID_CONFIG, LOGLEVEL_ERROR);
        return result;
    }
    PTR(internal_config).global->monitor_product_types = HeapAlloc(GetProcessHeap(),
                                                            HEAP_ZERO_MEMORY,
                                                            sizeof(product_type_t) * PTR(internal_config).global->monitor_products_size);

    logmsg(LOGGING_NORMAL, L"- [Global] Number of products to monitor: %d", PTR(internal_config).global->monitor_products_size);
    uint8_t counter = 0;
    for ( ; counter < PTR(internal_config).global->monitor_products_size; counter++) {
        PTR(internal_config).global->monitor_product_types[counter] =
            parse_product_type(PTR(internal_config).global->monitor_products[counter]);
#if defined(_DEBUG_CONSOLE)
        logmsg(LOGGING_NORMAL, L"--- [Global][MonitorProducts] Product to monitor: %ls", PTR(internal_config).global->monitor_products[counter]);
#endif
    }

    // Flags computational
    read_ini_value(SECTION_NAME_GLOBAL, FLAGNAME_INVENTORY_SCAN, flag_inventory_scan, BUFFER_SIZE);
    read_ini_value(SECTION_NAME_GLOBAL, FLAGNAME_PROCESS_SCAN, flag_process_scan, BUFFER_SIZE);
    read_ini_value(SECTION_NAME_GLOBAL, FLAGNAME_CVE_SCAN, flag_cve_scan, BUFFER_SIZE);

    PTR(internal_config).global->inventory_scan_ctrl = _IS_TRUE_STRING( flag_inventory_scan );
    PTR(internal_config).global->process_scan_ctrl = _IS_TRUE_STRING( flag_process_scan );
    PTR(internal_config).global->cve_scan_ctrl = _IS_TRUE_STRING( flag_cve_scan );

    // Initialize the internal configuration model
    result = init_model_config(&PTR(internal_config).model_config);
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }

    // Read the pattern based configuration
    result = classif_json_open(&PTR(internal_config).model_config->root);
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }

    // Parse the pattern configuration to be used later on
    result = classif_json_parse(PTR(internal_config).model_config->root, &PTR(internal_config).model_config->model);
    if ( !_IS_SUCCESS(result) ) {
        return result;
    }
    classif_json_close(PTR(internal_config).model_config->root); // We don't need to keep the JSON allocated into mem after we load the model

    initialized = 1;
    return ST_CODE_SUCCESS;
}

errorcode_t release_config() {
    uint8_t counter = 0;

    if (!internal_config) {
        initialized = 0;
        return ST_CODE_SUCCESS;
    }
    if (PTR(internal_config).global) {
        // Release the Global configuration
        for ( ; counter < PTR(internal_config).global->monitor_products_size ; counter++ ) {
            free(PTR(internal_config).global->monitor_products[counter]);
        }
        free(PTR(internal_config).global->monitor_products);

        free(PTR(internal_config).global->configuration_regkey);
        free(PTR(internal_config).global->active_operation);

        HeapFree(GetProcessHeap(), 0, PTR(internal_config).global->monitor_product_types);
        HeapFree(GetProcessHeap(), 0, PTR(internal_config).global);
    }


    // Release the Security configuration
    if (PTR(internal_config).security) {
        // TODO: Implement
        HeapFree(GetProcessHeap(), 0, PTR(internal_config).security);
    }

    classif_pattern_model_free(PTR(internal_config).model_config->model);
    end_model_config(PTR(internal_config).model_config);

    HeapFree(GetProcessHeap(), 0, internal_config);
    internal_config = NULL;
    initialized = 0;
    return ST_CODE_SUCCESS;
}

errorcode_t get_config(CONFIG *config) {
    if ( !_IS_TRUE(initialized) ) {
        win_evt_log_id(L"The configuration was not initialized yet. No active configuration.", JG_EVENT_ID_CONFIG, LOGLEVEL_ERROR);
        return ST_CODE_CONFIGURATION_NOTINIT;
    }
    PTR(config) = internal_config;

    return ST_CODE_SUCCESS;
}
