//
// Created by Joao Gonzalez on 4/22/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_CONFIG_H
#define JG_COMPLIANCE_MONITOR_CONFIG_H

#include "utils.h"

#define PRODUCTNAME_JAVA L"Java"
#define PRODUCTNAME_ALL L"All"

typedef enum _product_type_t {
    PRODUCT_TYPE_ALL = 0,
    PRODUCT_TYPE_JAVA = 1
} product_type_t;

typedef struct _global_config_t {
    LPWSTR active_operation;
    LPWSTR configuration_regkey;

    LPWSTR *monitor_products;
    product_type_t *monitor_product_types;
    size_t monitor_products_size;

    BOOL inventory_scan_ctrl;
    BOOL process_scan_ctrl;
    BOOL cve_scan_ctrl;
} global_config_t;

typedef struct _security_config_t {
    uint8_t dummy;
} security_config_t;

typedef struct _config_t {
    global_config_t *global;
    security_config_t *security;
    INIT_MODEL_CONFIG model_config;
} config_t;

typedef config_t *CONFIG;

errorcode_t init_config();
errorcode_t release_config();
errorcode_t get_config(CONFIG *config);

#endif //JG_COMPLIANCE_MONITOR_CONFIG_H
