//
// Created by Joao Gonzalez on 4/27/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_JVM_MDL_H
#define JG_COMPLIANCE_MONITOR_JVM_MDL_H

#include <wchar.h>
#include "cjson/cJSON.h"

#include "windows/db/agent_db.h"

#define ENV_VAR_JAVAHOME        L"JAVA_HOME"
#define ENV_VAR_PATH            L"PATH"

typedef LPCWSTR *PATTERN_LIST;

typedef struct _pattern_entry {
    LPCWSTR product_name;
    size_t pattern_array_size;
    PATTERN_LIST pattern_array;
} pattern_entry_t;

typedef pattern_entry_t *PATTERN_ENTRY;
typedef pattern_entry_t **PATTERN_ENTRY_LIST;

typedef struct _pattern_model {
    PATTERN_ENTRY_LIST entry_list;
    size_t entry_list_size;
} pattern_model_t;

typedef pattern_model_t *PATTERN_MODEL;

typedef struct _product_details {
    LPCWSTR contact;
    LPCWSTR display_name;
    LPCWSTR display_version;
    LPCWSTR tel_help;
    LPCWSTR install_date;
    LPCWSTR publisher;
    uint8_t major_version;
    uint8_t minor_version;
    LPCWSTR url;
    LPCWSTR uninstall_instr;
} product_details_t;

typedef product_details_t *PRODUCT_INFO;

typedef struct _jvm_details {
    LPCWSTR installation_path;
    LPCWSTR publisher;
    LPCWSTR license_type;

    LPCWSTR fullversion_jdk;
    LPCWSTR fullversion_win;
    uint8_t major_version;
    uint8_t minor_version;

    LPCWSTR env_path_installpath;
    LPCWSTR env_path_version;
    LPCWSTR env_javahome_installpath;
    LPCWSTR env_javahome_version;

    LPCWSTR product_name;
    PRODUCT_INFO product_info;

    BOOL is_jdk;
    BOOL is_jre;
    BOOL is_ojdk;
    BOOL is_oracle;
} jvm_details_t;

typedef jvm_details_t *JVM_DETAILS;

typedef struct _system_details {
    LPCWSTR os;
    LPCWSTR version;

    LPCWSTR env_path;
    LPCWSTR env_javahome;

    DWORD num_vcores;
    DWORD num_physical_cores;
    ULONGLONG vm_size;

    LPCWSTR local_user;

    JVM_DETAILS *jvm;
    DWORD jvm_count;
    DWORD jvm_capacity;
    CRITICAL_SECTION jvm_lock;

    HANDLE stop_event;
} system_details_t;
typedef system_details_t *SYSTEM_DETAILS;

typedef struct _init_model_config {
    cJSON *root;
    PATTERN_MODEL model;
} init_model_config_t;

typedef init_model_config_t *INIT_MODEL_CONFIG;

errorcode_t parse_model_system(SYSTEM_DETAILS *sysdetails);
errorcode_t parse_product_info(LPCWSTR install_path, PRODUCT_INFO *product, HANDLE stop_event);
errorcode_t jvm_parse_model(SYSTEM_DETAILS sysdetails, LPVOID lpData, HANDLE stop_event);
errorcode_t clean_jvm_data(SYSTEM_DETAILS *sysdetails);

#endif //JG_COMPLIANCE_MONITOR_JVM_MDL_H
