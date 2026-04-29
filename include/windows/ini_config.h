//
// Created by Joao Gonzalez on 4/22/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_INIT_CONFIG_H
#define JG_COMPLIANCE_MONITOR_INIT_CONFIG_H

#include "utils.h"

#define SECTION_NAME_GLOBAL      L"Global"
#define SECTION_NAME_SECURITY    L"Security"

#define PARAM_KEY_ACTIVE_OPERATION          L"ActiveOperation"
#define PARAM_KEY_MONITOR_PRODUCTS          L"MonitorProducts"
#define PARAM_KEY_CONFIGURATION_KEY         L"ConfigurationKey"

#define FLAGNAME_INVENTORY_SCAN     L"FLagInventoryScan"
#define FLAGNAME_PROCESS_SCAN       L"FlagProcessScan"
#define FLAGNAME_CVE_SCAN           L"FlagCVEScan"

errorcode_t read_ini_value(LPCWSTR section, LPCWSTR key, LPWSTR output, size_t output_size);

#endif //JG_COMPLIANCE_MONITOR_INIT_CONFIG_H
