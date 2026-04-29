//
// Created by Joao Gonzalez on 4/22/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_WINREG_CONFIG_H
#define JG_COMPLIANCE_MONITOR_WINREG_CONFIG_H

#include "utils.h"

#define REG_PATH                    L"SOFTWARE\\JGComplianceMonitor"
#define REG_CONFIG_LOCATION         L"ConfigurationFile"
#define REG_LOG_LOCATION            L"LogLocation"
#define REG_VERSION                 L"Version"

#define REG_FSSCANTO                L"FSScanTO"
#define REG_AGENTCACHEDB            L"AgentCacheDB"

#define REG_PATTERN_CLASSIF_FILE    L"PatternFile"

#define RC_REGKEYVAL_DOESNT_EXIST(X)    ((X) == ST_CODE_READ_READ_REGVAL)

errorcode_t crtupt_registry_value(LPCWSTR key_name, const void *value, DWORD type);
errorcode_t read_registry_string(LPCWSTR key_name, LPWSTR buffer, DWORD buffer_size);
errorcode_t read_registry_dword(LPCWSTR key_name, DWORD *value);

#endif //JG_COMPLIANCE_MONITOR_WINREG_CONFIG_H
