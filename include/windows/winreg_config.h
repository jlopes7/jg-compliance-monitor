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

#define REG_UNINSTALL_PATH                  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
#define REG_UNINSTALL_KEY_CONTACT           L"Contact"
#define REG_UNINSTALL_KEY_DISPLAYNAME       L"DisplayName"
#define REG_UNINSTALL_KEY_DISPLAYVERSION    L"DisplayVersion"
#define REG_UNINSTALL_KEY_HELPTELEPHONE     L"HelpTelephone"
#define REG_UNINSTALL_KEY_INSTALLDATE       L"InstallDate"
#define REG_UNINSTALL_KEY_PUBLISHER         L"Publisher"
#define REG_UNINSTALL_KEY_UNINSTALLSTRING   L"UninstallString"
#define REG_UNINSTALL_KEY_URLINFOABOUT      L"URLInfoAbout"
#define REG_UNINSTALL_KEY_MAJVER            L"VersionMajor"
#define REG_UNINSTALL_KEY_MINVER            L"VersionMinor"
#define REG_UNINSTALL_KEY_INSTALLOCATION    L"InstallLocation"

#define IS_REG_OPSUCCESS(X)             ((X) == ST_CODE_REGKEY_NOT_FOUND || (X) == ST_CODE_SUCCESS)
#define IS_REG_NOTFOUND(X)              ((X) == ST_CODE_REGKEY_NOT_FOUND)
#define RC_REGKEYVAL_DOESNT_EXIST(X)    ((X) == ST_CODE_READ_READ_REGVAL)

errorcode_t crtupt_registry_value(LPCWSTR key_name, const void *value, DWORD type);

errorcode_t read_registry_string(LPCWSTR key_name, LPWSTR buffer, DWORD buffer_size);

errorcode_t read_registry_dword(LPCWSTR key_name, DWORD *value);

errorcode_t read_uninstall_product_by_install_location(LPCWSTR install_path, PRODUCT_INFO product, HANDLE stop_event);
errorcode_t populate_product_from_uninstall_key(HKEY hKey, PRODUCT_INFO product);

#endif //JG_COMPLIANCE_MONITOR_WINREG_CONFIG_H
