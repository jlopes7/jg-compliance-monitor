//
// Created by Joao Gonzalez on 4/23/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_SCAN_AGENT_H
#define JG_COMPLIANCE_MONITOR_SCAN_AGENT_H

#include "utils.h"
#include "windows/dispatcher_types.h"

DWORD WINAPI fs_scan_agent_thread(LPVOID param);

#endif //JG_COMPLIANCE_MONITOR_SCAN_AGENT_H
