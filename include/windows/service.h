//
// Created by Joao Gonzalez on 4/21/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_SERVICE_H
#define JG_COMPLIANCE_MONITOR_SERVICE_H

#include "utils.h"

#define SERVICE_NAME                L"JGComplianceAgent"
#define SERVICE_STOP_EVENT_NAME     L"JGComplianceAgent_EVT_STOP"

int service_dispatch(void);
#if defined(_DEBUG_CONSOLE)
int service_run_debug(void);
#endif

#endif //JG_COMPLIANCE_MONITOR_SERVICE_H
