//
// Created by Joao Gonzalez on 4/21/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_EVTLOG_H
#define JG_COMPLIANCE_MONITOR_EVTLOG_H

#include "utils.h"

#define EVTLOG_SOURCE_NAME      L"JGComplianceAgent"

#define JG_EVENT_ID_GENERIC         0x1B58
#define JG_EVENT_ID_STARTSERVICE    0x1B59
#define JG_EVENT_ID_STOPSERVICE     0x1B5A
#define JG_EVENT_ID_ERRORSERVICE    0x1B5B
#define JG_EVENT_ID_RESTARTSERVICE  0x1B5C
#define JG_EVENT_ID_REGMAINTENANCE  0x1B5D
#define JG_EVENT_ID_INIDEFINITION   0x1B5E
#define JG_EVENT_ID_CONFIG          0x1B5F
#define JG_EVENT_ID_DISPATCHER      0x1B60

typedef enum loglevel_t {
    LOGLEVEL_INFO   = 0,
    LOGLEVEL_WARN   = 1,
    LOGLEVEL_ERROR  = 2
} loglevel_t;

errorcode_t win_evt_log(LPCWSTR msg, loglevel_t level);
errorcode_t win_evt_log_id(LPCWSTR msg, DWORD evtID, loglevel_t level);
errorcode_t win_evt_log_id_fmt(DWORD evtID, loglevel_t level, LPCWSTR fmt, ...);

#endif //JG_COMPLIANCE_MONITOR_EVTLOG_H
