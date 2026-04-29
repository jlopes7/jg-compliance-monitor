//
// Created by Joao Gonzalez on 4/22/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_DISPATCHER_H
#define JG_COMPLIANCE_MONITOR_DISPATCHER_H

#include "utils.h"
#include "windows/dispatcher_types.h"

#define PROCESSNAME_FSSCAN          L"fsscan"
#define PROCESSNAME_PROCSCAN        L"procscan"
#define PROCESSNAME_CVESCAN         L"cvescan"

#define TID_FSSCAN                  0x000003E8
#define TID_PROCSCAN                0x000003E9
#define TID_CVESCAN                 0x000003EA

#define DEFAULT_POLLING_INTERVAL    0x006DDD00 /*2 hours*/
#define DEFAULT_SYNC_HB_MS          0x00002710 /* 10 seconds */

errorcode_t dispatcher_start(HANDLE stop_event);
errorcode_t dispatcher_stop(void);

#endif //JG_COMPLIANCE_MONITOR_DISPATCHER_H
