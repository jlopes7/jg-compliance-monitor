//
// Created by Joao Gonzalez on 4/23/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_SCAN_STRUCTS_H
#define JG_COMPLIANCE_MONITOR_SCAN_STRUCTS_H

#if defined(_WIN32)
#include <windows.h>
#endif

typedef struct _agent_thread_ctx {
    HANDLE stop_event;
    HANDLE thread_handle;
    DWORD thread_id;
    DWORD interval_ms;
    DWORD heartbeat_ms;
    LPCWSTR name;
    LPTHREAD_START_ROUTINE thread_proc;
} agent_thread_ctx_t;

typedef struct _dispatcher_state {
    agent_thread_ctx_t fs_scan;
    agent_thread_ctx_t proc_scan;
    agent_thread_ctx_t cve_scan;

    BOOL fs_scan_active;
    BOOL proc_scan_active;
    BOOL cve_scan_active;
} dispatcher_state_t;

#endif //JG_COMPLIANCE_MONITOR_SCAN_STRUCTS_H
