//
// Created by Joao Gonzalez on 4/21/2026.
//

#include "windows/evtlog.h"
#include "windows/logging.h"

static WORD evtlog_type_from_level(loglevel_t level) {
    switch (level) {
        case LOGLEVEL_INFO:
            return EVENTLOG_INFORMATION_TYPE;

        case LOGLEVEL_WARN:
            return EVENTLOG_WARNING_TYPE;

        case LOGLEVEL_ERROR:
            return EVENTLOG_ERROR_TYPE;

        default:
            return EVENTLOG_INFORMATION_TYPE;
    }
}

errorcode_t win_evt_log_id_fmt(DWORD evtID, loglevel_t level, LPCWSTR fmt, ...) {
    va_list args;
    wchar_t fmtmsg[MAX_PATH +1];

    HANDLE h_event_source;
    LPCWSTR strings[1];
    WORD event_type;

    if (fmt == NULL) {
        return ST_CODE_UNALLOWED_EMPTY_STRING;
    }

    h_event_source = RegisterEventSourceW(NULL, EVTLOG_SOURCE_NAME);
    if (h_event_source == NULL) {
        return ST_CODE_FAILED_EVTLOGSYS;
    }

    ZeroMemory(fmtmsg, sizeof(fmtmsg));

    va_start(args, fmt);
    vswprintf_s(fmtmsg, _LPWLEN(fmtmsg), fmt, args);
    va_end(args);

    event_type = evtlog_type_from_level(level);
    strings[0] = fmtmsg;

    ReportEventW(
        h_event_source,            /* event log handle */
        event_type,                         /* event type */
        0,                         /* category */
        evtID,                              /* event identifier */
        NULL,                       /* user SID */
        1,                       /* number of strings */
        0,                        /* raw data size */
        strings,                            /* string array */
        NULL                       /* raw data */
    );

    // Logging wrapper with the event viewer
    logmsg(_MAP_FROM_EVTTOLOG_LVL(level), fmtmsg);

    DeregisterEventSource(h_event_source);

    return ST_CODE_SUCCESS;
}

errorcode_t win_evt_log_id(LPCWSTR msg, DWORD evtID, loglevel_t level) {
    return win_evt_log_id_fmt(evtID, level, msg);
}

errorcode_t win_evt_log(LPCWSTR msg, loglevel_t level) {
    return win_evt_log_id(msg, JG_EVENT_ID_GENERIC, level);
}
