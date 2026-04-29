//
// Created by Joao Gonzalez on 4/22/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_LOGGING_H
#define JG_COMPLIANCE_MONITOR_LOGGING_H

#include "utils.h"
#include "windows/win-queue.h"

#define LOG_QUEUE_NAME          L"LOG_Q"
#define LOG_QUEUE_CAPACITY      MAX_BUFFER_SIZE
#define LOG_FLUSH_INTERVAL_MS   0x000003E8  /*1 second*/
#define LOG_LINE_CCH            0x00001000  /*4KB*/

#define LOG_ROTATE_SIZE_BYTES (1024l * 1024l)

typedef struct {
    LPWSTR log_file;
    LPWSTR log_dir;
    LPWSTR level;
    FILE *log_file_fp;

    QUEUE queue;
    HANDLE stop_event;
    HANDLE writer_thread;
    DWORD writer_thread_id;
} logging_t;

typedef enum {
    LOGGING_NORMAL,
    LOGGING_WARN,
    LOGGING_ERROR
} level_t;

errorcode_t logging_init(void);
errorcode_t logmsg(level_t lvl, LPCWSTR format, ...);
errorcode_t logging_end(void);

#endif //JG_COMPLIANCE_MONITOR_LOGGING_H
