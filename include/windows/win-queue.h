//
// Created by Joao Gonzalez on 4/24/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_WIN_QUEUE_H
#define JG_COMPLIANCE_MONITOR_WIN_QUEUE_H

#include "utils.h"

#define DEF_QUEUE_CAPACITY      MAX_BUFFER_SIZE /* Anything higher than 4KB should be complicated ... review it in the future */

typedef struct _win_queue {
    void **items;
    DWORD capacity;
    DWORD capacity_size_in_mem;
    DWORD head;
    DWORD tail;
    DWORD count;
    DWORD active_workers;
    BOOL closed;

    LPCWSTR name;

    CRITICAL_SECTION lock;
    CONDITION_VARIABLE not_empty;
    CONDITION_VARIABLE not_full;
} win_queue_t;

typedef win_queue_t *QUEUE;
typedef void        *QUEUE_ITEM;

typedef void (*queue_item_free)(QUEUE_ITEM item);

errorcode_t inmem_queue_create(QUEUE *queue, DWORD capacity, LPCWSTR name);
errorcode_t inmem_queue_destroy(QUEUE queue, queue_item_free free_item);

errorcode_t inmem_queue_put(QUEUE queue, QUEUE_ITEM item, HANDLE stop_event);
errorcode_t inmem_queue_get(QUEUE queue, QUEUE_ITEM *item, HANDLE stop_event);

errorcode_t inmem_queue_size(QUEUE queue, DWORD *item_count);

errorcode_t inmem_queue_task_done(QUEUE queue);

errorcode_t inmem_queue_close(QUEUE queue);
BOOL inmem_queue_is_closed(QUEUE queue);

#endif //JG_COMPLIANCE_MONITOR_WIN_QUEUE_H
