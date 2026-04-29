//
// Created by Joao Gonzalez on 4/24/2026.
//

#include "windows/win-queue.h"

#include "windows/evtlog.h"
#include "windows/winreg_config.h"
#include "windows/logging.h"

static BOOL queue_should_stop(HANDLE stop_event) {
    return stop_event && WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0;
}

static errorcode_t inmem_queue_grow(QUEUE queue) {
    DWORD new_capacity;
    void **new_items;
    DWORD i;

    if (!queue || PTR(queue).capacity == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    new_capacity = PTR(queue).capacity * 2;

    new_items = HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(void *) * new_capacity
    );

    if (!new_items) {
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    for (i = 0; i < PTR(queue).count; i++) {
        DWORD old_index = (PTR(queue).head + i) % PTR(queue).capacity;
        new_items[i] = PTR(queue).items[old_index];
    }

    HeapFree(GetProcessHeap(), 0, queue->items);

    PTR(queue).items = new_items;
    PTR(queue).capacity = new_capacity;
    PTR(queue).capacity_size_in_mem = sizeof(void *) * new_capacity;
    PTR(queue).head = 0;
    PTR(queue).tail = PTR(queue).count;

    return ST_CODE_SUCCESS;
}

errorcode_t inmem_queue_create(QUEUE *queue, DWORD capacity, LPCWSTR name) {
    QUEUE q_local;
    DWORD initial_capacity_size;

    if (!queue || capacity == 0) {
        return ST_CODE_INVALID_PARAM;
    }

    PTR(queue) = NULL;

    q_local = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(win_queue_t));
    if (!q_local) {
        win_evt_log(L"Failed to create the in-memory system queue", LOGLEVEL_ERROR);
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    initial_capacity_size = sizeof(void *) * capacity;
    PTR(q_local).items = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, initial_capacity_size);
    if (!PTR(q_local).items) {
        HeapFree(GetProcessHeap(), 0, q_local);

        win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_ERROR,
                        L"Failed to create the in-memory system queue - memory allocation error. Memory size: %d", initial_capacity_size);
        return ST_CODE_MEMORY_ALLOCATION_FAILED;
    }

    PTR(q_local).capacity = capacity;
    PTR(q_local).capacity_size_in_mem = initial_capacity_size;
    PTR(q_local).name = name;

    InitializeCriticalSection(&PTR(q_local).lock);
    InitializeConditionVariable(&PTR(q_local).not_empty);
    InitializeConditionVariable(&PTR(q_local).not_full);

    PTR(queue) = q_local;

    win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_INFO,L"[QUEUE] Created the new processing queue: %ls", name);

    return ST_CODE_SUCCESS;
}

errorcode_t inmem_queue_destroy(QUEUE queue, queue_item_free free_item) {
    if (!queue) {
        return ST_CODE_SUCCESS;
    }

    EnterCriticalSection(&PTR(queue).lock);

    win_evt_log_id_fmt(JG_EVENT_ID_GENERIC, LOGLEVEL_WARN, L"Destroying the QUEUE: %ls", PTR(queue).name);

    if (PTR(queue).items && free_item) {
        DWORD i;
        for (i = 0; i < PTR(queue).count; i++) {
            DWORD index = (PTR(queue).head + i) % PTR(queue).capacity;
            QUEUE_ITEM item = PTR(queue).items[index];

            if (item) {
                free_item(item);
                PTR(queue).items[index] = NULL;
            }
        }

        PTR(queue).count = 0;
        PTR(queue).head = 0;
        PTR(queue).tail = 0;
    }

    if (PTR(queue).items) {
        HeapFree(GetProcessHeap(), 0, PTR(queue).items);
        PTR(queue).items = NULL;
        PTR(queue).capacity = 0;
        PTR(queue).capacity_size_in_mem = 0;
    }

    LeaveCriticalSection(&PTR(queue).lock);

    DeleteCriticalSection(&PTR(queue).lock);
    HeapFree(GetProcessHeap(), 0, queue);

    return ST_CODE_SUCCESS;
}

errorcode_t inmem_queue_put(QUEUE queue, QUEUE_ITEM item, HANDLE stop_event) {
    errorcode_t rc;

    if (!queue || !item) {
        return ST_CODE_INVALID_PARAM;
    }

    EnterCriticalSection(&PTR(queue).lock);

    if (queue->closed || queue_should_stop(stop_event)) {
        LeaveCriticalSection(&queue->lock);
        return ST_CODE_QUEUE_IS_EMPTY_OR_CLOSED;
    }

    if (queue->count == queue->capacity) {
        rc = inmem_queue_grow(queue);
        if (!_IS_SUCCESS(rc)) {
            LeaveCriticalSection(&queue->lock);
            return rc;
        }
    }

    PTR(queue).items[PTR(queue).tail] = item;
    PTR(queue).tail = (PTR(queue).tail + 1) % PTR(queue).capacity;
    PTR(queue).count++;

    WakeConditionVariable(&PTR(queue).not_empty);
    LeaveCriticalSection(&PTR(queue).lock);

    return ST_CODE_SUCCESS;
}

errorcode_t inmem_queue_size(QUEUE queue, DWORD *item_count) {
    if (queue == NULL || item_count == NULL) {
        return ST_CODE_INVALID_PARAM;
    }

    EnterCriticalSection(&PTR(queue).lock);
    *item_count = PTR(queue).count;
    LeaveCriticalSection(&PTR(queue).lock);

    return ST_CODE_SUCCESS;
}

errorcode_t inmem_queue_get(QUEUE queue, QUEUE_ITEM *item, HANDLE stop_event) {
    if (!queue || !item) {
        return ST_CODE_INVALID_PARAM;
    }

    PTR(item) = NULL;

    EnterCriticalSection(&PTR(queue).lock);

    while (PTR(queue).count == 0 && !PTR(queue).closed) {
        if (queue_should_stop(stop_event)) {
            LeaveCriticalSection(&queue->lock);
            return ST_CODE_QUEUE_IS_EMPTY_OR_CLOSED;
        }

        SleepConditionVariableCS(&PTR(queue).not_empty, &PTR(queue).lock, 250);
    }

    if (queue->closed || queue->count == 0 || queue_should_stop(stop_event)) {
        LeaveCriticalSection(&PTR(queue).lock);
        return ST_CODE_QUEUE_IS_EMPTY_OR_CLOSED;
    }

    PTR(item) = PTR(queue).items[PTR(queue).head];
    PTR(queue).items[PTR(queue).head] = NULL;
    PTR(queue).head = (PTR(queue).head + 1) % PTR(queue).capacity;
    PTR(queue).count--;
    PTR(queue).active_workers++;

    WakeConditionVariable(&PTR(queue).not_full);
    LeaveCriticalSection(&PTR(queue).lock);

    return ST_CODE_SUCCESS;
}

errorcode_t inmem_queue_task_done(QUEUE queue) {
    if (!queue) {
        return ST_CODE_INVALID_PARAM;
    }

    EnterCriticalSection(&PTR(queue).lock);

    if (PTR(queue).active_workers > 0) {
        PTR(queue).active_workers--;
    }

    if (PTR(queue).count == 0 && PTR(queue).active_workers == 0) {
        PTR(queue).closed = TRUE;
        WakeAllConditionVariable(&PTR(queue).not_empty);
        WakeAllConditionVariable(&PTR(queue).not_full);
    }

    LeaveCriticalSection(&PTR(queue).lock);
    return ST_CODE_SUCCESS;
}

errorcode_t inmem_queue_close(QUEUE queue) {
    if (!queue) {
        return ST_CODE_INVALID_PARAM;
    }

    EnterCriticalSection(&PTR(queue).lock);

    PTR(queue).closed = TRUE;
    WakeAllConditionVariable(&PTR(queue).not_empty);
    WakeAllConditionVariable(&PTR(queue).not_full);

    LeaveCriticalSection(&PTR(queue).lock);

    //logmsg(LOGGING_NORMAL, L"WARN [QUEUE]--> The given queue was closed: %ls", PTR(queue).name);

    return ST_CODE_SUCCESS;
}

BOOL inmem_queue_is_closed(QUEUE queue) {
    BOOL closed;

    if (!queue) {
        return TRUE;
    }

    EnterCriticalSection(&PTR(queue).lock);
    closed = PTR(queue).closed;
    LeaveCriticalSection(&PTR(queue).lock);

    return closed;
}
