//
// Created by Joao Gonzalez on 4/29/2026.
//

#ifndef JGCOMPLIANCEMONITOR_JVM_WORKER_H
#define JGCOMPLIANCEMONITOR_JVM_WORKER_H

#include "utils.h"

errorcode_t jvm_worker_run(SYSTEM_DETAILS *system_details, LPCWSTR jvmPath, HANDLE stop_event);

BOOL jvm_verify_valid_installpath(LPCWSTR jvmPath, HANDLE stop_event);

#endif //JGCOMPLIANCEMONITOR_JVM_WORKER_H
