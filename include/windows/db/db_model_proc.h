//
// Created by Joao Gonzalez on 5/2/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_DB_MODEL_PROC_H
#define JG_COMPLIANCE_MONITOR_DB_MODEL_PROC_H

#include "windows/db/db_model.h"

#define SHA256_HEX_CCH          0x00000041  /*65*/
#define SHA1_HASH_CCH           0x00000020  /*32*/
#define DB_UTC_ISO_CCH          0x00000020  /* enough for yyyy-mm-ddThh:mm:ssZ */

#define DB_SYNC_NOT_SYNCED      0
#define DB_REMOVE_FIRST_READ    0

errorcode_t db_agent_system_insert(AGENT_DB db, SYSTEM_DETAILS sysdetails);
errorcode_t db_agent_jvm_insert(AGENT_DB db, JVM_DETAILS jvmdetails);
errorcode_t db_agent_productinfo_insert(AGENT_DB db, JVM_DETAILS jvmdetails);

#endif //JG_COMPLIANCE_MONITOR_DB_MODEL_PROC_H
