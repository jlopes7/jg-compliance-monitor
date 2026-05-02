//
// Created by Joao Gonzalez on 5/2/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_DB_MODEL_H
#define JG_COMPLIANCE_MONITOR_DB_MODEL_H

#define AGENT_SYSTEM_SCAN_RUN_ID    L"AGENT_JVM_FSCAN_RUN"

extern const char *k_system_db_ddl;
extern const char *k_jvmdetails_db_ddl;
extern const char *k_productinfo_db_ddl;

extern const char *k_agent_system_upsert_dml;
extern const char *k_agent_jvm_upsert_dml;
extern const char *k_agent_productinfo_upsert_dml;

#endif //JG_COMPLIANCE_MONITOR_DB_MODEL_H
