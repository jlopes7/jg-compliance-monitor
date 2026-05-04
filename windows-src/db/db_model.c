//
// Created by Joao Gonzalez on 5/2/2026.
//

#include "windows/db/db_model.h"

/**
 * The tiny SQL DDL for the System persistence. These entries are used for logging
 * all system entries
 */
const char *k_system_db_ddl =
        "CREATE TABLE IF NOT EXISTS agent_system ("
        "    hostname_hash TEXT PRIMARY KEY,"
        "    hostname TEXT NOT NULL,"
        "    os_name TEXT,"
        "    os_version TEXT,"
        "    env_path TEXT,"
        "    env_javahome TEXT,"
        "    env_path_installpath TEXT,"
        "    env_path_version TEXT,"
        "    env_javahome_installpath TEXT,"
        "    env_javahome_version TEXT,"
        "    is_env_path_broken INTEGER NOT NULL DEFAULT 0,"
        "    is_env_javahome_broken INTEGER NOT NULL DEFAULT 0,"
        "    num_vcores INTEGER NOT NULL DEFAULT 0,"
        "    num_physical_cores INTEGER NOT NULL DEFAULT 0,"
        "    vm_size INTEGER NOT NULL DEFAULT 0,"
        "    jvm_count INTEGER NOT NULL DEFAULT 0,"
        "    jvm_last_count INTEGER NOT NULL DEFAULT 0,"
        "    classification_status TEXT NOT NULL DEFAULT 'pending',"
        "    first_seen_utc INTEGER NOT NULL,"
        "    last_seen_utc INTEGER NOT NULL,"
        "    scan_run_id TEXT,"
        "    updated_date_utc TEXT,"
        "    created_date_utc TEXT NOT NULL"
        ");"

        "CREATE INDEX IF NOT EXISTS idx_agent_system_updated_date "
        "ON agent_system(updated_date_utc);"

        "CREATE INDEX IF NOT EXISTS idx_agent_system_hostname "
        "ON agent_system(hostname);"
    ;;;

/**
 * The tiny SQL DDL for the JVM persistence.
 *
 * The "sync_ctrl" attribute is an enumerator with possible codes applied:
 * - 0 : Not synced
 * - 1 : Synced
 * - 2 : Failed syncing
 * - 3 : Syncing
 *
 * The "remove_ctrl" column is an enumerator with possible values:
 * - 0 : First read, no update
 * - 1 : Still active, exists
 * - 2 : Was removed
 */
const char *k_jvmdetails_db_ddl =
        "CREATE TABLE IF NOT EXISTS agent_jvm_details ("
        "    installpath_hash TEXT PRIMARY KEY,"
        "    hostname_hash TEXT NOT NULL,"
        "    installpath TEXT NOT NULL,"
        "    publisher TEXT,"
        "    license_type TEXT,"
        "    legal_copyright TEXT,"
        "    fullversion_jdk TEXT,"
        "    fullversion_win TEXT,"
        "    runtime_version TEXT,"
        "    build_type TEXT,"
        "    major_version INTEGER NOT NULL DEFAULT 0,"
        "    minor_version INTEGER NOT NULL DEFAULT 0,"
        "    product_name TEXT,"
        "    is_jdk INTEGER NOT NULL DEFAULT 0,"
        "    is_jre INTEGER NOT NULL DEFAULT 0,"
        "    is_ojdk INTEGER NOT NULL DEFAULT 0,"
        "    is_oracle INTEGER NOT NULL DEFAULT 0,"
        "    sync_ctrl INTEGER NOT NULL DEFAULT 0,"
        "    remove_ctrl INTEGER NOT NULL DEFAULT 0,"
        "    updated_date_utc TEXT,"
        "    created_date_utc TEXT NOT NULL,"
        "    FOREIGN KEY (hostname_hash) "
        "        REFERENCES agent_system(hostname_hash) "
        "        ON UPDATE CASCADE "
        "        ON DELETE CASCADE"
        ");"

        "CREATE INDEX IF NOT EXISTS idx_agent_jvm_installpath "
        "ON agent_jvm_details(installpath);"

        "CREATE INDEX IF NOT EXISTS idx_agent_jvm_fullversion_win "
        "ON agent_jvm_details(fullversion_win);"

        "CREATE INDEX IF NOT EXISTS idx_agent_jvm_license_type "
        "ON agent_jvm_details(license_type);"

        "CREATE INDEX IF NOT EXISTS idx_agent_jvm_hostname_hash "
        "ON agent_jvm_details(hostname_hash);"
    ;;;

/**
 * The tiny SQL DDL for the product information related to the JVM.
 */
const char *k_productinfo_db_ddl =
        "CREATE TABLE IF NOT EXISTS agent_product_details ("
        "    display_name_hash TEXT PRIMARY KEY,"
        "    installpath_hash TEXT NOT NULL,"
        "    display_name TEXT NOT NULL,"
        "    display_version TEXT,"
        "    tel_help TEXT,"
        "    install_date TEXT,"
        "    publisher TEXT,"
        "    vendor_url TEXT,"
        "    uninstall_instr TEXT,"
        "    major_version INTEGER NOT NULL DEFAULT 0,"
        "    minor_version INTEGER NOT NULL DEFAULT 0,"
        "    updated_date_utc TEXT,"
        "    created_date_utc TEXT NOT NULL,"
        "    FOREIGN KEY (installpath_hash) "
        "        REFERENCES agent_jvm_details(installpath_hash) "
        "        ON UPDATE CASCADE "
        "        ON DELETE CASCADE"
        ");"

        "CREATE INDEX IF NOT EXISTS idx_agent_product_details_display_name "
        "ON agent_product_details(display_name);"

        "CREATE INDEX IF NOT EXISTS idx_agent_product_details_publisher "
        "ON agent_product_details(publisher);"

        "CREATE INDEX IF NOT EXISTS idx_agent_product_installpath_hash "
        "ON agent_product_details(installpath_hash);"
    ;;;

const char *k_agent_system_upsert_dml =
        "INSERT INTO agent_system ("
        "    hostname_hash,"
        "    hostname,"
        "    os_name,"
        "    os_version,"
        "    env_path,"
        "    env_javahome,"
        "    env_path_installpath,"
        "    env_path_version,"
        "    env_javahome_installpath,"
        "    env_javahome_version,"
        "    is_env_path_broken,"
        "    is_env_javahome_broken,"
        "    num_vcores,"
        "    num_physical_cores,"
        "    vm_size,"
        "    jvm_count,"
        "    jvm_last_count,"
        "    classification_status,"
        "    first_seen_utc,"
        "    last_seen_utc,"
        "    scan_run_id,"
        "    updated_date_utc,"
        "    created_date_utc"
        ") VALUES ("
        "    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,"
        "    ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,"
        "    ?19, ?20, ?21, ?22, ?23"
        ") "
        "ON CONFLICT(hostname_hash) DO UPDATE SET "
        "    hostname = excluded.hostname,"
        "    os_name = excluded.os_name,"
        "    os_version = excluded.os_version,"
        "    env_path = excluded.env_path,"
        "    env_javahome = excluded.env_javahome,"
        "    env_path_installpath = excluded.env_path_installpath,"
        "    env_path_version = excluded.env_path_version,"
        "    env_javahome_installpath = excluded.env_javahome_installpath,"
        "    env_javahome_version = excluded.env_javahome_version,"
        "    is_env_path_broken = excluded.is_env_path_broken,"
        "    is_env_javahome_broken = excluded.is_env_javahome_broken,"
        "    num_vcores = excluded.num_vcores,"
        "    num_physical_cores = excluded.num_physical_cores,"
        "    vm_size = excluded.vm_size,"
        "    jvm_last_count = agent_system.jvm_count,"
        "    jvm_count = excluded.jvm_count,"
        "    last_seen_utc = excluded.last_seen_utc,"
        "    scan_run_id = excluded.scan_run_id,"
        "    updated_date_utc = excluded.updated_date_utc;";

const char *k_agent_jvm_upsert_dml =
        "INSERT INTO agent_jvm_details ("
        "    installpath_hash,"
        "    hostname_hash,"
        "    installpath,"
        "    publisher,"
        "    license_type,"
        "    legal_copyright,"
        "    fullversion_jdk,"
        "    fullversion_win,"
        "    runtime_version,"
        "    build_type,"
        "    major_version,"
        "    minor_version,"
        "    product_name,"
        "    is_jdk,"
        "    is_jre,"
        "    is_ojdk,"
        "    is_oracle,"
        "    sync_ctrl,"
        "    remove_ctrl,"
        "    updated_date_utc,"
        "    created_date_utc"
        ") VALUES ("
        "    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,"
        "    ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,"
        "    ?19, ?20, ?21"
        ") "
        "ON CONFLICT(installpath_hash) DO UPDATE SET "
        "    hostname_hash = excluded.hostname_hash,"
        "    installpath = excluded.installpath,"
        "    publisher = excluded.publisher,"
        "    license_type = excluded.license_type,"
        "    legal_copyright = excluded.legal_copyright,"
        "    fullversion_jdk = excluded.fullversion_jdk,"
        "    fullversion_win = excluded.fullversion_win,"
        "    runtime_version = excluded.runtime_version,"
        "    build_type = excluded.build_type,"
        "    major_version = excluded.major_version,"
        "    minor_version = excluded.minor_version,"
        "    product_name = excluded.product_name,"
        "    is_jdk = excluded.is_jdk,"
        "    is_jre = excluded.is_jre,"
        "    is_ojdk = excluded.is_ojdk,"
        "    is_oracle = excluded.is_oracle,"
        "    remove_ctrl = 1,"
        "    updated_date_utc = excluded.updated_date_utc;";

const char *k_agent_productinfo_upsert_dml =
        "INSERT INTO agent_product_details ("
        "    display_name_hash,"
        "    installpath_hash,"
        "    display_name,"
        "    display_version,"
        "    tel_help,"
        "    install_date,"
        "    publisher,"
        "    vendor_url,"
        "    uninstall_instr,"
        "    major_version,"
        "    minor_version,"
        "    updated_date_utc,"
        "    created_date_utc"
        ") VALUES ("
        "    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,"
        "    ?10, ?11, ?12, ?13"
        ") "
        "ON CONFLICT(display_name_hash) DO UPDATE SET "
        "    installpath_hash = excluded.installpath_hash,"
        "    display_name = excluded.display_name,"
        "    display_version = excluded.display_version,"
        "    tel_help = excluded.tel_help,"
        "    install_date = excluded.install_date,"
        "    publisher = excluded.publisher,"
        "    vendor_url = excluded.vendor_url,"
        "    uninstall_instr = excluded.uninstall_instr,"
        "    major_version = excluded.major_version,"
        "    minor_version = excluded.minor_version,"
        "    updated_date_utc = excluded.updated_date_utc;";

const char *k_agent_jvm_select_hashes_by_system_dml =
        "SELECT installpath_hash "
        "FROM agent_jvm_details "
        "WHERE hostname_hash = ?1;";

const char *k_agent_jvm_pair_state_update_dml =
        "UPDATE agent_jvm_details "
        "SET "
        "    remove_ctrl = ?1,"
        "    sync_ctrl = CASE "
        "        WHEN ?1 = 1 THEN 0 "
        "        WHEN remove_ctrl <> ?1 THEN 0 "
        "        ELSE sync_ctrl "
        "    END,"
        "    updated_date_utc = ?2 "
        "WHERE hostname_hash = ?3 "
        "  AND installpath_hash = ?4;";
