//
// Created by Joao Gonzalez on 4/21/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_ERRCODES_H
#define JG_COMPLIANCE_MONITOR_ERRCODES_H
#include <wchar.h>

typedef unsigned int errorcode_t;

#define ST_CODE_SUCCESS                     0       /* No error found during execution */
#define ST_CODE_FAILURE                     1       /* General failure code */
#define ST_CODE_UNALLOWED_EMPTY_STRING      70000   /* The given string cannot be empty or nil */
#define ST_CODE_INVALID_PARAM               70001   /* Invalid parameter given */
#define ST_CODE_CONFIGURATION_NOTINIT       70002   /* The Agent global configuration was not initialized yet */
#define ST_CODE_INVALID_PATH                70003   /* Invalid path provided */
#define ST_CODE_IO_CREATEDIR_FAILED         70004   /* Failed the given directory */
#define ST_CODE_MEMORY_ALLOCATION_FAILED    70005   /* Failed to allocate memory on the VM */
#define ST_CODE_IO_OPEN_FAILED              70006   /* Failed to open the IO stream */
#define ST_CODE_IO_STAT_FAILED              70007   /* Failed to get IO status */
#define ST_CODE_BUFFER_TOO_SMALL            70009   /* Failed to modify file because the buffer is too small */
#define ST_CODE_FAILED_EVTLOGSYS            70010   /* The Windows Event Log system failed execution */
#define ST_CODE_FAILED_CREATEEVENT          70011   /* Failed to create the Windows Event */
#define ST_CODE_READ_READ_REGVAL            70012   /* Failed to read the respective registry entry */
#define ST_CODE_CREATEUPT_REGKEY            70013   /* Failed to create the following registry key */
#define ST_CODE_INIFILE_DOESNT_EXIST        70014   /* The path defined in the registry for the INI doesnt exist */
#define ST_CODE_INI_KEY_NOT_FOUND           70015   /* The INI configuration key was not found */
#define ST_CODE_FAILED_TO_READINIVAL        70016   /* Failed to read the INI configuration value */
#define ST_CODE_IO_RENAME_FAILED            70017   /* Failed to rename the file */
#define ST_CODE_FAILED_DISPATCH_AGENTPROC   70018   /* Failed to dispatch the execution of the Agent processes */
#define ST_CODE_FAILED_CREATETHREAD         70019   /* Failed to create a new thread */
#define ST_CODE_NOACTIVE_AGENTS             70020   /* No active agents found. Error in the configuration */
#define ST_CODE_FAILED_AGENT_CRTPRCS        70021   /* Failed to create the agent process */
#define ST_CODE_UNSUPPORTED_OPERATION       70022   /* Given operation is not supported */
#define ST_CODE_QUEUE_IS_EMPTY_OR_CLOSED    70023   /* No items were found in the in-memory queue or he queue is closed */
#define ST_CODE_FAILED_OPERATION            70024   /* Failed to perform the operation */
#define ST_CODE_DB_OPEN_FAILED              70025   /* Failed to open the local database */
#define ST_CODE_DB_EXEC_FAILED              70026   /* Local database execution failed */
#define ST_CODE_DB_SCHEMA_FAILED            70027   /* Schema creation failed for the local database */
#define ST_CODE_DB_PREPARE_FAILED           70028   /* Local database execution preparation failed */
#define ST_CODE_DB_BIND_FAILED              70029   /* Failed to bind to agent local database */
#define ST_CODE_OUT_OF_MEMORY               70030   /* OUT OF MEMORY ERROR */
#define ST_CODE_IO_READ_FAILED              70031   /* IO read failure during processing */
#define ST_CODE_FAILED_PARSE_JSON           70032   /* Message format is wrong, failed to parse the JSON content */
#define ST_CODE_FAILED_TO_RELEASE_RES       70033   /* Failed to release resources */
#define ST_CODE_FAILED_PARSE_MODEL          70034   /* Fail to parse the model details during the process execution */


#endif //JG_COMPLIANCE_MONITOR_ERRCODES_H
