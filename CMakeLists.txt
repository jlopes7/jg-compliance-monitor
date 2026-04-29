cmake_minimum_required(VERSION 3.25)

project(jg_compliance_monitor C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(EVENTLOG_MC_FILE "${CMAKE_SOURCE_DIR}/res/agent.mc")
set(EVENTLOG_GEN_DIR "${CMAKE_BINARY_DIR}/eventlog")

file(MAKE_DIRECTORY "${EVENTLOG_GEN_DIR}")

if(WIN32)
    add_executable(jg_compliance_monitor
            windows-src/main.c
            windows-src/service.c
            windows-src/evtlog.c
            windows-src/dispatcher.c
            windows-src/winreg_config.c
            windows-src/ini_config.c
            windows-src/config.c
            windows-src/utils.c
            windows-src/logging.c
            windows-src/win-queue.c
            windows-src/pe_file_prop.c
            windows-src/classif_json.c
            windows-src/model_proc.c

            windows-src/fsscan/scan_agent.c
            windows-src/fsscan/search_fs.c

            windows-src/sqlite/sqlite3.c
            windows-src/db/agent_db.c
            windows-src/cjson/cJSON.c

            windows-src/workers/jvm_worker.c

            res/agent.rc
    )

    add_custom_command(
        OUTPUT
            "${EVENTLOG_GEN_DIR}/agent.rc"
            "${EVENTLOG_GEN_DIR}/agent.h"
        COMMAND mc.exe
            -h "${EVENTLOG_GEN_DIR}"
            -r "${EVENTLOG_GEN_DIR}"
            "${EVENTLOG_MC_FILE}"
        DEPENDS "${EVENTLOG_MC_FILE}"
        COMMENT "Compiling Windows Event Log message file"
        VERBATIM
    )
    target_sources(jg_compliance_monitor PRIVATE
        "${EVENTLOG_GEN_DIR}/agent.rc"
    )
endif()

target_include_directories(jg_compliance_monitor PRIVATE ${CMAKE_SOURCE_DIR}/include)

target_compile_definitions(jg_compliance_monitor PRIVATE
        $<$<CONFIG:Debug>:_DEBUG_CONSOLE>
)
if(WIN32)
    target_compile_definitions(jg_compliance_monitor PRIVATE
            UNICODE
            _UNICODE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
    )

    target_link_libraries(jg_compliance_monitor PRIVATE
            advapi32
            Version
            "${CMAKE_SOURCE_DIR}/lib/pcre2-16-static_x64.lib"
    )

    set_target_properties(jg_compliance_monitor PROPERTIES
            OUTPUT_NAME "jgcomp-agent"
    )
endif()