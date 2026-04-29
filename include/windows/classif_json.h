//
// Created by Joao Gonzalez on 4/27/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_CLASSIF_JSON_H
#define JG_COMPLIANCE_MONITOR_CLASSIF_JSON_H

#include "utils.h"
#include "model/basemdl.h"
#include "cjson/cJSON.h"

#define EL_JSON_ENTRIES     "Entries"
#define EL_JSON_NAME        "Name"
#define EL_JSON_REGEXS      "RegExs"

errorcode_t classif_json_open(cJSON **root);
errorcode_t classif_json_parse(cJSON *root, PATTERN_MODEL *model);
errorcode_t classif_json_close(cJSON *root);

errorcode_t classif_pattern_model_free(PATTERN_MODEL model);

#endif //JG_COMPLIANCE_MONITOR_CLASSIF_JSON_H
