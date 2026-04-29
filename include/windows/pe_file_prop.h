//
// Created by Joao Gonzalez on 4/27/2026.
//

#ifndef JG_COMPLIANCE_MONITOR_PE_FILE_PROP_H
#define JG_COMPLIANCE_MONITOR_PE_FILE_PROP_H

#include "utils.h"

#define PE_PROP_COMPANY_NAME       L"CompanyName"
#define PE_PROP_FILE_DESCRIPTION   L"FileDescription"
#define PE_PROP_FILE_VERSION       L"FileVersion"
#define PE_PROP_INTERNAL_NAME      L"InternalName"
#define PE_PROP_ORIGINAL_FILENAME  L"OriginalFilename"
#define PE_PROP_PRODUCT_NAME       L"ProductName"
#define PE_PROP_PRODUCT_VERSION    L"ProductVersion"
#define PE_PROP_LEGAL_COPYRIGHT    L"LegalCopyright"

typedef struct _pe_file_t {
    LPBYTE version_block;
    DWORD version_size;
    WORD language;
    WORD codepage;
    LPCWSTR file_name;
} pe_file_t;

typedef struct _LANGANDCODEPAGE {
    WORD language;
    WORD codepage;
} LANGANDCODEPAGE;

typedef pe_file_t *PE_FILE;

errorcode_t pe_open(LPCWSTR filepath, PE_FILE *pe);
errorcode_t pe_get_prop(PE_FILE pe, LPCWSTR prop_name, LPWSTR value, size_t value_cch);
errorcode_t pe_close(PE_FILE pe);

#endif //JG_COMPLIANCE_MONITOR_PE_FILE_PROP_H
