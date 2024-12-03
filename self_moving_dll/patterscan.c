#include "utils.h"

PEB* get_peb() {
    return (PEB*)__readgsqword(0x60);
}

uint8_t* get_loaded_module(const wchar_t* name) {
    PEB* peb = get_peb();

    LIST_ENTRY* head = peb->Ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY* curr = head;

    for (int count = 0;; count++) {
        if (count && curr == head)
            break;

        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((uint8_t*)(curr)-sizeof(LIST_ENTRY));

        if (entry->BaseDllName.Buffer) {
            if (!lstrcmpW(entry->BaseDllName.Buffer, name))
                return (uint8_t*)entry->DllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

uint8_t* pattern_scan(uint8_t* start_addr, uint8_t* end_addr, const uint8_t* pattern, const char* mask) {
    for (uint8_t* addr = start_addr; addr < (end_addr - strlen(mask)); addr++) {
        BOOL found = TRUE;
        for (int i = 0; i < strlen(mask); i++) {
            if (mask[i] != '?' && addr[i] != pattern[i]) {
                found = FALSE;
                break;
            }
        }
        if (found) return addr;
    }

    return NULL;
}

uint8_t* pattern_scan_section(uint8_t* image, const char* sect_name, const uint8_t* pattern, const char* mask) {
    PE_BINARY pe = { 0 };
    parse_pe(image, &pe);

    MEM_RANGE range = find_section(&pe, sect_name, NULL);

    if (!range.start || !range.end)
        return NULL;

    return pattern_scan(range.start, range.end, pattern, mask);
}