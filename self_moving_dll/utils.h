#include <Windows.h>
#include <stdint.h>

#include "ntapi.h"

extern uint8_t* g_image_base;
extern size_t   g_image_size;

#define array_len(arr) sizeof(arr) / sizeof(*arr)

typedef struct _PE_BINARY {
    uint8_t* image;
    IMAGE_DOS_HEADER* doshdr;
    IMAGE_NT_HEADERS* nthdrs;
    IMAGE_SECTION_HEADER* secthdrs;
    IMAGE_DATA_DIRECTORY* datadir;
} PE_BINARY;

typedef struct _MEM_RANGE {
    uint8_t* start;
    uint8_t* end;
} MEM_RANGE;

// pe parsing
BOOL      parse_pe(uint8_t* image, _Outptr_ PE_BINARY* out_pe);
uint32_t  rva_to_file_offset(PE_BINARY* pe, uint32_t rva);
MEM_RANGE find_section(PE_BINARY* pe, _In_opt_ const char* sect_name, _In_opt_ uint32_t required_flags);
uint8_t*  find_export(uint8_t* image, const char* export_name);

// patern scanning
PEB*     get_peb();
uint8_t* get_loaded_module(const wchar_t* name);
uint8_t* pattern_scan(uint8_t* start_addr, uint8_t* end_addr, const uint8_t* pattern, const char* mask);
uint8_t* pattern_scan_section(uint8_t* image, const char* sect_name, const uint8_t* pattern, const char* mask);

// stack
RUNTIME_FUNCTION* find_function_entry(void* control_pc);
int               get_callstack(CONTEXT* ctx, void* out_ret_addr_array[], int ret_addr_array_capacity);