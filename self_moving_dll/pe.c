#include "utils.h"

BOOL parse_pe(uint8_t* image, _Out_ PE_BINARY* out_pe) {
    PE_BINARY pe = { 0 };
    pe.image = image;
    pe.doshdr = (IMAGE_DOS_HEADER*)image;

    if (pe.doshdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    pe.nthdrs = (IMAGE_NT_HEADERS*)(image + pe.doshdr->e_lfanew);
    pe.datadir = pe.nthdrs->OptionalHeader.DataDirectory;
    pe.secthdrs = IMAGE_FIRST_SECTION(pe.nthdrs);

    *out_pe = pe;
    return TRUE;
}

uint32_t rva_to_file_offset(PE_BINARY* pe, uint32_t rva) {
    for (int i = 0; i < pe->nthdrs->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* sect_hdr = &pe->secthdrs[i];
        uint32_t sect_size = sect_hdr->Misc.VirtualSize ? sect_hdr->Misc.VirtualSize : sect_hdr->SizeOfRawData;

        if (rva >= sect_hdr->VirtualAddress && rva <= sect_hdr->VirtualAddress + sect_size)
            return rva - sect_hdr->VirtualAddress + sect_hdr->PointerToRawData;
    }
}

MEM_RANGE find_section(PE_BINARY* pe, _In_opt_ const char* sect_name, _In_opt_ uint32_t required_flags) {
    MEM_RANGE range = { 0 };
    for (int i = 0; i < pe->nthdrs->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* sect_hdr = &pe->secthdrs[i];

        uint8_t* start = pe->image + sect_hdr->VirtualAddress;
        uint8_t* end = pe->image + sect_hdr->VirtualAddress + sect_hdr->Misc.VirtualSize;

        if (sect_name && strlen(sect_name) && memcmp(sect_hdr->Name, sect_name, sizeof(sect_hdr->Name)))
            continue;

        if (required_flags && !(sect_hdr->Characteristics & required_flags))
            continue;

        range.start = start;
        range.end = end;
        return range;
    }
    return range;
}

uint8_t* find_export(uint8_t* image, const char* export_name) {
    PE_BINARY pe = { 0 };
    parse_pe(image, &pe);

    IMAGE_DATA_DIRECTORY* export_data_dir = &pe.datadir[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exportdir = image + export_data_dir->VirtualAddress;

    uint32_t* address_rvas = image + exportdir->AddressOfFunctions;
    uint32_t* name_rvas = image + exportdir->AddressOfNames;
    uint16_t* ordinal_rvas = image + exportdir->AddressOfNameOrdinals;

    for (int i = 0; i < exportdir->NumberOfNames; i++) {
        uint8_t* name = image + name_rvas[i];
        uint8_t* addr = image + address_rvas[ordinal_rvas[i]];

        if (!strcmp(name, export_name)) {
            if (addr >= (image + export_data_dir->VirtualAddress)
                && addr < (image + export_data_dir->VirtualAddress + export_data_dir->Size)) {
                // TOOD: handle forwarded functions ..
            }
            return addr;
        }
    }
    return NULL;
}