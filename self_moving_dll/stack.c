#include "utils.h"

RUNTIME_FUNCTION* find_function_entry(void* control_pc) {
    uint32_t  control_rva = (uint8_t*)control_pc - g_image_base;
    PE_BINARY pe = { 0 };
    parse_pe(g_image_base, &pe);

    IMAGE_DATA_DIRECTORY* exception_dir = &pe.datadir[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    RUNTIME_FUNCTION* table  = pe.image + exception_dir->VirtualAddress;
    RUNTIME_FUNCTION* rtfunc = table;

    // do a binary search
    uintptr_t idxlo = 0;
    uintptr_t idxmid = 0;
    uintptr_t idxhi = exception_dir->Size / sizeof(RUNTIME_FUNCTION);

    while (idxhi > idxlo) {
        idxmid = (idxlo + idxhi) / 2;
        rtfunc = &table[idxmid];

        if (control_rva < rtfunc->BeginAddress) {
            // continue searching lower half
            idxhi = idxmid;
        } else if (control_rva >= rtfunc->EndAddress) {
            // continue searching uper half
            idxlo = idxmid + 1;
        } else {
            printf("found function entry for 0x%p, RUNTIME_FUNCTION: 0x%p\n", control_pc, rtfunc);
            return rtfunc;
        }
    }

    return NULL;
}


int get_callstack(CONTEXT* ctx, void* out_ret_addr_array[], int ret_addr_array_capacity) {
    RUNTIME_FUNCTION* rtfunc = NULL;
    int        frame_idx = 0;
    CONTEXT    local_ctx = *ctx;

    while (local_ctx.Rip && (frame_idx < ret_addr_array_capacity)) {
        rtfunc = find_function_entry(local_ctx.Rip);

        if (rtfunc) {
            void* handler_data = NULL;
            void* establisher_frame_ptrs[2] = { 0 };
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, g_image_base, local_ctx.Rip, rtfunc, &local_ctx, &handler_data, establisher_frame_ptrs, NULL);
        } else {
            local_ctx.Rip = *(uintptr_t*)local_ctx.Rsp;
            local_ctx.Rsp += 8;
        }

        if (local_ctx.Rip && (frame_idx < ret_addr_array_capacity))
            out_ret_addr_array[frame_idx++] = local_ctx.Rip;
    }

    return frame_idx;
}