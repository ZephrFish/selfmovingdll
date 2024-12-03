#include "sleepobf.h"
#include "utils.h"

uint8_t* g_image_base;
size_t   g_image_size;


DWORD dll_start(LPVOID lpThreadParameter) {
    printf("hello from self moving dll! try and catch me lolz >_<\n");

    while (TRUE) {
        printf("sleeping..\n");
        sleep_obf(10000);
        printf("awakened..\n");
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    PE_BINARY pe = { 0 };

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        parse_pe(hModule, &pe);
        g_image_base = hModule;
        g_image_size = pe.nthdrs->OptionalHeader.SizeOfImage;

        // note: you can change this part yourself to fit your use
        // this project is just a proof of concept
        CloseHandle(CreateThread(0, 0, dll_start, 0, 0, 0));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}