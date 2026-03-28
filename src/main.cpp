#include <Windows.h>
#include "log/log.h"
#include "comms/comms.h"
#include "hook/dxgi_hooks.h"
#include "hook/network_hooks.h"
#include "offsets/offsets.h"

#pragma comment(lib, "kernel32.lib")

volatile LONG g_injection_marker = 0;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        log::to_file("[Ring-1] FC26-ZeroHook injected\r\n");

        // Resolve all offsets first (game module, spoof gadget, swapchain, input reader)
        if (!offsets::Init())
        {
            log::to_file("[Ring-1] ABORT: offsets::Init() failed\r\n");
            return TRUE;
        }

        if (!comms::test_channel())
        {
            log::to_file("[Ring-1] ABORT: NtClose channel not working\r\n");
            return TRUE;
        }

        hook::install_dxgi_hooks();
        hook::install_network_hooks();
        hook::install_playerside_hook();
    }

    return TRUE;
}
