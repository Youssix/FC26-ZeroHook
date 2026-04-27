#include <Windows.h>
#include "log/log.h"
#include "comms/comms.h"
#include "hook/dxgi_hooks.h"
#include "hook/network_hooks.h"
#include "offsets/offsets.h"
#include "bridge/bridge.h"
#include "features/ai_control.h"
#pragma comment(lib, "kernel32.lib")

volatile LONG g_injection_marker = 0;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        g_injection_marker = 1;
        log::to_file("[ZeroHook] FC26-ZeroHook injected\r\n");

        if (!offsets::Init())
        {
            log::debug("[ZeroHook] ABORT: offsets::Init() failed\r\n");
            return TRUE;
        }

        if (!comms::test_channel())
        {
            log::debug("[ZeroHook] ABORT: NtClose channel not working\r\n");
            return TRUE;
        }

        hook::install_dxgi_hooks();
        hook::install_network_hooks();
        hook::install_playerside_hook();
        hook::install_match_timer_hook();
        hook::install_eaid_hook();
        bridge::init("FC26");
    }

    return TRUE;
}
