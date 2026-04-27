#include <Windows.h>
#include "log/log.h"
#include "comms/comms.h"
#include "hook/dxgi_hooks.h"
#include "hook/network_hooks.h"
#include "offsets/offsets.h"
#include "bridge/bridge.h"
#include "features/ai_control.h"
#pragma comment(lib, "kernel32.lib")

#ifndef ZH_AMD_WIN11_TEST_PHASE
#define ZH_AMD_WIN11_TEST_PHASE 5
#endif

#if (ZH_AMD_WIN11_TEST_PHASE < 1 || ZH_AMD_WIN11_TEST_PHASE > 5) && ZH_AMD_WIN11_TEST_PHASE != 45
#error "ZH_AMD_WIN11_TEST_PHASE must be 1..5, or 45 for phase 4.5"
#endif

#define ZH_STRINGIZE_IMPL(value) #value
#define ZH_STRINGIZE(value) ZH_STRINGIZE_IMPL(value)

volatile LONG g_injection_marker = 0;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        g_injection_marker = ZH_AMD_WIN11_TEST_PHASE;

        log::to_file("[ZeroHook] FC26-ZeroHook injected (AMD-WIN11 phase "
            ZH_STRINGIZE(ZH_AMD_WIN11_TEST_PHASE) ")\r\n");

#if ZH_AMD_WIN11_TEST_PHASE >= 2
        if (!comms::test_channel())
        {
            log::debug("[ZeroHook] ABORT: NtClose channel not working\r\n");
            return TRUE;
        }
#endif

#if ZH_AMD_WIN11_TEST_PHASE >= 3
        if (!offsets::Init())
        {
            log::debug("[ZeroHook] ABORT: offsets::Init() failed\r\n");
            return TRUE;
        }
#endif

#if ZH_AMD_WIN11_TEST_PHASE == 4
        hook::install_present_hook_only();
#elif ZH_AMD_WIN11_TEST_PHASE == 45
        hook::install_present_render_hook_only();
#elif ZH_AMD_WIN11_TEST_PHASE >= 5
        hook::install_present_render_hook_only();
        hook::install_network_hooks();
#endif
    }

    return TRUE;
}
