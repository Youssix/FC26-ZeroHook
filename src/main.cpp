#include <Windows.h>
#include "log/log.h"
#include "log/breadcrumb.h"
#include "comms/comms.h"
#include "hook/dxgi_hooks.h"
#include "hook/network_hooks.h"
#include "offsets/offsets.h"
#include "bridge/bridge.h"

#pragma comment(lib, "kernel32.lib")

volatile LONG g_injection_marker = 0;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        log::to_file("[ZeroHook] FC26-ZeroHook injected\r\n");
        breadcrumb::rescue_previous();  // salvage last-stage from prior session (if any)
        breadcrumb::set("boot:dll_attach");

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

        hook::install_dxgi_hooks();           breadcrumb::set("boot:dxgi_hooked");
        hook::install_network_hooks();        breadcrumb::set("boot:network_hooked");
        hook::install_playerside_hook();      breadcrumb::set("boot:playerside_hooked");
        hook::install_match_timer_hook();     breadcrumb::set("boot:matchtimer_hooked");
        hook::install_eaid_hook();            breadcrumb::set("boot:eaid_hooked");
        hook::install_mismatch_gate_hook();   breadcrumb::set("boot:mismatch_hooked");
        hook::install_checksum_check_hook();  breadcrumb::set("boot:checksum_hooked");

        bridge::init("FC26");
        breadcrumb::set("boot:complete");
    }

    return TRUE;
}
