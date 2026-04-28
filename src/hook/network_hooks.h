#pragma once
#include <Windows.h>

namespace hook
{
    // Legacy bypass flag (kept for non-attack sends that don't need opcode tracking)
    extern volatile bool g_allow_attack_send;
    // Per-opcode pending send counter: incremented before we queue an attack,
    // decremented when the hook sees it pass through. Fixes the async race where
    // g_allow_attack_send is reset before the network thread picks up the packet.
    extern volatile LONG g_pending_crash_sends;
    // Runtime test switch: RouteGameMessage hook stays installed, but all
    // protection/parsing logic is bypassed and original game handler runs.
    extern volatile bool g_network_fast_passthrough;
    extern volatile bool g_network_hook_installed;
    // Alt Tab bypass: EPT hook on SystemOnAltTabMessage sender
    extern volatile bool g_bypass_alt_tab;

    void install_network_hooks();
    bool remove_network_hooks();
    void install_alttab_hook();
    void install_playerside_hook();
    void install_match_timer_hook();
    void install_eaid_hook();
}
