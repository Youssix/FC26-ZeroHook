#pragma once

namespace hook
{
    // Bypass flag: set true while WE send crash/freeze, so our own hook lets it through
    extern volatile bool g_allow_attack_send;
    // Alt Tab bypass: EPT hook on SystemOnAltTabMessage sender
    extern volatile bool g_bypass_alt_tab;

    void install_network_hooks();
    void install_alttab_hook();
    void install_playerside_hook();
    void install_match_timer_hook();
}
