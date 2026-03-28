#pragma once

namespace champions
{
    // UI state (menu writes these)
    inline bool  enabled     = false;
#ifndef STANDARD_BUILD
    // Premium: free wins/losses
    inline int   spoofedWins   = 0;
    inline int   spoofedLosses = 0;
#endif

    // Runtime state
    inline bool  initialized = false;

    // Init: pattern scan only. Call after offsets::GameBase is set.
    bool Init(void* gameBase, unsigned long gameSize);
    bool IsReady();

    // Install EPT hook (separate step, triggered by button)
    bool InstallHook();
    bool IsHooked();
}
