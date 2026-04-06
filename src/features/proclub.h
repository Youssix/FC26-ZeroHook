#pragma once
#include <cstdint>

namespace proclub
{
    // Toggle flags — checked by cave code at runtime
    extern bool g_xpBoost;
    extern bool g_skills99;
    extern bool g_searchAlone;

    // True after EPT hooks installed successfully
    extern bool g_xpReady;
    extern bool g_skillsReady;
    extern bool g_searchAloneReady;

    // Scan patterns + install EPT split hooks. Call once after game module resolved.
    bool Init(void* gameBase, unsigned long gameSize);

    // Per-frame: toggle SearchAlone EPT byte patch on state change.
    void Update();
}
