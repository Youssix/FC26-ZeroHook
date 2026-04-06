#pragma once
#include <cstdint>

namespace proclub
{
    // Toggle flags — checked by cave code at runtime
    extern bool g_xpBoost;
    extern bool g_skills99;

    // True after EPT hooks installed successfully
    extern bool g_xpReady;
    extern bool g_skillsReady;

    // Scan patterns + install EPT split hooks. Call once after game module resolved.
    bool Init(void* gameBase, unsigned long gameSize);
}
