#pragma once
#include <cstdint>

// Phase-3 Console-Only Matchmaking feature.
//
// Goal: from a PC client, force the Blaze MM scenario request to advertise
// the local user as a console player with crossplay enabled, so the server
// routes us into the console-only matchmaking pool.
//
// Attack surface (see memory/console_only_matchmaking.md):
//   Osdk__UserData__Serialize_ToTdfMap (0x144143530) reads 3 vtable slots
//   on the IOsdkUser* argument when building the outgoing MM TDF:
//     vtable[0x19] / +0xC8  : bCrossplay        (bool)
//     vtable[0x1A] / +0xD0  : iPlatform         (uint32 ClientPlatformType)
//     vtable[0x1E] / +0xF0  : iDisplayPlatform  (uint32)
//
// Implementation:
//   1. EPT-hook the serializer just past its null-check (offset +9) so the
//      detour always runs with a valid IOsdkUser* in RDX.
//   2. On first hit, read the user's vtable and extract the 3 getter
//      function pointers.
//   3. Lazy-install 3 more EPT hooks on the getters themselves. Each one
//      sets ctx->rax to the spoofed value and returns non-zero to fully
//      replace the original getter (no passthrough).

namespace console_only
{
    // Blaze::ClientPlatformType enum values (from IDA getter 0x1428C2660)
    constexpr uint32_t CP_XONE  = 0x13;
    constexpr uint32_t CP_PS4   = 0x14;
    constexpr uint32_t CP_PS5   = 0x16;
    constexpr uint32_t CP_XBSX  = 0x17;
    constexpr uint32_t CP_STEAM = 0x18;

    // UI state
    inline bool     enabled        = false;
    inline uint32_t targetPlatform = CP_PS5;   // default: ask server for PS pool

    // Lifecycle
    bool Init(void* gameBase, unsigned long gameSize);
    bool InstallHook();
    bool IsReady();
    bool IsHooked();

    // Discovery state — for UI
    bool GettersResolved();
}
