// champions.cpp -- FUT Champions WL Score Spoofer
// EPT hooks vtable slot 53 to intercept score calculation.
// Score formula:  a3 = clamp(0, 10 + (wins - losses), 20)
//   0W-14L -> a3 = 0  (noob matchmaking)
//  10W-0L  -> a3 = 20 (god matchmaking)
//
// EPT hook modifies R8 (a3) in register context before passthrough.
// Vtable stays untouched — invisible to AC scans.

#include "champions.h"
#include <intrin.h>
#include <Windows.h>
#include "../game/game.h"
#include "../hook/ept_hook.h"
#include "../comms/comms.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"

namespace
{
    // Resolved addresses
    uintptr_t g_vtableBase   = 0;
    uintptr_t g_targetFunc   = 0;   // slot 53 function address (hook target)

    bool g_hooked = false;

    // EPT hook params (page-aligned)
    __declspec(align(4096)) ept::ept_hook_install_params_t g_champHookParams = {};

    // ---- Helper: RIP-relative resolve ----
    uintptr_t resolve_rip3_7(uintptr_t addr)
    {
        if (!addr) return 0;
        int disp = *(int*)(addr + 3);
        return addr + 7 + disp;
    }

    // ---- EPT detour ----
    // Called by the EPT stub. ctx->r8 = a3 (third arg in x64 calling convention).
    // We modify ctx->r8 with the spoofed score, then return 0 to passthrough
    // to the original function which sees our modified a3.
    extern "C" unsigned long long ChampionsDetour(
        void* ctx_raw,
        unsigned long long a1,   // original RCX
        unsigned long long a2)   // original RDX (= a2/int)
    {
        if (champions::enabled)
        {
            auto* ctx = reinterpret_cast<ept::register_context_t*>(ctx_raw);
            int a3 = (int)ctx->r8;
            int final_a3 = a3;

#ifndef STANDARD_BUILD
            int netScore = champions::spoofedWins - champions::spoofedLosses;
            final_a3 = 10 + netScore;
            if (final_a3 < 0)  final_a3 = 0;
            if (final_a3 > 20) final_a3 = 20;
#else
            final_a3 = 7;
#endif

            ctx->r8 = (unsigned long long)final_a3;

            static bool s_logged = false;
            if (!s_logged) {
                char buf[128];
                fmt::snprintf(buf, sizeof(buf),
                    "[CHAMP] a3=%d -> %d | spoof ON\r\n", a3, final_a3);
                log::debug(buf);
                toast::Show(toast::Type::Success, "WL Score spoof active");
                s_logged = true;
            }
        }

        return 0; // passthrough to original with modified R8
    }
}

bool champions::Init(void* gameBase, unsigned long gameSize)
{
    char buf[256];
    initialized = false;

    if (!gameBase || !gameSize) {
        log::debug("[CHAMP] Init: no game module\r\n");
        return false;
    }

    log::debug("[CHAMP] Scanning champions vtable pattern...\r\n");

    void* match = game::pattern_scan(gameBase, gameSize,
        "48 8D 0D ? ? ? ? 45 33 FF 41 8B C7");
    if (!match) {
        log::debug("[CHAMP] ERROR: champions vtable pattern not found\r\n");
        return false;
    }

    g_vtableBase = resolve_rip3_7((uintptr_t)match);
    if (!g_vtableBase) {
        log::debug("[CHAMP] ERROR: RIP resolve failed\r\n");
        return false;
    }

    fmt::snprintf(buf, sizeof(buf), "[CHAMP] vtable base: %p\r\n", (void*)g_vtableBase);
    log::debug(buf);

    // Read slot 53 function pointer
    __try {
        uintptr_t* vtable = reinterpret_cast<uintptr_t*>(g_vtableBase);
        g_targetFunc = vtable[53];
    } __except(1) {
        log::debug("[CHAMP] ERROR: cannot read vtable slot 53\r\n");
        return false;
    }

    if (!g_targetFunc) {
        log::debug("[CHAMP] ERROR: slot 53 is null\r\n");
        return false;
    }

    fmt::snprintf(buf, sizeof(buf), "[CHAMP] slot 53 func: %p\r\n", (void*)g_targetFunc);
    log::debug(buf);

    initialized = true;
    log::debug("[CHAMP] Init OK (pattern scan done, hook not installed yet)\r\n");
    return true;
}

bool champions::IsReady()
{
    return initialized;
}

bool champions::InstallHook()
{
    if (!initialized || !g_targetFunc) {
        log::debug("[CHAMP] InstallHook: not initialized\r\n");
        return false;
    }

    if (g_hooked) {
        log::debug("[CHAMP] InstallHook: already installed\r\n");
        return true;
    }

    bool ok = ept::install_hook(g_champHookParams,
        reinterpret_cast<unsigned char*>(g_targetFunc),
        (void*)&ChampionsDetour, "ChampionsScore");

    if (ok) {
        g_hooked = true;
        log::debug("[CHAMP] EPT hook installed on slot 53 function\r\n");
        toast::Show(toast::Type::Success, "Champions hook active");
    } else {
        log::debug("[CHAMP] ERROR: EPT hook install failed\r\n");
        toast::Show(toast::Type::Error, "Champions hook failed");
    }

    return ok;
}

bool champions::IsHooked()
{
    return g_hooked;
}
