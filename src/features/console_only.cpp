// console_only.cpp -- Phase-3 Console-Only Matchmaking Spoofer
//
// Hooks Osdk::UserData::Serialize_ToTdfMap (sub_144143530) to discover the
// IOsdkUser vtable at runtime, then installs three return-value spoofers
// on bCrossplay/iPlatform/iDisplayPlatform getters. The Blaze server then
// sees us as a console player with crossplay on and matches us against
// the console pool.
//
// NoCRT-safe: no std:: anything, no CRT init.

#include "console_only.h"
#include <intrin.h>
#include <Windows.h>
#include "../game/game.h"
#include "../hook/ept_hook.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"

namespace
{
    // Vtable slot layout of IOsdkUser (from IDA decomp of the serializer).
    // Byte offsets on the vtable; slot index = offset / 8.
    constexpr unsigned int VSLOT_BCROSSPLAY        = 0xC8 / 8;   // 0x19
    constexpr unsigned int VSLOT_IPLATFORM         = 0xD0 / 8;   // 0x1A
    constexpr unsigned int VSLOT_IDISPLAYPLATFORM  = 0xF0 / 8;   // 0x1E

    // Offset into the serializer function where we install the hook.
    // The first 9 bytes are: test rdx,rdx ; jz end  (null-guard on user ptr).
    // We hook past the guard so a2 is guaranteed non-null in the detour.
    constexpr unsigned int SERIALIZER_HOOK_OFFSET = 9;

    // Resolved at Init time
    uintptr_t g_serializerBase = 0;  // function entry, BEFORE the +9 offset
    uintptr_t g_serializerHook = 0;  // actual hook target (base + 9)
    bool g_initialized = false;
    bool g_mainHooked  = false;

    // Resolved lazily on first serializer hit
    volatile long      g_lazyRunning     = 0;   // interlock
    volatile long      g_gettersInstalled = 0;
    volatile uintptr_t g_bCrossplayFn    = 0;
    volatile uintptr_t g_iPlatformFn     = 0;
    volatile uintptr_t g_iDispPlatformFn = 0;

    // EPT hook params (page-aligned — one per hook)
    __declspec(align(4096)) ept::ept_hook_install_params_t g_serializerHookParams = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_bCrossplayHookParams = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_iPlatformHookParams = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_iDispPlatformHookParams = {};

    // Cheap pointer sanity check (AC-safe — no API calls)
    bool is_valid_ptr(uintptr_t addr)
    {
        return addr >= 0x10000 && addr < 0x7FFFFFFFFFFF;
    }

    // ── Getter detours ─────────────────────────────────────────────────
    //
    // Each sets ctx->rax to the spoofed value and returns 1. The EPT stub
    // treats non-zero return as "skip original", pops the saved register
    // context (which now has our rax) back into CPU registers, and rets.
    // To the original caller it looks exactly like the getter returned
    // our value.

    extern "C" unsigned long long BCrossplayDetour(
        void* ctx_raw, unsigned long long /*a1*/, unsigned long long /*a2*/)
    {
        if (!console_only::enabled)
            return 0;  // passthrough — original getter runs

        auto* ctx = reinterpret_cast<ept::register_context_t*>(ctx_raw);
        ctx->rax = 1;  // bCrossplay = true
        return 1;       // skip original
    }

    extern "C" unsigned long long IPlatformDetour(
        void* ctx_raw, unsigned long long /*a1*/, unsigned long long /*a2*/)
    {
        if (!console_only::enabled)
            return 0;

        auto* ctx = reinterpret_cast<ept::register_context_t*>(ctx_raw);
        ctx->rax = console_only::targetPlatform;
        return 1;
    }

    extern "C" unsigned long long IDisplayPlatformDetour(
        void* ctx_raw, unsigned long long /*a1*/, unsigned long long /*a2*/)
    {
        if (!console_only::enabled)
            return 0;

        auto* ctx = reinterpret_cast<ept::register_context_t*>(ctx_raw);
        ctx->rax = console_only::targetPlatform;
        return 1;
    }

    // ── Lazy getter-hook installer ─────────────────────────────────────
    //
    // Called from the serializer detour once we've read the IOsdkUser
    // vtable and extracted the 3 getter function pointers. Single-shot
    // (guarded by g_gettersInstalled).

    void lazy_install_getter_hooks()
    {
        if (_InterlockedCompareExchange(&g_gettersInstalled, 1, 0) != 0)
            return;  // already installed (or in progress)

        uintptr_t bcFn = g_bCrossplayFn;
        uintptr_t ipFn = g_iPlatformFn;
        uintptr_t idFn = g_iDispPlatformFn;

        log::debugf(
            "[CO] lazy install: bCrossplay=%p iPlatform=%p iDispPlatform=%p\r\n",
            (void*)bcFn, (void*)ipFn, (void*)idFn);

        int ok_count = 0;

        if (bcFn && is_valid_ptr(bcFn)) {
            bool ok = ept::install_hook(g_bCrossplayHookParams,
                reinterpret_cast<unsigned char*>(bcFn),
                (void*)&BCrossplayDetour, "CO_bCrossplay");
            if (ok) ok_count++;
        }

        if (ipFn && is_valid_ptr(ipFn)) {
            bool ok = ept::install_hook(g_iPlatformHookParams,
                reinterpret_cast<unsigned char*>(ipFn),
                (void*)&IPlatformDetour, "CO_iPlatform");
            if (ok) ok_count++;
        }

        if (idFn && is_valid_ptr(idFn)) {
            bool ok = ept::install_hook(g_iDispPlatformHookParams,
                reinterpret_cast<unsigned char*>(idFn),
                (void*)&IDisplayPlatformDetour, "CO_iDispPlatform");
            if (ok) ok_count++;
        }

        if (ok_count == 3) {
            toast::Show(toast::Type::Success, "Console-only: 3 getters armed");
        } else {
            char msg[64];
            fmt::snprintf(msg, sizeof(msg),
                "Console-only: %d/3 getters armed", ok_count);
            toast::Show(toast::Type::Warning, msg);
        }
    }

    // ── Serializer entry detour ────────────────────────────────────────
    //
    // Runs just past the null-check in Osdk::UserData::Serialize_ToTdfMap.
    // On the first valid hit we:
    //   1. Read the IOsdkUser vtable from *(rdx)
    //   2. Extract the 3 getter function pointers
    //   3. Kick off lazy installation of the 3 getter hooks
    //
    // Always returns 0 — original serializer runs normally. Our goal here
    // is pure discovery, not spoofing the map directly.
    //
    // Note: args are x64 fastcall, so rdx = a2 = IOsdkUser*.

    extern "C" unsigned long long SerializerDetour(
        void* /*ctx_raw*/,
        unsigned long long /*a1*/,
        unsigned long long a2)
    {
        if (g_gettersInstalled) return 0;  // already done — cheap exit
        if (!a2 || !is_valid_ptr(a2)) return 0;

        // Interlock so multiple callers of the serializer racing here
        // don't all try to install hooks.
        if (_InterlockedCompareExchange(&g_lazyRunning, 1, 0) != 0)
            return 0;

        __try {
            uintptr_t vtable = *reinterpret_cast<uintptr_t*>(a2);
            if (!is_valid_ptr(vtable)) {
                log::debugf("[CO] SerializerDetour: bad vtable at a2=%p\r\n", (void*)a2);
                return 0;
            }

            uintptr_t* v = reinterpret_cast<uintptr_t*>(vtable);
            uintptr_t bcFn = v[VSLOT_BCROSSPLAY];
            uintptr_t ipFn = v[VSLOT_IPLATFORM];
            uintptr_t idFn = v[VSLOT_IDISPLAYPLATFORM];

            log::debugf(
                "[CO] user=%p vtable=%p bc=%p ip=%p id=%p\r\n",
                (void*)a2, (void*)vtable, (void*)bcFn, (void*)ipFn, (void*)idFn);

            if (is_valid_ptr(bcFn) && is_valid_ptr(ipFn) && is_valid_ptr(idFn)) {
                g_bCrossplayFn    = bcFn;
                g_iPlatformFn     = ipFn;
                g_iDispPlatformFn = idFn;
                lazy_install_getter_hooks();
            } else {
                log::debug("[CO] SerializerDetour: one of the 3 getters looked invalid\r\n");
            }
        } __except(1) {
            log::debug("[CO] SerializerDetour: EXCEPTION while reading vtable\r\n");
        }

        return 0;  // always passthrough
    }
}

// ── Public API ─────────────────────────────────────────────────────────

bool console_only::Init(void* gameBase, unsigned long gameSize)
{
    g_initialized = false;

    if (!gameBase || !gameSize) {
        log::debug("[CO] Init: no game module\r\n");
        return false;
    }

    // Osdk::UserData::Serialize_ToTdfMap prologue (sub_144143530):
    //   test rdx, rdx
    //   jz   <end>
    //   mov  r11, rsp
    //   push rbp ; push r12 ; push r14
    // Bytes 0..16 : 48 85 D2 0F 84 ?? ?? ?? ?? 4C 8B DC 55 41 54 41 56
    // Pattern verified unique across the game module.
    void* m = game::pattern_scan(gameBase, gameSize,
        "48 85 D2 0F 84 ? ? ? ? 4C 8B DC 55 41 54 41 56");

    if (!m) {
        log::debug("[CO] ERROR: serializer pattern not found\r\n");
        return false;
    }

    g_serializerBase = reinterpret_cast<uintptr_t>(m);
    g_serializerHook = g_serializerBase + SERIALIZER_HOOK_OFFSET;
    g_initialized = true;

    log::debugf("[CO] serializer: %p (hook at +%u = %p)\r\n",
        (void*)g_serializerBase, SERIALIZER_HOOK_OFFSET, (void*)g_serializerHook);
    return true;
}

bool console_only::InstallHook()
{
    if (!g_initialized || !g_serializerHook) {
        log::debug("[CO] InstallHook: not initialized\r\n");
        return false;
    }
    if (g_mainHooked) {
        log::debug("[CO] InstallHook: already installed\r\n");
        return true;
    }

    bool ok = ept::install_hook(g_serializerHookParams,
        reinterpret_cast<unsigned char*>(g_serializerHook),
        (void*)&SerializerDetour, "ConsoleOnlySerializer");

    if (ok) {
        g_mainHooked = true;
        log::debug("[CO] serializer hook installed — waiting for first MM serialize\r\n");
        toast::Show(toast::Type::Success, "Console-only discovery armed");
    } else {
        log::debug("[CO] ERROR: serializer hook install FAILED\r\n");
        toast::Show(toast::Type::Error, "Console-only hook failed");
    }
    return ok;
}

bool console_only::IsReady()         { return g_initialized; }
bool console_only::IsHooked()        { return g_mainHooked; }
bool console_only::GettersResolved() { return g_gettersInstalled != 0; }
