// rage.cpp — Rage features (crash, freeze, slider bomb, kick)
// Pattern-scanned offsets + dispatch calls via spoof_call

#include "rage.h"
#include <intrin.h>
#include "../game/game.h"
#include "../hook/network_hooks.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"
#include "../spoof/spoof_call.hpp"

// ── Globals ─────────────────────────────────────────────────────────
uintptr_t rage::slider_ptr      = 0;
uintptr_t rage::msg_dispatcher  = 0;

// ── Helpers ─────────────────────────────────────────────────────────
namespace
{
    uintptr_t resolve_rip3_7(uintptr_t addr)
    {
        if (!addr) return 0;
        int32_t disp = *reinterpret_cast<int32_t*>(addr + 3);
        return addr + 7 + disp;
    }

    uintptr_t safe_deref(uintptr_t addr)
    {
        if (!addr || addr < 0x10000 || addr >= 0x7FFFFFFFFFFF) return 0;
        return *reinterpret_cast<uintptr_t*>(addr);
    }
}

// ── Public dispatcher resolver (used by rage actions + sliders) ─────
//
// Verified via CE on FC26.exe (post-update build):
//   msg_dispatcher       = RIP-resolved global addr
//   *msg_dispatcher      = intermediate wrapper (heap)
//   **msg_dispatcher     = actual dispatcher object — passed as rcx
//   ***msg_dispatcher    = vtable in FC26.exe data section
//   vtable[9] = *(vtable+0x48) = real dispatch fn (Frostbite vtable[9] convention)
//
// Resolves the chain dynamically — no need to pattern-scan a thunk.
bool rage::get_dispatch(uintptr_t& outRcx, dispatch_fn_t& outFn)
{
    if (!rage::msg_dispatcher) return false;

    uintptr_t v50 = safe_deref(rage::msg_dispatcher);
    if (!v50) return false;

    uintptr_t v51 = safe_deref(v50);
    if (!v51) return false;

    outRcx = v51;

    uintptr_t vtable = safe_deref(v51);
    if (!vtable) return false;

    uintptr_t fnAddr = safe_deref(vtable + 0x48);
    if (!fnAddr) return false;

    outFn = reinterpret_cast<dispatch_fn_t>(fnAddr);
    return true;
}

// ── Pattern scan init ───────────────────────────────────────────────
bool rage::InitOffsets(void* gameBase, unsigned long gameSize)
{
    char buf[128];
    log::debug("[RAGE] Scanning patterns...\r\n");

    // 1. slider_ptr
    void* m1 = game::pattern_scan(gameBase, gameSize,
        "48 8B 0D ? ? ? ? 48 0F 44 C8 E9 ? ? ? ? CC CC CC CC CC CC");
    if (m1) {
        slider_ptr = resolve_rip3_7((uintptr_t)m1);
        fmt::snprintf(buf, sizeof(buf), "[RAGE] slider_ptr: %p\r\n", (void*)slider_ptr);
        log::debug(buf);
    } else {
        log::debug("[RAGE] ERROR: slider_ptr not found\r\n");
    }

    // 2. RubberImmediateMsgDispatcher
    void* m2 = game::pattern_scan(gameBase, gameSize,
        "48 8B 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 8B 05 ? ? ? ? 48 8B 15");
    if (m2) {
        msg_dispatcher = resolve_rip3_7((uintptr_t)m2);
        fmt::snprintf(buf, sizeof(buf), "[RAGE] msg_dispatcher: %p\r\n", (void*)msg_dispatcher);
        log::debug(buf);
    } else {
        log::debug("[RAGE] ERROR: msg_dispatcher not found\r\n");
    }

    // dispatch_vfunc is no longer pattern-scanned. The .rodata thunk that
    // matched was a generic vtable[9] dispatcher with no inner-object wrapper.
    // get_dispatch() now resolves vtable[9] of the real dispatcher object at
    // call time via msg_dispatcher chain, which is what the game itself does.

    bool ok = slider_ptr && msg_dispatcher;
    fmt::snprintf(buf, sizeof(buf), "[RAGE] InitOffsets: %s\r\n", ok ? "ALL OK" : "SOME MISSING");
    log::debug(buf);
    return ok;
}

#ifndef STANDARD_BUILD
// ── crash_opps ──────────────────────────────────────────────────────
void rage::crash_opps()
{
    char buf[256];
    log::debug("[RAGE] crash_opps: ENTER\r\n");

    fmt::snprintf(buf, sizeof(buf),
        "[RAGE] crash_opps: msg_dispatcher=%p\r\n",
        (void*)rage::msg_dispatcher);
    log::debug(buf);

    uintptr_t rcx = 0; rage::dispatch_fn_t fn = nullptr;
    if (!rage::get_dispatch(rcx, fn)) {
        log::debug("[RAGE] crash_opps: dispatch not ready (offsets stale?)\r\n");
        toast::Show(toast::Type::Error, "Dispatch not ready");
        return;
    }

    fmt::snprintf(buf, sizeof(buf),
        "[RAGE] crash_opps: rcx=%p fn=%p\r\n", (void*)rcx, (void*)fn);
    log::debug(buf);

    uint64_t v32 = 0x75879024;
    int v33 = 0x90;

    log::debug("[RAGE] crash_opps: dispatching...\r\n");

    __try {
        hook::g_allow_attack_send = true;
        spoof_call(fn, (uint64_t)rcx, (uint64_t*)&v32, (uint64_t*)&v32,
            (void*)&v33, (int)1, (char)1, (unsigned char)0);
        hook::g_allow_attack_send = false;

        toast::Show(toast::Type::Success, "Crash sent to opponent");
        log::debug("[RAGE] crash_opps: SUCCESS\r\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::g_allow_attack_send = false;
        DWORD code = GetExceptionCode();
        fmt::snprintf(buf, sizeof(buf),
            "[RAGE] crash_opps: EXCEPTION 0x%08X — offsets are stale, game updated\r\n", code);
        log::debug(buf);
        toast::Show(toast::Type::Error, "Crash opps failed (game updated?)");
    }
}

// ── pause_op_game (Freeze 1) ────────────────────────────────────────
void rage::pause_op_game()
{
    log::debug("[RAGE] pause_op_game: ENTER\r\n");
    uintptr_t rcx = 0; dispatch_fn_t fn = nullptr;
    if (!get_dispatch(rcx, fn)) {
        log::debug("[RAGE] pause_op_game: dispatch not ready\r\n");
        return;
    }

    unsigned char v147[0x840];
    __stosb(v147, 0xFF, 0x840);

    uint64_t v32 = 0x406CE419;

    __try {
        hook::g_allow_attack_send = true;
        spoof_call(fn, (uint64_t)rcx, (uint64_t*)&v32, (uint64_t*)&v32,
            (void*)v147, (int)0x840, (char)0xFFFFFFFF, (unsigned char)0);
        hook::g_allow_attack_send = false;
        toast::Show(toast::Type::Success, "Freeze 1 sent to opponent");
        log::debug("[RAGE] pause_op_game: SUCCESS\r\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::g_allow_attack_send = false;
        char buf[128];
        fmt::snprintf(buf, sizeof(buf),
            "[RAGE] pause_op_game: EXCEPTION 0x%08X\r\n", GetExceptionCode());
        log::debug(buf);
        toast::Show(toast::Type::Error, "Freeze 1 failed");
    }
}

// ── pause_op_game_new (Freeze 2) ────────────────────────────────────
void rage::pause_op_game_new()
{
    log::debug("[RAGE] pause_op_game_new: ENTER\r\n");
    uintptr_t rcx = 0; dispatch_fn_t fn = nullptr;
    if (!get_dispatch(rcx, fn)) {
        log::debug("[RAGE] pause_op_game_new: dispatch not ready\r\n");
        return;
    }

    uint64_t v28 = 0xA477B52B;
    uint64_t v29 = 0xA477B52B;
    int64_t v27 = 0;

    __try {
        hook::g_allow_attack_send = true;
        spoof_call(fn, (uint64_t)rcx, (uint64_t*)&v29, (uint64_t*)&v28,
            (void*)&v27, (int)1, (char)0xFF, (unsigned char)0);
        hook::g_allow_attack_send = false;
        toast::Show(toast::Type::Success, "Freeze 2 sent to opponent");
        log::debug("[RAGE] pause_op_game_new: SUCCESS\r\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::g_allow_attack_send = false;
        char buf[128];
        fmt::snprintf(buf, sizeof(buf),
            "[RAGE] pause_op_game_new: EXCEPTION 0x%08X\r\n", GetExceptionCode());
        log::debug(buf);
        toast::Show(toast::Type::Error, "Freeze 2 failed");
    }
}

// ── slider_bomb ─────────────────────────────────────────────────────
void rage::slider_bomb()
{
    log::debug("[RAGE] slider_bomb: ENTER\r\n");
    uintptr_t rcx = 0; dispatch_fn_t fn = nullptr;
    if (!get_dispatch(rcx, fn)) {
        log::debug("[RAGE] slider_bomb: dispatch not ready\r\n");
        return;
    }

    unsigned char buffer[0x784];
    __stosb(buffer, 0x32, sizeof(buffer));

    buffer[0x719] = 0x00;
    buffer[0x71A] = 0x00;
    buffer[0x71B] = 0x00;
    buffer[0x755] = 0x00;
    buffer[0x763] = 0x00;
    buffer[0x771] = 0x00;
    buffer[0x77F] = 0x00;

    __movsb(buffer + 0x700, (const unsigned char*)"222222222222222222222222", 24);
    __stosb(buffer + 0x71C, 0x32, 32);
    __movsb(buffer + 0x73C, (const unsigned char*)"222222222222222222222212", 24);
    __movsb(buffer + 0x756, (const unsigned char*)"222222222212", 12);
    __movsb(buffer + 0x764, (const unsigned char*)"222222222212", 12);
    __movsb(buffer + 0x772, (const unsigned char*)"222222222212", 12);

    for (int i = 0x66C; i <= 0x696; i += 2)
        buffer[i] = 0x32;

    *reinterpret_cast<unsigned int*>(buffer + 0x780) = 2;

    uint64_t opcode = 0x75879024;
    __try {
        hook::g_allow_attack_send = true;
        spoof_call(fn, (uint64_t)rcx, (uint64_t*)&opcode, (uint64_t*)&opcode,
            (void*)buffer, (int)0x784, (char)0xFF, (unsigned char)0);
        hook::g_allow_attack_send = false;
        toast::Show(toast::Type::Success, "Slider Bomb sent to opponent");
        log::debug("[RAGE] slider_bomb: SUCCESS\r\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::g_allow_attack_send = false;
        char buf[128];
        fmt::snprintf(buf, sizeof(buf),
            "[RAGE] slider_bomb: EXCEPTION 0x%08X\r\n", GetExceptionCode());
        log::debug(buf);
        toast::Show(toast::Type::Error, "Slider Bomb failed");
    }
}

#endif // !STANDARD_BUILD

// ── kick_opponent (available in all builds) ─────────────────────────
void rage::kick_opponent(int dcReason)
{
    if (!slider_ptr) {
        log::debug("[RAGE] kick_opponent: slider_ptr not resolved\r\n");
        return;
    }

    uintptr_t v0 = safe_deref(slider_ptr);
    if (!v0) {
        log::debug("[RAGE] kick_opponent: slider deref null\r\n");
        return;
    }

    char v1;
    switch (dcReason) {
        case 0:  v1 = 1;    break; // Opponent Quit
        case 1:  v1 = 5;    break; // End Match Early
        case 2:  v1 = 0xD;  break; // Squad Mismatch
        case 3:  v1 = 0x12; break; // Both Get Loss
        case 4:  v1 = 8;    break; // Forfeit
        default: v1 = 1;    break;
    }

    if (*reinterpret_cast<unsigned char*>(v0 + 0x5D62) != 1) {
        *reinterpret_cast<unsigned char*>(v0 + 0x5D64) = v1;
        *reinterpret_cast<unsigned char*>(v0 + 0x5D62) = 1;
    }

    toast::Show(toast::Type::Success, "Kick sent to opponent");

    char buf[80];
    fmt::snprintf(buf, sizeof(buf), "[RAGE] kick_opponent sent (reason=%d)\r\n", dcReason);
    log::debug(buf);
}
