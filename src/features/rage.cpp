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
uintptr_t rage::dispatch_vfunc  = 0;

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

    typedef void(__fastcall* dispatch_fn_t)(
        uint64_t rcx, uint64_t* rdx, uint64_t* r8, void* r9,
        int param1, char param2, unsigned char param3);

    bool get_dispatch(uintptr_t& outRcx, dispatch_fn_t& outFn)
    {
        if (!rage::msg_dispatcher || !rage::dispatch_vfunc)
            return false;
        outRcx = safe_deref(rage::msg_dispatcher);
        if (!outRcx) return false;
        outFn = reinterpret_cast<dispatch_fn_t>(rage::dispatch_vfunc);
        return true;
    }
}

// ── Pattern scan init ───────────────────────────────────────────────
bool rage::InitOffsets(void* gameBase, unsigned long gameSize)
{
    char buf[128];
    log::to_file("[RAGE] Scanning patterns...\r\n");

    // 1. slider_ptr
    void* m1 = game::pattern_scan(gameBase, gameSize,
        "48 8B 0D ? ? ? ? 48 0F 44 C8 E9 ? ? ? ? CC CC CC CC CC CC");
    if (m1) {
        slider_ptr = resolve_rip3_7((uintptr_t)m1);
        fmt::snprintf(buf, sizeof(buf), "[RAGE] slider_ptr: %p\r\n", (void*)slider_ptr);
        log::to_file(buf);
    } else {
        log::to_file("[RAGE] ERROR: slider_ptr not found\r\n");
    }

    // 2. RubberImmediateMsgDispatcher
    void* m2 = game::pattern_scan(gameBase, gameSize,
        "48 8B 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 8B 05 ? ? ? ? 48 8B 15");
    if (m2) {
        msg_dispatcher = resolve_rip3_7((uintptr_t)m2);
        fmt::snprintf(buf, sizeof(buf), "[RAGE] msg_dispatcher: %p\r\n", (void*)msg_dispatcher);
        log::to_file(buf);
    } else {
        log::to_file("[RAGE] ERROR: msg_dispatcher not found\r\n");
    }

    // 3. dispatch_action_vfunc
    void* m3 = game::pattern_scan(gameBase, gameSize,
        "48 8B 01 4C 8B 50 48 0F B6 44 24");
    if (m3) {
        dispatch_vfunc = (uintptr_t)m3;
        fmt::snprintf(buf, sizeof(buf), "[RAGE] dispatch_vfunc: %p\r\n", (void*)dispatch_vfunc);
        log::to_file(buf);
    } else {
        log::to_file("[RAGE] ERROR: dispatch_vfunc not found\r\n");
    }

    bool ok = slider_ptr && msg_dispatcher && dispatch_vfunc;
    fmt::snprintf(buf, sizeof(buf), "[RAGE] InitOffsets: %s\r\n", ok ? "ALL OK" : "SOME MISSING");
    log::to_file(buf);
    return ok;
}

#ifndef STANDARD_BUILD
// ── crash_opps ──────────────────────────────────────────────────────
void rage::crash_opps()
{
    uintptr_t rcx; dispatch_fn_t fn;
    if (!get_dispatch(rcx, fn)) {
        log::to_file("[RAGE] crash_opps: dispatch not ready\r\n");
        return;
    }

    uint64_t v32 = 0x75879024;
    int v33 = 0x90;

    hook::g_allow_attack_send = true;
    spoof_call(fn, (uint64_t)rcx, (uint64_t*)&v32, (uint64_t*)&v32,
        (void*)&v33, (int)1, (char)1, (unsigned char)0);
    hook::g_allow_attack_send = false;

    toast::Show(toast::Type::Success, "Crash sent to opponent");
    log::to_file("[RAGE] crash_opps sent\r\n");
}

// ── pause_op_game (Freeze 1) ────────────────────────────────────────
void rage::pause_op_game()
{
    uintptr_t rcx; dispatch_fn_t fn;
    if (!get_dispatch(rcx, fn)) {
        log::to_file("[RAGE] pause_op_game: dispatch not ready\r\n");
        return;
    }

    unsigned char v147[0x840];
    __stosb(v147, 0xFF, 0x840);

    uint64_t v32 = 0x406CE419;

    hook::g_allow_attack_send = true;
    spoof_call(fn, (uint64_t)rcx, (uint64_t*)&v32, (uint64_t*)&v32,
        (void*)v147, (int)0x840, (char)0xFFFFFFFF, (unsigned char)0);
    hook::g_allow_attack_send = false;

    toast::Show(toast::Type::Success, "Freeze 1 sent to opponent");
    log::to_file("[RAGE] Freeze 1 sent\r\n");
}

// ── pause_op_game_new (Freeze 2) ────────────────────────────────────
void rage::pause_op_game_new()
{
    uintptr_t rcx; dispatch_fn_t fn;
    if (!get_dispatch(rcx, fn)) {
        log::to_file("[RAGE] pause_op_game_new: dispatch not ready\r\n");
        return;
    }

    uint64_t v28 = 0xA477B52B;
    uint64_t v29 = 0xA477B52B;
    int64_t v27 = 0;

    hook::g_allow_attack_send = true;
    spoof_call(fn, (uint64_t)rcx, (uint64_t*)&v29, (uint64_t*)&v28,
        (void*)&v27, (int)1, (char)0xFF, (unsigned char)0);
    hook::g_allow_attack_send = false;

    toast::Show(toast::Type::Success, "Freeze 2 sent to opponent");
    log::to_file("[RAGE] Freeze 2 sent\r\n");
}

// ── slider_bomb ─────────────────────────────────────────────────────
void rage::slider_bomb()
{
    uintptr_t rcx; dispatch_fn_t fn;
    if (!get_dispatch(rcx, fn)) {
        log::to_file("[RAGE] slider_bomb: dispatch not ready\r\n");
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
    hook::g_allow_attack_send = true;
    spoof_call(fn, (uint64_t)rcx, (uint64_t*)&opcode, (uint64_t*)&opcode,
        (void*)buffer, (int)0x784, (char)0xFF, (unsigned char)0);
    hook::g_allow_attack_send = false;

    toast::Show(toast::Type::Success, "Slider Bomb sent to opponent");
    log::to_file("[RAGE] slider_bomb sent\r\n");
}

// ── kick_opponent ───────────────────────────────────────────────────
void rage::kick_opponent(int dcReason)
{
    if (!slider_ptr) {
        log::to_file("[RAGE] kick_opponent: slider_ptr not resolved\r\n");
        return;
    }

    uintptr_t v0 = safe_deref(slider_ptr);
    if (!v0) {
        log::to_file("[RAGE] kick_opponent: slider deref null\r\n");
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

    if (*reinterpret_cast<unsigned char*>(v0 + 0x5D72) != 1) {
        *reinterpret_cast<unsigned char*>(v0 + 0x5D74) = v1;
        *reinterpret_cast<unsigned char*>(v0 + 0x5D72) = 1;
    }

    toast::Show(toast::Type::Success, "Kick sent to opponent");

    char buf[80];
    fmt::snprintf(buf, sizeof(buf), "[RAGE] kick_opponent sent (reason=%d)\r\n", dcReason);
    log::to_file(buf);
}
#endif // !STANDARD_BUILD
