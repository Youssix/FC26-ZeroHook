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
uintptr_t rage::slider_ptr           = 0;
uintptr_t rage::msg_dispatcher       = 0;
uintptr_t rage::dispatch_action_vfunc = 0;
static bool g_new_dispatch_chain     = false;

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
// Two chains depending on build:
//
// Legacy (pre-update):
//   global → *global (wrapper) → **global (obj/rcx) → vtable[9]
//
// New (post-update, SynchedInputDispatcher routing layer added):
//   global → *global (SynchedInputDispatcher A) → *(A+0x178) (raw obj/rcx) → vtable[9]
//   Offset breakdown: A+0xA8 (routing base) + 0xD0 (raw dispatcher slot) = A+0x178
//   Confirmed from sub_142192030 Path-C fallback in updated binary.
bool rage::get_dispatch(uintptr_t& outRcx, dispatch_fn_t& outFn)
{
    if (!rage::msg_dispatcher) return false;

    uintptr_t A = safe_deref(rage::msg_dispatcher);
    if (!A) return false;

    uintptr_t raw = 0;
    if (g_new_dispatch_chain) {
        raw = safe_deref(A + 0x178);
    } else {
        raw = safe_deref(A);
    }
    if (!raw) return false;

    outRcx = raw;

    uintptr_t vtable = safe_deref(raw);
    if (!vtable) return false;

    uintptr_t fnAddr = safe_deref(vtable + 0x48);
    if (!fnAddr) return false;

    outFn = reinterpret_cast<dispatch_fn_t>(fnAddr);
    return true;
}

// ── Pattern scan init ───────────────────────────────────────────────
bool rage::InitOffsets(void* gameBase, unsigned long gameSize)
{
    log::debug("[RAGE] Scanning patterns...\r\n");

    // 1. slider_ptr
    void* m1 = game::pattern_scan(gameBase, gameSize,
        "48 8B 0D ? ? ? ? 48 0F 44 C8 E9 ? ? ? ? CC CC CC CC CC CC");
    if (m1) {
        slider_ptr = resolve_rip3_7((uintptr_t)m1);
        log::debugf("[RAGE] slider_ptr: %p\r\n", (void*)slider_ptr);
    } else {
        log::debug("[RAGE] ERROR: slider_ptr not found\r\n");
    }

    // 2. Dispatcher global — two patterns for two build generations:
    //
    // New (post-update): the ONLINE/HOTJOIN send site calls sub_1424660F0() to get
    // the SynchedInputDispatcher, then serializes payload, then walks to the raw
    // dispatcher at SynchedInputDispatcher+0x178 for vtable[9].
    // Pattern: call getter; xorps xmm0,xmm0; arg setup; mov rdi,rax (save obj);
    //          call serializer; add rdi,0xA8 (routing base); jz
    //
    // Legacy (pre-update): getter returned raw dispatcher directly (2-level deref).
    void* m2 = game::pattern_scan(gameBase, gameSize,
        "E8 ? ? ? ? 0F 57 C0 4C 8D 45 ? BA ? ? ? ? 48 8D 4D ? 0F 11 45 ? 48 8B F8 0F 11 45 ? E8 ? ? ? ? 48 81 C7 ? ? ? ? 74");
    if (m2) {
        __try {
            uintptr_t callSite  = (uintptr_t)m2;
            uintptr_t getterFn  = callSite + 5 + *reinterpret_cast<int32_t*>(callSite + 1);
            // getter is: 48 8B 05 XX XX XX XX C3  (mov rax,[rip+disp]; ret)
            if (*(uint8_t*)getterFn == 0x48 && *(uint8_t*)(getterFn + 1) == 0x8B &&
                *(uint8_t*)(getterFn + 2) == 0x05)
            {
                msg_dispatcher    = resolve_rip3_7(getterFn);
                g_new_dispatch_chain = true;
                log::debugf("[RAGE] msg_dispatcher (new chain +0x178): %p getter=%p\r\n",
                    (void*)msg_dispatcher, (void*)getterFn);
            }
        } __except(1) {
            log::debug("[RAGE] EXCEPTION resolving new getter\r\n");
        }
    }

    if (!msg_dispatcher) {
        // Legacy pattern: getter sits adjacent to array-range helper, same CC padding.
        void* m2l = game::pattern_scan(gameBase, gameSize,
            "48 8B 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 8B 05 ? ? ? ? 48 8B 15");
        if (m2l) {
            msg_dispatcher = resolve_rip3_7((uintptr_t)m2l);
            g_new_dispatch_chain = false;
            log::debugf("[RAGE] msg_dispatcher (legacy chain): %p\r\n", (void*)msg_dispatcher);
        }
    }

    if (!msg_dispatcher)
        log::debug("[RAGE] ERROR: msg_dispatcher not found\r\n");

    // 3. dispatch_action_vfunc — forwarder thunk that reads vtable[9] from rcx
    //    and tail-jumps to it, cleaning two byte stack args first.
    //    Pattern: mov rax,[rcx]; mov r10,[rax+48h]; movzx eax,[rsp+arg_30]; ...
    void* m3 = game::pattern_scan(gameBase, gameSize,
        "48 8B 01 4C 8B 50 48 0F B6 44 24");
    if (m3) {
        dispatch_action_vfunc = (uintptr_t)m3;
        log::debugf("[RAGE] dispatch_action_vfunc: %p\r\n", (void*)dispatch_action_vfunc);
    } else {
        log::debug("[RAGE] dispatch_action_vfunc: NOT FOUND\r\n");
    }

    bool ok = slider_ptr && msg_dispatcher;
    log::debugf("[RAGE] InitOffsets: %s\r\n", ok ? "ALL OK" : "SOME MISSING");
    return ok;
}

#ifndef STANDARD_BUILD
// ── crash_opps ──────────────────────────────────────────────────────
void rage::crash_opps()
{
    log::debug("[RAGE] crash_opps: ENTER\r\n");

    log::debugf(
        "[RAGE] crash_opps: msg_dispatcher=%p\r\n",
        (void*)rage::msg_dispatcher);

    uintptr_t rcx = 0; rage::dispatch_fn_t fn = nullptr;
    if (!rage::get_dispatch(rcx, fn)) {
        log::debug("[RAGE] crash_opps: dispatch not ready (offsets stale?)\r\n");
        toast::Show(toast::Type::Error, "Dispatch not ready");
        return;
    }

    log::debugf(
        "[RAGE] crash_opps: rcx=%p fn=%p\r\n", (void*)rcx, (void*)fn);

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
        log::debugf(
            "[RAGE] crash_opps: EXCEPTION 0x%08X — offsets are stale, game updated\r\n", code);
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
        log::debugf(
            "[RAGE] pause_op_game: EXCEPTION 0x%08X\r\n", GetExceptionCode());
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
        log::debugf(
            "[RAGE] pause_op_game_new: EXCEPTION 0x%08X\r\n", GetExceptionCode());
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
        log::debugf(
            "[RAGE] slider_bomb: EXCEPTION 0x%08X\r\n", GetExceptionCode());
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

    log::debugf("[RAGE] kick_opponent sent (reason=%d)\r\n", dcReason);
}
