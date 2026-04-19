// ai_difficulty.cpp — AI difficulty override (Premium only)
// Ports FC26-Internal's AI Local Legendary / AI Opponent Beginner to ZeroHook.
//
// Opcode 0x4837B24B — 12 bytes  [teamIdx, diffFloat, diffFloat]
// Opcode 0x298B28B1 — 112 bytes [teamIdx, diffFloat, diffFloat, diffID, diffID, 0, 0…]
//
// Legendary:  float 0x3F800000 (1.0), ID 5
// Beginner:   float 0x00000000 (0.0), ID 0

#include "ai_difficulty.h"

#ifndef STANDARD_BUILD

#include <Windows.h>
#include <intrin.h>
#include "rage.h"
#include "sliders.h"
#include "../hook/network_hooks.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"
#include "../log/breadcrumb.h"
#include "../spoof/spoof_call.hpp"

bool ai_difficulty::g_localLegendary    = false;
bool ai_difficulty::g_opponentBeginner  = false;

namespace
{
    // 12-byte simple payload
    void send_simple(uint32_t teamIndex, uint32_t diff)
    {
        breadcrumb::set("ai_diff:simple_enter");
        uintptr_t rcx = 0; rage::dispatch_fn_t fn = nullptr;
        if (!rage::get_dispatch(rcx, fn)) {
            log::debug("[AI-DIFF] simple: dispatch not ready\r\n");
            breadcrumb::set("ai_diff:simple_no_dispatch");
            return;
        }

        char dbuf[128];
        fmt::snprintf(dbuf, sizeof(dbuf),
            "ai_diff:simple_dispatch_resolved rcx=%p fn=%p", (void*)rcx, (void*)fn);
        breadcrumb::set(dbuf);

        uint64_t opcode = 0x4837B24B;
        uint32_t buffer[3] = { teamIndex, diff, diff };

        __try {
            hook::g_allow_attack_send = true;
            breadcrumb::set("ai_diff:simple_spoof_call_pre");
            spoof_call(fn, (uint64_t)rcx, (uint64_t*)&opcode, (uint64_t*)&opcode,
                (void*)buffer, (int)12, (char)0xFF, (unsigned char)0);
            breadcrumb::set("ai_diff:simple_spoof_call_post");
            hook::g_allow_attack_send = false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            hook::g_allow_attack_send = false;
            char eb[96];
            fmt::snprintf(eb, sizeof(eb), "ai_diff:simple_EXCEPTION code=0x%08X",
                (unsigned)GetExceptionCode());
            breadcrumb::set(eb);
            log::debug("[AI-DIFF] simple: exception\r\n");
        }
        breadcrumb::set("ai_diff:simple_exit");
    }

    // 112-byte payload with difficulty ID
    void send_float(uint32_t teamIndex, uint32_t diff, uint32_t id)
    {
        breadcrumb::set("ai_diff:float_enter");
        uintptr_t rcx = 0; rage::dispatch_fn_t fn = nullptr;
        if (!rage::get_dispatch(rcx, fn)) {
            log::debug("[AI-DIFF] float: dispatch not ready\r\n");
            breadcrumb::set("ai_diff:float_no_dispatch");
            return;
        }

        char dbuf[128];
        fmt::snprintf(dbuf, sizeof(dbuf),
            "ai_diff:float_dispatch_resolved rcx=%p fn=%p", (void*)rcx, (void*)fn);
        breadcrumb::set(dbuf);

        uint64_t opcode = 0x298B28B1;
        uint32_t buffer[28];  // 112 bytes
        __stosb((unsigned char*)buffer, 0, sizeof(buffer));
        buffer[0] = teamIndex;
        buffer[1] = diff;
        buffer[2] = diff;
        buffer[3] = id;
        buffer[4] = id;

        __try {
            hook::g_allow_attack_send = true;
            breadcrumb::set("ai_diff:float_spoof_call_pre");
            spoof_call(fn, (uint64_t)rcx, (uint64_t*)&opcode, (uint64_t*)&opcode,
                (void*)buffer, (int)112, (char)0xFF, (unsigned char)2);
            breadcrumb::set("ai_diff:float_spoof_call_post");
            hook::g_allow_attack_send = false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            hook::g_allow_attack_send = false;
            char eb[96];
            fmt::snprintf(eb, sizeof(eb), "ai_diff:float_EXCEPTION code=0x%08X",
                (unsigned)GetExceptionCode());
            breadcrumb::set(eb);
            log::debug("[AI-DIFF] float: exception\r\n");
        }
        breadcrumb::set("ai_diff:float_exit");
    }
}

void ai_difficulty::send_local_legendary()
{
    uint32_t team = (sliders::playerside == 0) ? 0u : 1u;
    send_simple(team, 0x3F800000);
    send_float (team, 0x3F800000, 5);
    toast::Show(toast::Type::Success, "AI Local Legendary sent");
    log::debug("[AI-DIFF] Local Legendary sent\r\n");
}

void ai_difficulty::send_opponent_beginner()
{
    uint32_t team = (sliders::playerside == 0) ? 1u : 0u;
    send_simple(team, 0x00000000);
    send_float (team, 0x00000000, 0);
    toast::Show(toast::Type::Success, "AI Opponent Beginner sent");
    log::debug("[AI-DIFF] Opponent Beginner sent\r\n");
}

#endif // !STANDARD_BUILD
