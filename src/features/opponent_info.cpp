// opponent_info.cpp — Opponent Intel via EPT hook on matchmaking vtable
// NoCRT-safe: no std:: anything. Uses CMD_INSTALL_EPT_HOOK via NtClose channel.

#include "opponent_info.h"
#include <intrin.h>
#include <Windows.h>
#include "../game/game.h"
#include "../hook/ept_hook.h"
#include "../comms/comms.h"
#include "../offsets/offsets.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"
#include "../spoof/spoof_call.hpp"

// ── Globals ─────────────────────────────────────────────────────────

namespace opp_info
{
    PlayerData g_opponent = {};
    bool       g_showWindow = true;
    bool       g_enableStats = false;  // OFF by default — calling game funcs during 0x75AD corrupts state for some users
}

namespace
{
    // ── Resolved offsets ────────────────────────────────────────────
    uintptr_t g_vtableBase       = 0;   // OnlineMatchmakingPreMatchController vtbl
    uintptr_t g_targetFunc       = 0;   // vtable[1] — hook target
    uintptr_t g_func1            = 0;   // getOpponentFunc_1
    uintptr_t g_func2            = 0;   // getOpponentFunc_2
    uintptr_t g_func3            = 0;   // getOpponentFunc_3
    uintptr_t g_seasonInfoFn     = 0;   // getSeasonInfo
    uintptr_t g_testfuncMatch    = 0;   // testfunc_match (RIP-resolved pointer)
    uint32_t  g_matchTypeMagic  = 0;   // dynamically extracted from "BA ? ? ? ?" (e.g. 0x1B5)
    uint32_t  g_matchTypeVtOff  = 0;   // vtable offset from "FF 90 ? ? ? ?" (e.g. 0x1A0)

    // IDK hook (creation date for all match types incl. FUT Champs)
    uintptr_t g_idkVtable        = 0;   // idk_hook vtable base
    uintptr_t g_idkTargetFunc    = 0;   // dynamically resolved vtable slot
    uintptr_t g_idkFuncAddr      = 0;   // direct address of the IDK function
    uint32_t  g_idkDataOffset    = 0;   // dynamic from prologue (e.g. 0xC410)
    int       g_idkSlot          = -1;  // resolved vtable slot index
    bool      g_idkHooked        = false;

    bool g_initialized = false;
    bool g_hooked      = false;

    // EPT hook params (page-aligned for hypervisor)
    __declspec(align(4096)) ept::ept_hook_install_params_t g_hookParams = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_idkHookParams = {};

    // ── Helpers ─────────────────────────────────────────────────────

    uintptr_t resolve_rip3_7(uintptr_t addr)
    {
        if (!addr) return 0;
        int32_t disp = *(int32_t*)(addr + 3);
        return addr + 7 + disp;
    }

    uintptr_t resolve_call_e8(uintptr_t addr)
    {
        if (!addr) return 0;
        int32_t disp = *(int32_t*)(addr + 1);
        return addr + 5 + disp;
    }

    // GetOppsInfo — follows E8 call, then reads RIP-relative at +4 inside target
    uintptr_t resolve_opps_info(uintptr_t addr)
    {
        if (!addr) return 0;
        // follow E8 call
        uintptr_t sub = resolve_call_e8(addr);
        if (!sub) return 0;
        // at sub+4 there's a RIP-relative instruction (48 8B 0D / 48 8B 05)
        uintptr_t instr = sub + 4;
        int32_t disp = *(int32_t*)(instr + 3);
        return instr + 7 + disp;
    }

    // Lightweight pointer sanity check — no API calls (AC-safe)
    bool is_valid_ptr(uintptr_t addr)
    {
        return addr >= 0x10000 && addr < 0x7FFFFFFFFFFF;
    }

    void safe_copy(void* dst, const void* src, int size)
    {
        __try { __movsb((unsigned char*)dst, (const unsigned char*)src, size); }
        __except (1) { __stosb((unsigned char*)dst, 0, size); }
    }

    // NoCRT strncpy
    void safe_strcpy(char* dst, const char* src, int maxLen)
    {
        __try {
            int i = 0;
            while (src[i] && i < maxLen - 1) { dst[i] = src[i]; i++; }
            dst[i] = '\0';
        } __except (1) { dst[0] = '\0'; }
    }

    bool safe_strcmp(const char* a, const char* b)
    {
        while (*a && *b) { if (*a != *b) return false; a++; b++; }
        return *a == *b;
    }

    // ── Match type constants ───────────────────────────────────────
    constexpr int MT_FUTCHAMPS = 0x1E;

    // Resolve match type via testfunc_match vtable chain.
    // Returns raw int (0x1E = FUT Champions, 0x22 = Rivals, etc.) or -1 on failure.
    int getMatchType()
    {
        if (!g_testfuncMatch || !g_matchTypeMagic) {
            log::debug("[OPP] getMatchType: testfuncMatch or magic not set\r\n");
            return -1;
        }

        __try {
            if (!is_valid_ptr(g_testfuncMatch)) { log::to_file("[OPP] BAIL getMatchType: testfuncMatch bad\r\n"); return -1; }
            uint64_t basePtr = *(uint64_t*)g_testfuncMatch;
            if (!is_valid_ptr(basePtr)) { log::to_file("[OPP] BAIL getMatchType: basePtr bad\r\n"); return -1; }

            uint64_t vtbl = *(uint64_t*)basePtr;
            if (!is_valid_ptr(vtbl + 0x30)) { log::to_file("[OPP] BAIL getMatchType: vtbl bad\r\n"); return -1; }

            uint64_t fnAddr = *(uint64_t*)(vtbl + 0x30);
            if (!is_valid_ptr(fnAddr)) { log::to_file("[OPP] BAIL getMatchType: vtbl+0x30 bad\r\n"); return -1; }

            typedef __int64(__fastcall* FnType)(uint64_t, uint32_t);
            auto fn = reinterpret_cast<FnType>(fnAddr);

            log::debugf("[OPP] getMatchType: CALL1 fn=%p rcx=%p edx=0x0EBDBBE3\r\n", (void*)fnAddr, (void*)basePtr);
            __int64 v3 = spoof_call(fn, (uint64_t)basePtr, (uint32_t)0x0EBDBBE3);
            log::debugf("[OPP] getMatchType: CALL1 returned v3=%p\r\n", (void*)v3);
            if (!is_valid_ptr((uintptr_t)v3)) { log::to_file("[OPP] BAIL getMatchType: v3 bad\r\n"); return -1; }

            uint64_t v3_vtbl = *(uint64_t*)v3;
            if (!is_valid_ptr(v3_vtbl)) { log::to_file("[OPP] BAIL getMatchType: v3_vtbl bad\r\n"); return -1; }

            uint64_t fnAddr2 = *(uint64_t*)(v3_vtbl + 0x18);
            if (!is_valid_ptr(fnAddr2)) { log::to_file("[OPP] BAIL getMatchType: fnAddr2 bad\r\n"); return -1; }

            auto call2 = reinterpret_cast<FnType>(fnAddr2);
            log::debugf("[OPP] getMatchType: CALL2 fn=%p rcx=%p edx=0x0EBDBBE4\r\n", (void*)fnAddr2, (void*)v3);
            __int64 v4 = spoof_call(call2, (uint64_t)v3, (uint32_t)0x0EBDBBE4);
            log::debugf("[OPP] getMatchType: CALL2 returned v4=%p\r\n", (void*)v4);
            if (!is_valid_ptr((uintptr_t)v4)) { log::to_file("[OPP] BAIL getMatchType: v4 bad\r\n"); return -1; }

            uint64_t v4_vtbl = *(uint64_t*)v4;
            if (!is_valid_ptr(v4_vtbl)) { log::to_file("[OPP] BAIL getMatchType: v4_vtbl bad\r\n"); return -1; }

            uint32_t vtOff = g_matchTypeVtOff ? g_matchTypeVtOff : 0x1A0;
            if (!is_valid_ptr(v4_vtbl + vtOff)) { log::to_file("[OPP] BAIL getMatchType: vtOff bad\r\n"); return -1; }
            uint64_t fnAddr3 = *(uint64_t*)(v4_vtbl + vtOff);
            if (!is_valid_ptr(fnAddr3)) { log::to_file("[OPP] BAIL getMatchType: fnAddr3 bad\r\n"); return -1; }

            typedef __int64(__fastcall* Fn3Type)(uint64_t, uint32_t, unsigned int*);
            auto fn3 = reinterpret_cast<Fn3Type>(fnAddr3);

            unsigned int result = 0;
            log::debugf("[OPP] getMatchType: CALL3 fn=%p rcx=%p edx=0x%X r8=&result\r\n",
                (void*)fnAddr3, (void*)v4, g_matchTypeMagic);
            spoof_call(fn3, (uint64_t)v4, (uint32_t)g_matchTypeMagic, &result);
            log::debugf("[OPP] getMatchType: CALL3 returned, result=%d (0x%X)\r\n", result, result);

            // Release v4 only if it's a NEW object (v4 != v3).
            // When vtable+0x18 returns the same ptr, no AddRef was done — releasing would over-decrement.
            if (v4 != v3) {
                uint64_t relFn = *(uint64_t*)(v4_vtbl + 0x8);
                if (is_valid_ptr(relFn)) {
                    typedef void(__fastcall* ReleaseFn)(__int64);
                    log::debugf("[OPP] getMatchType: RELEASE fn=%p rcx=%p (v4!=v3)\r\n", (void*)relFn, (void*)v4);
                    spoof_call(reinterpret_cast<ReleaseFn>(relFn), (__int64)v4);
                    log::to_file("[OPP] getMatchType: RELEASE done\r\n");
                }
            } else {
                log::to_file("[OPP] getMatchType: SKIP release (v4==v3, no AddRef)\r\n");
            }

            log::debugf("[OPP] getMatchType: DONE result=%d (0x%X)\r\n", result, result);

            return (int)result;
        }
        __except (1) {
            log::debug("[OPP] getMatchType: EXCEPTION\r\n");
            return -1;
        }
    }

    // ── get_object_result (mirrors Internal's helper) ───────────────

    __int64 get_object_result()
    {
        log::debug("[OPP] get_object_result: calling func2...\r\n");

        typedef __int64(__fastcall* GetterFn)();
        auto getter = reinterpret_cast<GetterFn>(g_func2);

        __int64 obj = 0;
        __try { obj = spoof_call(getter); }
        __except (1) {
            log::debug("[OPP] get_object_result: func2 CRASHED\r\n");
            return 0;
        }

        log::debugf("[OPP] get_object_result: func2 returned %p\r\n", (void*)obj);

        if (!obj) { log::to_file("[OPP] BAIL: func2 returned NULL\r\n"); return 0; }

        __try {
            if (!is_valid_ptr(obj)) { log::to_file("[OPP] BAIL: func2 result invalid ptr\r\n"); return 0; }
            uintptr_t vtbl = *(uintptr_t*)obj;
            if (!is_valid_ptr(vtbl + 0x180)) { log::to_file("[OPP] BAIL: obj vtbl invalid\r\n"); return 0; }

            uintptr_t fnAddr = *(uintptr_t*)(vtbl + 0x180);
            if (!is_valid_ptr(fnAddr)) { log::to_file("[OPP] BAIL: vtbl+0x180 invalid\r\n"); return 0; }

            log::debugf("[OPP] get_object_result: calling vtbl+0x180 at %p\r\n", (void*)fnAddr);

            typedef __int64(__fastcall* VFuncType)(__int64);
            auto vfunc = reinterpret_cast<VFuncType>(fnAddr);
            __int64 result = spoof_call(vfunc, obj);

            log::debugf("[OPP] get_object_result: vtbl+0x180 returned %p\r\n", (void*)result);
            return result;
        }
        __except (1) {
            log::debug("[OPP] get_object_result: vtbl call CRASHED\r\n");
            return 0;
        }
    }

    // ── Extract stats from FutCooperativeServiceImpl ────────────────

    void extract_stats()
    {
        if (!g_testfuncMatch) {
            log::debug("[OPP] extract_stats: testfunc_match is NULL, skipping stats\r\n");
            return;
        }

        __try {
            if (!is_valid_ptr(g_testfuncMatch)) return;
            uint64_t basePtr = *(uint64_t*)g_testfuncMatch;
            if (!is_valid_ptr(basePtr)) return;

            uint64_t vtbl = *(uint64_t*)basePtr;
            if (!is_valid_ptr(vtbl + 0x30)) return;

            uint64_t fnAddr = *(uint64_t*)(vtbl + 0x30);
            if (!is_valid_ptr(fnAddr)) return;

            typedef __int64(__fastcall* FnType)(uint64_t, uint32_t);
            auto fn = reinterpret_cast<FnType>(fnAddr);

            log::debugf("[OPP] extract_stats: CALL1 fn=%p rcx=%p edx=0x1C3E87C8\r\n", (void*)fnAddr, (void*)basePtr);
            __int64 v3 = spoof_call(fn, (uint64_t)basePtr, (uint32_t)0x1C3E87C8);
            log::debugf("[OPP] extract_stats: CALL1 returned v3=%p\r\n", (void*)v3);
            if (!is_valid_ptr((uintptr_t)v3)) { log::to_file("[OPP] BAIL extract_stats: v3 bad\r\n"); return; }

            uint64_t v3_vtbl = *(uint64_t*)v3;
            if (!is_valid_ptr(v3_vtbl + 0x18)) { log::to_file("[OPP] BAIL extract_stats: v3_vtbl bad\r\n"); return; }

            uint64_t fnAddr2 = *(uint64_t*)(v3_vtbl + 0x18);
            if (!is_valid_ptr(fnAddr2)) { log::to_file("[OPP] BAIL extract_stats: fnAddr2 bad\r\n"); return; }

            auto call2 = reinterpret_cast<FnType>(fnAddr2);
            log::debugf("[OPP] extract_stats: CALL2 fn=%p rcx=%p edx=0x1C3E87C9\r\n", (void*)fnAddr2, (void*)v3);
            __int64 v4 = spoof_call(call2, (uint64_t)v3, (uint32_t)0x1C3E87C9);
            log::debugf("[OPP] extract_stats: CALL2 returned v4=%p\r\n", (void*)v4);
            if (!is_valid_ptr((uintptr_t)v4)) { log::to_file("[OPP] BAIL extract_stats: v4 bad\r\n"); return; }

            uint64_t v4_vtbl = *(uint64_t*)v4;
            if (!is_valid_ptr(v4_vtbl + 0x190)) { log::to_file("[OPP] BAIL extract_stats: v4_vtbl bad\r\n"); return; }

            uint64_t fnAddr3 = *(uint64_t*)(v4_vtbl + 0x190);
            if (!is_valid_ptr(fnAddr3)) { log::to_file("[OPP] BAIL extract_stats: fnAddr3 bad\r\n"); return; }

            typedef __int64(__fastcall* Fn3Type)(uint64_t);
            auto call3 = reinterpret_cast<Fn3Type>(fnAddr3);
            log::debugf("[OPP] extract_stats: CALL3 fn=%p rcx=%p\r\n", (void*)fnAddr3, (void*)v4);
            __int64 finalResult = spoof_call(call3, (uint64_t)v4);
            log::debugf("[OPP] extract_stats: CALL3 returned finalResult=%p\r\n", (void*)finalResult);
            if (!is_valid_ptr((uintptr_t)finalResult)) { log::to_file("[OPP] BAIL extract_stats: finalResult bad\r\n"); return; }

            auto pWords = reinterpret_cast<uint32_t*>(finalResult);

            opp_info::g_opponent.drRating     = (int)pWords[0x10];
            opp_info::g_opponent.chemistry    = (int)pWords[0x11];
            opp_info::g_opponent.teamOvr      = (int)pWords[0x12];
            opp_info::g_opponent.skillRating  = (int)pWords[0x13];
            opp_info::g_opponent.seasonWins   = (int)pWords[0x08];
            opp_info::g_opponent.seasonLosses = (int)pWords[0x09];
            opp_info::g_opponent.seasonTies   = (int)pWords[0x0A];
            opp_info::g_opponent.totalGames   = (int)pWords[0x0B];
            opp_info::g_opponent.dnfPercent   = (int)pWords[0x0C];
            opp_info::g_opponent.starLevel    = (int)pWords[0x0D];
            opp_info::g_opponent.badgeId      = (int)pWords[0x0F];

            // Club name at pWords[0x14], club tag at pWords[0x34]
            safe_strcpy(opp_info::g_opponent.clubName,
                reinterpret_cast<const char*>(pWords + 0x14), sizeof(opp_info::g_opponent.clubName));
            safe_strcpy(opp_info::g_opponent.clubTag,
                reinterpret_cast<const char*>(pWords + 0x34), sizeof(opp_info::g_opponent.clubTag));

            log::debugf(
                "[OPP] Stats: DR=%d Chem=%d OVR=%d Skill=%d W=%d L=%d D=%d DNF=%d\r\n",
                opp_info::g_opponent.drRating, opp_info::g_opponent.chemistry,
                opp_info::g_opponent.teamOvr, opp_info::g_opponent.skillRating,
                opp_info::g_opponent.seasonWins, opp_info::g_opponent.seasonLosses,
                opp_info::g_opponent.seasonTies, opp_info::g_opponent.dnfPercent);

            // ── Season info (creation date) ─────────────────────────
            if (g_seasonInfoFn) {
                auto v31 = pWords[0x0E];
                char v11[64] = {};

                log::debugf("[OPP] extract_stats: CALL_SEASON fn=%p arg=0x%X\r\n",
                    (void*)g_seasonInfoFn, v31);

                typedef void(__fastcall* SeasonFn)(unsigned int, __int64);
                auto seasonFn = reinterpret_cast<SeasonFn>(g_seasonInfoFn);
                spoof_call(seasonFn, v31, reinterpret_cast<__int64>(v11));
                log::to_file("[OPP] extract_stats: CALL_SEASON returned\r\n");

                int month = *(int*)(v11 + 0x10);
                unsigned int year = *(unsigned int*)(v11 + 0x14);
                year += 0x76C;

                opp_info::g_opponent.creationYear  = year;
                opp_info::g_opponent.creationMonth = month;

                log::debugf("[OPP] Account created: %u/%d\r\n", year, month);
            }

            // Release v4 only if different from v3 (same ptr = no AddRef was done)
            if (v4 != v3) {
                uint64_t relFn = *(uint64_t*)(v4_vtbl + 0x8);
                if (is_valid_ptr(relFn)) {
                    typedef void(__fastcall* ReleaseFn)(__int64);
                    log::debugf("[OPP] extract_stats: RELEASE fn=%p rcx=%p (v4!=v3)\r\n", (void*)relFn, (void*)v4);
                    spoof_call(reinterpret_cast<ReleaseFn>(relFn), (__int64)v4);
                    log::to_file("[OPP] extract_stats: RELEASE done\r\n");
                }
            } else {
                log::to_file("[OPP] extract_stats: SKIP release (v4==v3, no AddRef)\r\n");
            }

            log::to_file("[OPP] extract_stats: DONE\r\n");

        } __except (1) {
            log::to_file("[OPP] extract_stats: EXCEPTION\r\n");
        }
    }

    // ── IDK Hook Detour (creation date — all match types) ────────────
    //
    // Fires for every match type incl. FUT Champions.
    // Reads a1+dataOffset → +0x88 → GetSeasonInfo → creation year/month.

    extern "C" unsigned long long IdkHookDetour(
        void* ctx_raw,
        unsigned long long a1,
        unsigned long long /*a2*/)
    {
        log::debugf("[OPP-IDK] Detour fired, a1=%p\r\n", (void*)a1);

        if (!g_seasonInfoFn || !a1 || !g_idkDataOffset) return 0;
        if (!is_valid_ptr(a1) || !is_valid_ptr(a1 + g_idkDataOffset + 8)) {
            log::to_file("[OPP-IDK] BAIL: a1 ptr range invalid\r\n"); return 0;
        }

        __int64 v14 = *(__int64*)((uint8_t*)a1 + g_idkDataOffset);
        if (!is_valid_ptr((uintptr_t)v14) || !is_valid_ptr((uintptr_t)v14 + 0x90)) {
            log::to_file("[OPP-IDK] BAIL: v14 ptr range invalid\r\n"); return 0;
        }

        unsigned int v13 = *(unsigned int*)(v14 + 0x88);
        if (!v13) { log::to_file("[OPP-IDK] BAIL: v13=0, skip GetSeasonInfo\r\n"); return 0; }

        char v11[64] = {};
        typedef void(__fastcall* SeasonFn)(unsigned int, __int64);
        auto seasonFn = reinterpret_cast<SeasonFn>(g_seasonInfoFn);
        spoof_call(seasonFn, v13, reinterpret_cast<__int64>(v11));

        int month = *(int*)(v11 + 0x10);
        unsigned int year = *(unsigned int*)(v11 + 0x14);
        year += 0x76C;

        opp_info::g_opponent.creationYear  = year;
        opp_info::g_opponent.creationMonth = month;

        return 0; // passthrough to original
    }

    // ── EPT Hook Detour ─────────────────────────────────────────────
    //
    // Called by EPT stub when vtable[1] fires.
    // Signature matches EPT register context callback:
    //   ctx_raw  = register_context_t*
    //   a1       = original RCX
    //   a2       = original RDX (== 0x75AD when match found)

    extern "C" unsigned long long MatchFoundDetour(
        void* ctx_raw,
        unsigned long long a1,
        unsigned long long a2)
    {
        log::debugf(
            "[OPP] MatchFoundDetour: a1=%p a2=0x%X\r\n", (void*)a1, (unsigned int)a2);

        if ((unsigned int)a2 != 0x75AD)
            return 0;

        log::debug("[OPP] >>> MATCH FOUND (a2=0x75AD) <<<\r\n");

        // Clear previous data
        __stosb((unsigned char*)&opp_info::g_opponent, 0, sizeof(opp_info::g_opponent));

        // ── Step 1: Call getOpponentFunc_1 ──────────────────────────
        __try {
            typedef __int64(__fastcall* Fn1Type)();
            auto fn1 = reinterpret_cast<Fn1Type>(g_func1);

            log::debugf("[OPP] Calling func1 at %p\r\n", (void*)g_func1);

            __int64 v18 = spoof_call(fn1);

            log::debugf("[OPP] func1 returned v18=%p\r\n", (void*)v18);

            if (!v18) { log::debug("[OPP] v18 is NULL, aborting\r\n"); return 0; }

            // ── Step 2: get_object_result → dereference +0x838 ──────
            __int64 result2 = get_object_result();
            if (!result2) { log::debug("[OPP] result2 is NULL, aborting\r\n"); return 0; }

            log::debugf("[OPP] result2=%p, reading +0x838\r\n", (void*)result2);

            __int64 inner = *(__int64*)(result2 + 0x838);
            if (!inner) { log::debug("[OPP] result2+0x838 is NULL, aborting\r\n"); return 0; }

            log::debugf("[OPP] inner (result2+0x838)=%p\r\n", (void*)inner);

            // ── Step 3: Call getOpponentFunc_3(inner, v18) → v19 ────
            typedef __int64(__fastcall* Fn3Type)(__int64, __int64);
            auto fn3 = reinterpret_cast<Fn3Type>(g_func3);

            log::debugf("[OPP] Calling func3(%p, %p)\r\n", (void*)inner, (void*)v18);

            __int64 v19 = spoof_call(fn3, inner, v18);

            log::debugf("[OPP] func3 returned v19=%p\r\n", (void*)v19);

            if (!v19) { log::debug("[OPP] v19 is NULL, aborting\r\n"); return 0; }

            // ── v19 raw dump (first 0x130 bytes as DWORDs) ────────
            {
                log::debug("[OPP] v19 raw dump:\r\n");
                uint32_t* dw = reinterpret_cast<uint32_t*>(v19);
                for (int i = 0; i < 0x130 / 4; i += 4) {
                    log::debugf(
                        "  +0x%03X: %08X %08X %08X %08X\r\n",
                        i * 4, dw[i], dw[i+1], dw[i+2], dw[i+3]);
                }
                // Name + platform as strings
                char strBuf[80];
                safe_strcpy(strBuf, reinterpret_cast<const char*>(v19 + 0xF0), 32);
                log::debugf("  +0x0F0 (platform): %s\r\n", strBuf);
                safe_strcpy(strBuf, reinterpret_cast<const char*>(v19 + 0x110), 48);
                log::debugf("  +0x110 (name):     %s\r\n", strBuf);
            }

            // ── Step 4: Extract name, platform, IDs from v19 ────────
            safe_strcpy(opp_info::g_opponent.name,
                reinterpret_cast<const char*>(v19 + 0x110), sizeof(opp_info::g_opponent.name));

            safe_strcpy(opp_info::g_opponent.platform,
                reinterpret_cast<const char*>(v19 + 0xF0), sizeof(opp_info::g_opponent.platform));

            opp_info::g_opponent.personaId = *(uint64_t*)(v19 + 0x00);
            opp_info::g_opponent.nucleusId = *(uint64_t*)(v19 + 0x08);

            // Normalize platform string
            if (safe_strcmp(opp_info::g_opponent.platform, "cem_ea_id")) {
                opp_info::g_opponent.platform[0] = 'P';
                opp_info::g_opponent.platform[1] = 'C';
                opp_info::g_opponent.platform[2] = '\0';
            }

            log::debugf(
                "[OPP] Name: %s | Platform: %s | Persona: %llu | Nucleus: %llu\r\n",
                opp_info::g_opponent.name, opp_info::g_opponent.platform,
                opp_info::g_opponent.personaId, opp_info::g_opponent.nucleusId);

            // Grep-friendly match-boundary marker — matches FC26-Internal's convention
            // (hooks.cpp:1142 `[MatchFound] Oppponent Name : %s`). Use this line to
            // segment logs: anything before the last [MatchFound] belongs to a prior
            // session and can be discarded when analyzing the current match.
            log::debugf(
                "[MatchFound] Opponent Name : %s\r\n", opp_info::g_opponent.name);

            opp_info::g_opponent.valid = true;

        } __except (1) {
            log::debug("[OPP] EXCEPTION during opponent info extraction\r\n");
        }

        // ── Step 5: Match type + stats (toggleable — can crash for some users) ──
        if (opp_info::g_enableStats) {
            int matchType = getMatchType();
            {
                const char* mtName = "Unknown";
                if (matchType == 0x1B) mtName = "Classic Match";
                else if (matchType == 0x1E) mtName = "FUT Champions";
                else if (matchType == 0x22) mtName = "Division Rivals";

                log::debugf(
                    "[OPP] MatchType: %d (0x%X) = %s\r\n", matchType, matchType, mtName);
            }

            if (matchType == MT_FUTCHAMPS) {
                log::debug("[OPP] FUT Champions — skipping stats\r\n");
            } else {
                extract_stats();
            }
        }

        toast::Show(toast::Type::Info, opp_info::g_opponent.name[0]
            ? opp_info::g_opponent.name : "Opponent found");

        log::debug("[OPP] MatchFoundDetour complete, passing through\r\n");
        return 0; // passthrough to original
    }
}

// ── Public API ──────────────────────────────────────────────────────

bool opp_info::Init(void* gameBase, unsigned long gameSize)
{
    log::debug("[OPP] Init: scanning patterns...\r\n");

    // 1. OnlineMatchmakingPreMatchController vtable (RIP-relative LEA)
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "48 8D 05 ? ? ? ? 48 89 01 48 8B D9 48 8D 05 ? ? ? ? 48 89 81 ? ? ? ? 74 73");
        if (m) {
            g_vtableBase = resolve_rip3_7((uintptr_t)m);
            log::debugf("[OPP] vtableBase: %p\r\n", (void*)g_vtableBase);
        } else {
            log::debug("[OPP] ERROR: vtable pattern not found\r\n");
        }
    }

    // 2. getOpponentFunc_1 (E8 call resolution)
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B F0 48 85 C0 74 ? E8 ? ? ? ? 48 8D 4C 24");
        if (m) {
            g_func1 = resolve_call_e8((uintptr_t)m);
            log::debugf("[OPP] func1: %p\r\n", (void*)g_func1);
        } else {
            log::debug("[OPP] ERROR: func1 pattern not found\r\n");
        }
    }

    // 3. getOpponentFunc_2 (E8 call resolution)
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "E8 ? ? ? ? 48 85 C0 74 ? 48 8B 10 48 8B C8 FF 92 ? ? ? ? 48 8B D8 48 8B 8B");
        if (m) {
            g_func2 = resolve_call_e8((uintptr_t)m);
            log::debugf("[OPP] func2: %p\r\n", (void*)g_func2);
        } else {
            log::debug("[OPP] ERROR: func2 pattern not found\r\n");
        }
    }

    // 4. getOpponentFunc_3 (E8 call resolution)
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "E8 ? ? ? ? EB 09 48 8D 56 78");
        if (m) {
            g_func3 = resolve_call_e8((uintptr_t)m);
            log::debugf("[OPP] func3: %p\r\n", (void*)g_func3);
        } else {
            log::debug("[OPP] ERROR: func3 pattern not found\r\n");
        }
    }

    // 5. getSeasonInfo (direct address)
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "40 53 48 83 EC ? 8B C1 48 8B DA");
        if (m) {
            g_seasonInfoFn = (uintptr_t)m;
            log::debugf("[OPP] seasonInfoFn: %p\r\n", (void*)g_seasonInfoFn);
        } else {
            log::debug("[OPP] WARNING: seasonInfo pattern not found (creation date unavailable)\r\n");
        }
    }

    // 6. testfunc_match (RIP-relative pointer)
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "48 8B 0D ? ? ? ? 48 8B 01 48 FF 60 ? CC CC 40 57");
        if (m) {
            g_testfuncMatch = resolve_rip3_7((uintptr_t)m);
            log::debugf("[OPP] testfuncMatch: %p\r\n", (void*)g_testfuncMatch);
        } else {
            log::debug("[OPP] WARNING: testfunc_match pattern not found (stats unavailable)\r\n");
        }
    }

    // 7. Match type magic value + vtable offset (dynamic from "mov edx, imm32")
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "BA ? ? ? ? 48 8B CE FF 90 ? ? ? ? 44 8B 44 24");
        if (m) {
            g_matchTypeMagic = *(uint32_t*)((uintptr_t)m + 1);    // imm32 after BA
            g_matchTypeVtOff = *(uint32_t*)((uintptr_t)m + 10);  // disp32 after FF 90 opcode
            log::debugf(
                "[OPP] matchTypeMagic: 0x%X  vtOff: 0x%X\r\n", g_matchTypeMagic, g_matchTypeVtOff);
        } else {
            log::debug("[OPP] WARNING: matchType pattern not found (FUT Champs guard disabled)\r\n");
        }
    }

    // 8. idk_hook vtable (creation date hook — fires for all match types)
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "48 8D 0D ? ? ? ? 48 8D 05 ? ? ? ? 48 89 43 ? 33 C0 89 43 ? 87 43 ? 48 8D 05 ? ? ? ? 48 89 0B 48 89 43 ? 48 8D 4B ? 48 8D 05 ? ? ? ? 48 89 43");
        if (m) {
            g_idkVtable = resolve_rip3_7((uintptr_t)m);
            log::debugf("[OPP] idkVtable: %p\r\n", (void*)g_idkVtable);
        } else {
            log::debug("[OPP] WARNING: idk_hook pattern not found (FUT Champs creation date unavailable)\r\n");
        }
    }

    // Read vtable slot 1 (MatchFound hook target)
    if (g_vtableBase) {
        __try {
            uintptr_t* vtable = reinterpret_cast<uintptr_t*>(g_vtableBase);
            g_targetFunc = vtable[1];
            log::debugf("[OPP] vtable[1] target: %p\r\n", (void*)g_targetFunc);
        } __except (1) {
            log::debug("[OPP] ERROR: cannot read vtable[1]\r\n");
            g_targetFunc = 0;
        }
    }

    // Dynamically find IDK function + vtable slot + data offset
    if (g_idkVtable && g_seasonInfoFn) {
        // Pattern scan for the IDK function prologue
        void* idkFunc = game::pattern_scan(gameBase, gameSize,
            "40 55 41 56 41 57 48 83 EC ? 48 8B A9 ? ? ? ? 4C 8B F9");
        if (idkFunc) {
            g_idkFuncAddr = (uintptr_t)idkFunc;

            // Read data offset from "48 8B A9 XX XX XX XX" (displacement at prologue+13)
            g_idkDataOffset = *(uint32_t*)((uintptr_t)idkFunc + 13);

            log::debugf("[OPP] idkFunc: %p  dataOffset: 0x%X\r\n",
                idkFunc, g_idkDataOffset);

            // Search vtable for this function pointer to find the slot
            __try {
                uintptr_t* vtable = reinterpret_cast<uintptr_t*>(g_idkVtable);
                for (int i = 360; i < 400; i++) {
                    if (vtable[i] == g_idkFuncAddr) {
                        g_idkSlot = i;
                        g_idkTargetFunc = vtable[i];
                        log::debugf("[OPP] idkVtable[%d] = %p (MATCH)\r\n",
                            i, (void*)g_idkTargetFunc);
                        break;
                    }
                }
                if (g_idkSlot < 0)
                    log::debug("[OPP] WARNING: IDK function not found in vtable[360..399]\r\n");
            } __except (1) {
                log::debug("[OPP] ERROR: exception scanning IDK vtable\r\n");
            }
        } else {
            log::debug("[OPP] WARNING: IDK prologue pattern not found\r\n");
        }
    }

    // Minimum requirement: vtable + func1/2/3
    g_initialized = g_vtableBase && g_targetFunc && g_func1 && g_func2 && g_func3;

    log::debugf(
        "[OPP] Init %s — vtbl:%p tgt:%p f1:%p f2:%p f3:%p season:%p match:%p idk:%p\r\n",
        g_initialized ? "OK" : "INCOMPLETE",
        (void*)g_vtableBase, (void*)g_targetFunc,
        (void*)g_func1, (void*)g_func2, (void*)g_func3,
        (void*)g_seasonInfoFn, (void*)g_testfuncMatch,
        (void*)g_idkTargetFunc);

    return g_initialized;
}

bool opp_info::InstallHook()
{
    if (!g_initialized || !g_targetFunc) {
        log::debug("[OPP] InstallHook: not initialized\r\n");
        return false;
    }

    if (g_hooked) {
        log::debug("[OPP] InstallHook: already installed\r\n");
        return true;
    }

    log::debug("[OPP] Installing EPT hook on matchmaking vtable[1]...\r\n");

    bool ok = ept::install_hook(g_hookParams,
        reinterpret_cast<unsigned char*>(g_targetFunc),
        (void*)&MatchFoundDetour, "MatchFound");

    if (ok) {
        g_hooked = true;
        log::debug("[OPP] EPT hook installed on matchmaking vtable[1]\r\n");
        toast::Show(toast::Type::Success, "Opponent Info hook active");
    } else {
        log::debug("[OPP] ERROR: EPT hook install FAILED\r\n");
        toast::Show(toast::Type::Error, "Opponent Info hook failed");
    }

    // IDK hook (creation date) DISABLED — the function was rewritten in the
    // latest update (iterates array + vtable calls instead of simple offset read).
    // The spoof_call to GetSeasonInfo with garbage v13 values crashes for some users.
    // Creation date still works for Rivals/Classic via extract_stats path (when re-enabled).

    return ok;
}

bool opp_info::IsReady()  { return g_initialized; }
bool opp_info::IsHooked() { return g_hooked; }
