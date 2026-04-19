// ai_control.cpp — AI vs Opps / Disable Opponent AI
//
// AI takeover, clean:
//   1. LOCAL: write primary_array[field_slot].field0 = 0xFFFFFFFF
//      → the game's input processor sees "AI marker" for this slot, stops
//        reading user input, and hands the slot to the native AI code.
//   2. PEER: dispatch opcode 0xA2CB726E {0xFFFFFFFF, field_slot, 1}
//      slot=0xFF, param7=0 — the peer writes the same AI marker into its
//      primary array → both sides in sync → no DataMismatch DC.
//
// No AFK machinery. No sub_1427F7640. No mode spoofing. No state-machine
// tricks. This is a plain controller reassignment, structurally identical
// to the "human-subbed-for-AI" events the game already produces during
// normal mid-match controller transitions.
//
// Field slot resolution (via game's own table, not sub_142329490):
//   alt       = match_ctx[+8]
//   idx       = *(match_ctx + (alt ? 0x4930 : 0x23D0))
//   token     = *(match_ctx + (alt ? 0x4938 : 0x23D8) + 16*idx)
//   The token IS the field slot for the human player on our side. Verified
//   via live bridge reads (token=4 while human was physically at field slot
//   4 per the kickoff broadcast packet [controller=0, field_slot=4, 1]).
//
// NoCRT-safe.

#include "ai_control.h"

#include <Windows.h>
#include "../offsets/offsets.h"
#include "../hook/network_hooks.h"
#include "sliders.h"
#include "rage.h"
#include "../spoof/spoof_call.hpp"
#include "../log/log.h"
#include "../log/fmt.h"
#include "../menu/toast.h"

// Kept for compatibility with the RouteGameMessage capture code.
volatile uint32_t ai_control::g_ourPlayerId      = 0;
volatile bool     ai_control::g_playerIdCaptured = false;
volatile bool     ai_control::g_kickoffArmed     = false;
volatile bool     ai_control::g_aiTakeoverFired  = false;

void ai_control::ResetCapture()
{
    g_playerIdCaptured = false;
    g_ourPlayerId      = 0;
    g_aiTakeoverFired  = false;
}

void ai_control::OnIncomingControlOpcode(uint32_t team, uint32_t player)
{
    if (g_playerIdCaptured) return;
    // Ignore sentinel broadcast rows (Team=0xFFFFFFFF) — these fire for all
    // 22 squad positions during pre-match lineup distribution and would
    // poison ourPlayerId. We only want the per-team captain-init packet
    // (Team=0 or Team=1 matching playerside).
    if (team == 0xFFFFFFFFu) return;
    if (team != (uint32_t)sliders::playerside) return;
    g_ourPlayerId      = player;
    g_playerIdCaptured = true;

    char buf[128];
    fmt::snprintf(buf, sizeof(buf),
        "[AI] captured ourPlayerId=%u (team=%u, playerside=%d)\r\n",
        player, team, sliders::playerside);
    log::debug(buf);
}

namespace
{
    uintptr_t GetMatchCtx()
    {
        if (!offsets::FnGetMatchCtx) return 0;
        typedef uintptr_t(__fastcall* get_ctx_fn)();
        get_ctx_fn fn = reinterpret_cast<get_ctx_fn>(offsets::FnGetMatchCtx);
        uintptr_t ctx = 0;
        __try { ctx = fn(); }
        __except (EXCEPTION_EXECUTE_HANDLER) { ctx = 0; }
        return ctx;
    }

    // Field slot of our local human on the pitch (0..21).
    uint32_t ResolveLocalFieldSlot(uintptr_t match_ctx)
    {
        uint32_t slot = 0xFFFFFFFF;
        __try {
            uint8_t   alt     = *reinterpret_cast<uint8_t*>(match_ctx + 8);
            uintptr_t idxOff  = alt ? 0x4930 : 0x23D0;
            uintptr_t tblBase = alt ? 0x4938 : 0x23D8;
            uint32_t active_idx = *reinterpret_cast<uint32_t*>(match_ctx + idxOff);
            slot = *reinterpret_cast<uint32_t*>(
                match_ctx + tblBase + 16ULL * (uintptr_t)active_idx);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        return slot;
    }

    // Only mutate / send while gameplay is actually live. Avoids forfeit
    // during loading / menu / cutscenes.
    bool IsInActiveGameplay(uintptr_t ctx)
    {
        if (!ctx) return false;
        __try {
            uint8_t active = *reinterpret_cast<uint8_t*>(ctx + 0x4AD0);
            return active != 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // Primary / secondary 22-slot array base. Each slot is 0x1A0 bytes.
    uintptr_t SlotArrayBase(uintptr_t ctx)
    {
        uint8_t alt = 0;
        __try { alt = *reinterpret_cast<uint8_t*>(ctx + 8); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return ctx + (alt ? 0x2570 : 0x10);
    }

    // Write the AI marker into the slot's controller field (controllerIndex at +0x08).
    bool WriteLocalAiMarker(uintptr_t ctx, uint32_t field_slot, uint32_t& savedCtrlId)
    {
        if (field_slot > 21) return false;
        __try {
            uintptr_t slotAddr = SlotArrayBase(ctx) + 0x1A0ULL * field_slot;
            uint32_t* pCtrlId  = reinterpret_cast<uint32_t*>(slotAddr + 0x08);
            savedCtrlId = *pCtrlId;
            *pCtrlId = 0xFFFFFFFF;
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // Recipe C sweep: 22-slot broadcast. Currently DORMANT — ApplyAiTakeoverFor
    // uses local-only path. Kept for reference / Step 3 fallback if local write
    // alone is insufficient.
    //
    // buf[2] = 0 (NOT 1). Noor's IDA analysis of sub_14281B970 + sub_14282B1D0
    // confirmed buf[2] is the team index field, not a server-auth flag. Sending
    // buf[2]=1 on a home-team (team=0) match corrupts the team assignment,
    // which triggers the server's team-balance watchdog → forced DC.
    //   For each slot 0..21:
    //     buf = { 0xFFFFFFFF, slot, 0x00000000 }
    //     size=12, slot_arg=0xFF, param7=0
    bool BroadcastFullAiSweep(int& sent_count)
    {
        sent_count = 0;
        uintptr_t rcx = 0; rage::dispatch_fn_t fn = nullptr;
        if (!rage::get_dispatch(rcx, fn)) return false;

        uint64_t opcode = 0xA2CB726E;

        hook::g_allow_attack_send = true;
        for (uint32_t slot = 0; slot < 22; ++slot) {
            uint32_t buffer[3] = { 0xFFFFFFFF, slot, 0x00000000 };
            __try {
                spoof_call(fn, (uint64_t)rcx,
                           (uint64_t*)&opcode, (uint64_t*)&opcode,
                           (void*)buffer, (int)12, (char)0xFF, (unsigned char)0);
                ++sent_count;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Keep going — partial sweep still better than nothing.
            }
        }
        hook::g_allow_attack_send = false;
        return sent_count > 0;
    }

    bool ApplyAiTakeoverFor(uintptr_t ctx, uint32_t field_slot, const char* label)
    {
        // STRATEGY PIVOT: drop the broadcast entirely. Every broadcast-based
        // approach (single-slot + full sweep, with or without state-sync)
        // causes peer-side rejection → DataMismatch or "lost connection" DC.
        //
        // This branch writes ONLY the local slot's controller_id to 0xFFFFFFFF
        // (AI marker) and sends NOTHING over the wire. The game's input
        // dispatcher reads slot+0x00 each frame; once it sees 0xFFFFFFFF, it
        // routes our slot to the built-in AI driver. From the peer's view,
        // our physics broadcasts (0x90F87271) continue unchanged — they just
        // carry AI-driven positions. Diego's analysis confirmed the peer
        // stores raw positions without prediction, so hash stays consistent.
        //
        // If this still DCs, the peer-side timeout is the issue (they expect
        // certain packets we're no longer sending), or Javelin detected the
        // local write itself. Both are investigation hooks for next iteration.
        uint32_t prevCtrl = 0;
        bool localOk = WriteLocalAiMarker(ctx, field_slot, prevCtrl);

        char buf[192];
        fmt::snprintf(buf, sizeof(buf),
            "[AI] %s field_slot=%u prevCtrl=%08X localOk=%d (LOCAL-ONLY, no broadcast)\r\n",
            label, field_slot, prevCtrl, localOk ? 1 : 0);
        log::debug(buf);
        return localOk;
    }

    // Resolve our team_token via the game's per-round table.
    //   match_ctx[+8]       = alt/side flag (0=primary path, 1=secondary)
    //   match_ctx[+0x23D0]  (home) / +0x4930 (away) = DWORD index into the
    //                         team-token table
    //   match_ctx[+0x23D8]  (home) / +0x4938 (away) = base of 16B-stride
    //                         table; [baseIdx*16 + 0] holds the team_token
    // FnAiSlotResolver(match_ctx, team_token) returns the field slot index
    // [0..21] of our captain. Single slot. No stride.
    bool ResolveOurCaptainSlot(uintptr_t match_ctx, uint32_t& out_slot, uint32_t& out_token)
    {
        out_slot  = 0xFFFFFFFFu;
        out_token = 0xFFFFFFFFu;
        if (!offsets::FnAiSlotResolver) return false;
        __try {
            uint8_t   alt     = *reinterpret_cast<uint8_t*>(match_ctx + 8);
            uintptr_t idxOff  = alt ? 0x4930 : 0x23D0;
            uintptr_t tblBase = alt ? 0x4938 : 0x23D8;
            uint32_t  headIdx = *reinterpret_cast<uint32_t*>(match_ctx + idxOff);
            out_token = *reinterpret_cast<uint32_t*>(
                match_ctx + tblBase + 16ULL * (uintptr_t)headIdx);
        } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

        if (out_token == 0xFFFFFFFFu) return false;

        typedef uint32_t(__fastcall* slot_resolver_fn)(uintptr_t, uint32_t);
        slot_resolver_fn fn = reinterpret_cast<slot_resolver_fn>(offsets::FnAiSlotResolver);
        uint32_t s = 0xFFFFFFFFu;
        __try { s = fn(match_ctx, out_token); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        if (s > 21u) return false;
        out_slot = s;
        return true;
    }

    // Option A — local matchData write. No network emit, no state-machine
    // invocation. Replicates exactly what the in-game AI-takeover effectively
    // leaves behind in the 22-slot player table, derived from IDA RE of the
    // incoming 0xA2CB726E handler sub_14281A4F0:
    //
    //   matchData layout (ctx = return of FnGetMatchCtx = sub_142805590):
    //     +0x10 + k*0x1A0  = player entry k  (22 entries, 0x1A0 stride)
    //         +0x08  u32   teamSide          (0=home, 1=away)
    //         +0x178 u32   Slot              (controller idx; 0xFFFFFFFF=AI)
    //         +0x17C u32   modeflag
    //         +0x198 u32   modeflag mirror
    //     +0x23D4          u32   local_teamSide  (our side)
    //     +0x2550          u32   num_unassigned_slots
    //     +0x5198          u8[22]  controller-active bitmap indexed by
    //                              teamSide*0xB + slot_0..10
    //
    // Only touches our 11 entries. Does NOT modify Team(+0x00) — that field
    // belongs to server-reconciled state and writing 0xFFFFFFFF trips the
    // peer's team-balance watchdog.
    bool ApplyMySideAiMarkers(uintptr_t ctx, const char* label)
    {
        if (!ctx) return false;

        uint32_t mySide   = 0xFFFFFFFFu;
        uint32_t hits     = 0;
        uint32_t crashes  = 0;
        __try {
            mySide = *reinterpret_cast<uint32_t*>(ctx + 0x23D4);
        } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        if (mySide != 0 && mySide != 1) {
            char buf[128];
            fmt::snprintf(buf, sizeof(buf),
                "[AI] %s mySide=%u out of range — abort\r\n", label, mySide);
            log::debug(buf);
            return false;
        }

        uintptr_t tableBase = ctx + 0x10;
        for (uint32_t k = 0; k < 22; ++k) {
            uintptr_t entry = tableBase + 0x1A0ULL * k;
            __try {
                uint32_t side = *reinterpret_cast<uint32_t*>(entry + 0x08);
                if (side != mySide) continue;
                *reinterpret_cast<uint32_t*>(entry + 0x178) = 0xFFFFFFFFu;
                *reinterpret_cast<uint32_t*>(entry + 0x17C) = 0;
                *reinterpret_cast<uint32_t*>(entry + 0x198) = 0;
                ++hits;
            } __except (EXCEPTION_EXECUTE_HANDLER) { ++crashes; }
        }

        // Clear active-controller bitmap for our 11 slot positions.
        __try {
            uint8_t* bitmap = reinterpret_cast<uint8_t*>(ctx + 0x5198);
            for (uint32_t s = 0; s < 11; ++s)
                bitmap[mySide * 0xB + s] = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) { ++crashes; }

        // Bump unassigned counter to match the handler's bookkeeping.
        __try {
            (*reinterpret_cast<uint32_t*>(ctx + 0x2550)) += 1;
        } __except (EXCEPTION_EXECUTE_HANDLER) { ++crashes; }

        char buf[192];
        fmt::snprintf(buf, sizeof(buf),
            "[AI] %s mySide=%u hits=%u crashes=%u (OptionA matchData-local)\r\n",
            label, mySide, hits, crashes);
        log::debug(buf);

        return hits > 0 && crashes == 0;
    }
}

bool ai_control::SendAiTakeover()
{
    // Restoration of the old working path:
    //   opcode = 0xA2CB726E (controller assignment)
    //   buf    = { 0xFFFFFFFF, ourPlayerId, 0 }     // 3 x u32, size = 12
    //   a6     = playerside (0 or 1)                // our team side
    //   a7     = 0
    // Single packet. No 22-slot sweep. No sub_1427FD810 call. No matchData
    // field writes. Just one emit via the game's own dispatcher vtable[9],
    // spoof-called so the call site looks legit.
    //
    // Known limitation: this desyncs after the first goal because the game
    // re-emits its own controller-assignment broadcast on kickoff reset,
    // overwriting our AI marker. Re-arming on kickoff-transitions is TODO —
    // get the basic takeover working again first, then layer the fix.

    if (g_aiTakeoverFired) return false;     // one-shot per match
    if (!g_kickoffArmed)   return false;     // arm after match-timer kickoff tx
    if (!g_playerIdCaptured) {
        // No captured ID yet — the game hasn't broadcast the initial
        // controller-assignment packet for our side. Nothing to target.
        return false;
    }

    uintptr_t rcx = 0; rage::dispatch_fn_t fn = nullptr;
    if (!rage::get_dispatch(rcx, fn)) {
        log::debug("[AI] dispatcher unresolved\r\n");
        return false;
    }

    uint64_t opcode = 0xA2CB726E;
    uint32_t buffer[3] = { 0xFFFFFFFFu, g_ourPlayerId, 0x00000000u };

    bool threw = false;
    hook::g_allow_attack_send = true;
    __try {
        spoof_call(fn, (uint64_t)rcx,
                   (uint64_t*)&opcode, (uint64_t*)&opcode,
                   (void*)buffer, (int)12,
                   (char)sliders::playerside, (unsigned char)0);
    } __except (EXCEPTION_EXECUTE_HANDLER) { threw = true; }
    hook::g_allow_attack_send = false;

    char buf[160];
    fmt::snprintf(buf, sizeof(buf),
        "[AI] takeover-self emit playerId=%u playerside=%d threw=%d\r\n",
        g_ourPlayerId, sliders::playerside, threw ? 1 : 0);
    log::debug(buf);

    if (threw) {
        toast::Show(toast::Type::Error, "AI: takeover threw");
        return false;
    }
    g_aiTakeoverFired = true;
    toast::Show(toast::Type::Success, "AI takeover armed");
    return true;
}

bool ai_control::SendDisableOpponentAi()
{
    // Disabled for now. Writing to an opponent slot without hooking the
    // peer's FnMismatchGate (impossible from our side) causes immediate
    // DataMismatch from the peer's validator. See AI_VS_OPP_FIX.md.
    // Menu toggle is still wired but does nothing until we have a safe
    // approach (e.g., server-authoritative AFK-takeover packet replay).
    return false;
}
