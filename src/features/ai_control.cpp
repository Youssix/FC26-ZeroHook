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
#include "../game/game.h"
#include "../log/log.h"
#include "../log/fmt.h"
#include "../menu/toast.h"

// Kept for compatibility with the RouteGameMessage capture code.
volatile uint32_t ai_control::g_ourPlayerId        = 0;
volatile bool     ai_control::g_playerIdCaptured   = false;
volatile bool     ai_control::g_kickoffArmed       = false;
volatile bool     ai_control::g_aiTakeoverFired    = false;
volatile bool     ai_control::g_deepHookAiTakeover = false;
volatile bool     ai_control::g_forceAfkPath       = false;

namespace
{
    // sub_14282BB00 at IDA 0x14282BB00 → game-base RVA 0x282BB00.
    // Inside the fast-path block:
    //   14282bf07: test r15b, r15b           (r15b holds v11 = matchCtx[0x2554])
    //   14282bf0a: jz   short loc_14282BF27   ← patch site (2 bytes: 74 1B)
    //   14282bf0c..14282bf1a: load args for sub_1427F7640
    //   14282bf1d: call sub_1427F7640        ← the takeover
    // Patch those 2 bytes to 90 90 so the jz becomes a no-op and every
    // time control reaches this block sub_1427F7640 is called with the
    // brain's own derived (matchCtx, slot, v34, v36) args.
    constexpr uintptr_t kForceAfkPathRva     = 0x282BF0AULL;
    constexpr unsigned char kOrigJzBytes[2]  = { 0x74, 0x1B };
    constexpr unsigned char kNopBytes[2]     = { 0x90, 0x90 };
    bool g_forceAfkPathInstalled = false;
}

void ai_control::ApplyForceAfkPath(bool enable)
{
    if (!offsets::GameBase) return;
    uintptr_t addr = reinterpret_cast<uintptr_t>(offsets::GameBase) + kForceAfkPathRva;

    if (enable && !g_forceAfkPathInstalled)
    {
        if (game::ept_patch(addr, kNopBytes, 2))
        {
            g_forceAfkPathInstalled = true;
            g_forceAfkPath          = true;
            char b[128];
            fmt::snprintf(b, sizeof(b),
                "[ForceAfkPath] ON  — ept_patch %p: 74 1B -> 90 90\r\n",
                (void*)addr);
            log::debug(b);
            toast::Show(toast::Type::Success, "Force AFK Path: ON");
        }
        else
        {
            log::debug("[ForceAfkPath] ept_patch(ON) FAILED\r\n");
            toast::Show(toast::Type::Error, "Force AFK Path: patch failed");
            g_forceAfkPath = false;
        }
    }
    else if (!enable && g_forceAfkPathInstalled)
    {
        if (game::ept_patch(addr, kOrigJzBytes, 2))
        {
            g_forceAfkPathInstalled = false;
            g_forceAfkPath          = false;
            char b[128];
            fmt::snprintf(b, sizeof(b),
                "[ForceAfkPath] OFF — ept_patch %p: 90 90 -> 74 1B\r\n",
                (void*)addr);
            log::debug(b);
            toast::Show(toast::Type::Info, "Force AFK Path: OFF");
        }
        else
        {
            log::debug("[ForceAfkPath] ept_patch(OFF) FAILED\r\n");
            toast::Show(toast::Type::Error, "Force AFK Path: restore failed");
            g_forceAfkPath = true;  // keep UI in sync with actual state
        }
    }
}

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
    // Definitive path (verified via full team RE of sub_142814760):
    //   For each slot on our team, call the game's own public TakeOver API
    //   sub_142814760(matchData, slotIdx). It writes slot+0x194=1 (the
    //   local-away bit the IsAway getter reads to route human-vs-AI), and
    //   conditionally slot+0x193=1, slot+0x177=1, then dispatches a network
    //   announce via sub_142814510(sessionId, 1, 0, 1) → vtable 0xC0 to the
    //   online subsystem. Peers accept it natively because it's the game's
    //   own AFK-takeover path.
    //
    // Previous attempts that FAILED:
    //   - slot+0x08 = 0xFFFFFFFF (corrupts teamSide, trips watchdog)
    //   - slot+0x178 = 0xFFFFFFFF (that's field-position index, not the AI
    //     flag; writing 0xFFFFFFFF just means "no pitch position")
    //   - 21-packet 0xA2CB726E burst (handler bails on Team=0xFF; 20 of 21
    //     packets are no-ops on peer; the packet is a reconciliation ping,
    //     not a state-change vehicle)
    //   - sub_1427FD810 direct call (match-end stats handler, unrelated)
    //
    // The right answer is one function call per slot.

    // PRE-KICKOFF trigger (fires during match-setup, not at kickoff whistle):
    //   Gate on g_playerIdCaptured only. That flag flips when the game
    //   broadcasts the initial 0xA2CB726E controller-init — which happens
    //   during match-setup, 6-25 seconds BEFORE the MatchTimer kickoff
    //   transition (per empirical log analysis). The previous gate on
    //   g_kickoffArmed fired AT kickoff — too late; the takeover state
    //   machine requires the slot table to be populated but not yet locked
    //   by the match-start barrier.
    //
    // Approach — belt-and-suspenders:
    //   1. Call sub_142814760(ctx, slot) for all 22 slots. The function
    //      internally filters by occupied-state; slots that don't match our
    //      team or aren't populated simply no-op. This removes the wrong
    //      external filter on slot+0x08 that caused sent=1 (most slots in
    //      1v1 don't carry our teamSide in that field).
    //   2. ALSO direct-write the IsAway trio (+0x194, +0x193, +0x177) on
    //      every slot whose Team field (+0x00) matches our mySide at
    //      +0x23D4 OR whose Team is 0xFFFFFFFF (unassigned). This ensures
    //      the local IsAway getter returns true even if sub_142814760's
    //      internal gate no-ops for that slot.

    if (g_aiTakeoverFired) return false;
    if (!g_playerIdCaptured) return false;  // pre-kickoff gate

    uintptr_t ctx = GetMatchCtx();
    if (!ctx) return false;

    uint32_t mySide = 0xFFFFFFFFu;
    __try { mySide = *reinterpret_cast<uint32_t*>(ctx + 0x23D4); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    int sent = 0;
    int threw = 0;
    int wrote = 0;

    // Step 1: call the game's TakeOver API for every slot index.
    if (offsets::FnTakeOverSlot) {
        typedef int64_t(__fastcall* takeover_fn)(uintptr_t, int);
        auto fn = reinterpret_cast<takeover_fn>(offsets::FnTakeOverSlot);
        for (int slot = 0; slot < 22; ++slot) {
            __try { fn(ctx, slot); ++sent; }
            __except (EXCEPTION_EXECUTE_HANDLER) { ++threw; }
        }
    }

    // Step 2: direct-write IsAway flags on slots we own or unassigned.
    uintptr_t tableBase = ctx + 0x10;
    for (int slot = 0; slot < 22; ++slot) {
        uintptr_t row = tableBase + 0x1A0ULL * static_cast<uintptr_t>(slot);
        __try {
            uint32_t team = *reinterpret_cast<uint32_t*>(row + 0x00);
            uint32_t side = *reinterpret_cast<uint32_t*>(row + 0x08);
            bool oursBySide = (side == mySide);
            bool oursByTeam = (team == mySide);
            bool unassigned = (team == 0xFFFFFFFFu);
            if (oursBySide || oursByTeam || unassigned) {
                *reinterpret_cast<uint8_t*>(row + 0x194) = 1;  // IsAway
                *reinterpret_cast<uint8_t*>(row + 0x193) = 1;  // keyboard-released
                *reinterpret_cast<uint8_t*>(row + 0x177) = 1;  // sibling
                ++wrote;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    char lb[192];
    fmt::snprintf(lb, sizeof(lb),
        "[AI] takeover-self PRE-KICKOFF mySide=%u fn_sent=%d fn_threw=%d direct_wrote=%d\r\n",
        mySide, sent, threw, wrote);
    log::debug(lb);

    if (sent == 0 && wrote == 0) {
        toast::Show(toast::Type::Error, "AI: takeover did nothing");
        return false;
    }
    g_aiTakeoverFired = true;
    toast::Show(toast::Type::Success, "AI takeover armed (pre-kickoff)");
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

bool ai_control::FireAiHeartbeat()
{
    // Payload guess based on working-tool log diff: 12 bytes, {0, 0, 1}.
    // Seen RetAddrs in working logs: 0x14218E1E9, 0x14291EDAD, 0x1450965A5,
    // 0x14566B436. All go through the same dispatcher we use for other
    // 0xA2CB726E-style sends. If the hypothesis holds, peer should see this
    // as "AI driver is now driving this slot — heartbeat".
    uintptr_t rcx = 0;
    rage::dispatch_fn_t fn = nullptr;
    if (!rage::get_dispatch(rcx, fn)) {
        log::debug("[AI] FireAiHeartbeat: get_dispatch failed\r\n");
        toast::Show(toast::Type::Error, "Heartbeat: dispatcher unavailable");
        return false;
    }

    uint64_t opcode = 0xE81D3B4CULL;
    uint32_t buffer[3] = { 0u, 0u, 1u };

    hook::g_allow_attack_send = true;
    bool ok = false;
    __try {
        spoof_call(fn, (uint64_t)rcx,
                   (uint64_t*)&opcode, (uint64_t*)&opcode,
                   (void*)buffer, (int)12, (char)0xFF, (unsigned char)0);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    hook::g_allow_attack_send = false;

    char b[128];
    fmt::snprintf(b, sizeof(b),
        "[AI] FireAiHeartbeat: opcode=0xE81D3B4C sz=12 buf={0,0,1} ok=%d\r\n",
        ok ? 1 : 0);
    log::debug(b);

    if (ok) toast::Show(toast::Type::Success, "Heartbeat 0xE81D3B4C sent");
    else    toast::Show(toast::Type::Error, "Heartbeat send threw");
    return ok;
}

bool ai_control::FireAiInputAnnounce()
{
    // Joystick/axis flavor from the working logs:
    //   0000803F 0000803F 01000000   =  {1.0f, 1.0f, 1u}
    // Matches the per-frame AI input announce shape. If the flat handshake
    // doesn't trip the peer's ACK, this is the other candidate — a
    // simulated "AI is actively driving with max stick" input.
    uintptr_t rcx = 0;
    rage::dispatch_fn_t fn = nullptr;
    if (!rage::get_dispatch(rcx, fn)) {
        log::debug("[AI] FireAiInputAnnounce: get_dispatch failed\r\n");
        toast::Show(toast::Type::Error, "InputAnnounce: dispatcher unavailable");
        return false;
    }

    uint64_t opcode = 0xE81D3B4CULL;
    struct { float x; float y; uint32_t flag; } payload = { 1.0f, 1.0f, 1u };

    hook::g_allow_attack_send = true;
    bool ok = false;
    __try {
        spoof_call(fn, (uint64_t)rcx,
                   (uint64_t*)&opcode, (uint64_t*)&opcode,
                   (void*)&payload, (int)12, (char)0xFF, (unsigned char)0);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    hook::g_allow_attack_send = false;

    char b[128];
    fmt::snprintf(b, sizeof(b),
        "[AI] FireAiInputAnnounce: opcode=0xE81D3B4C sz=12 buf={1.0f,1.0f,1} ok=%d\r\n",
        ok ? 1 : 0);
    log::debug(b);

    if (ok) toast::Show(toast::Type::Success, "InputAnnounce 0xE81D3B4C sent");
    else    toast::Show(toast::Type::Error, "InputAnnounce send threw");
    return ok;
}

namespace
{
    // Resolve (matchCtx, captainSlot, mySide) in one go. Returns true if all
    // three came back valid. Shared by the four A2CB726E test-fire helpers.
    bool ResolveCtxSlotSide(uintptr_t& ctx, uint32_t& slot, uint32_t& side)
    {
        ctx  = GetMatchCtx();
        if (!ctx) return false;
        slot = ResolveLocalFieldSlot(ctx);
        if (slot > 21) return false;
        side = 0xFFFFFFFFu;
        __try { side = *reinterpret_cast<uint32_t*>(ctx + 0x23D4); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return side == 0 || side == 1;
    }

    // Common send body. Returns true on clean call, false on any failure.
    bool SendA2CB(uint32_t team, uint32_t fieldSlot, const char* tag)
    {
        uintptr_t rcx = 0;
        rage::dispatch_fn_t fn = nullptr;
        if (!rage::get_dispatch(rcx, fn)) {
            char b[96];
            fmt::snprintf(b, sizeof(b),
                "[AI] %s: get_dispatch failed\r\n", tag);
            log::debug(b);
            toast::Show(toast::Type::Error, "A2CB: dispatcher unavailable");
            return false;
        }

        uint64_t opcode = 0xA2CB726EULL;
        uint32_t buffer[3] = { team, fieldSlot, 0u };

        hook::g_allow_attack_send = true;
        bool ok = false;
        __try {
            spoof_call(fn, (uint64_t)rcx,
                       (uint64_t*)&opcode, (uint64_t*)&opcode,
                       (void*)buffer, (int)12, (char)0xFF, (unsigned char)0);
            ok = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ok = false;
        }
        hook::g_allow_attack_send = false;

        char b[192];
        fmt::snprintf(b, sizeof(b),
            "[AI] %s: A2CB726E {%08X,%u,0} slot=0xFF param7=0 ok=%d\r\n",
            tag, team, fieldSlot, ok ? 1 : 0);
        log::debug(b);

        if (ok) toast::Show(toast::Type::Success, tag);
        else    toast::Show(toast::Type::Error, "A2CB send threw");
        return ok;
    }
}

bool ai_control::FireA2CBSentinel()
{
    uintptr_t ctx; uint32_t slot; uint32_t side;
    if (!ResolveCtxSlotSide(ctx, slot, side)) {
        toast::Show(toast::Type::Error, "A2CB sentinel: ctx/slot not ready");
        return false;
    }
    return SendA2CB(0xFFFFFFFFu, slot, "A2CB sentinel {FFFFFFFF,cap,0}");
}

bool ai_control::FireA2CBTeamHome()
{
    uintptr_t ctx; uint32_t slot; uint32_t side;
    if (!ResolveCtxSlotSide(ctx, slot, side)) {
        toast::Show(toast::Type::Error, "A2CB home: ctx/slot not ready");
        return false;
    }
    return SendA2CB(side, slot, "A2CB home {mySide,cap,0}");
}

bool ai_control::FireA2CBTeamOpp()
{
    uintptr_t ctx; uint32_t slot; uint32_t side;
    if (!ResolveCtxSlotSide(ctx, slot, side)) {
        toast::Show(toast::Type::Error, "A2CB opp: ctx/slot not ready");
        return false;
    }
    return SendA2CB(side ^ 1u, slot, "A2CB opp {oppSide,cap,0}");
}

bool ai_control::FireA2CBFullSweep()
{
    uintptr_t rcx = 0;
    rage::dispatch_fn_t fn = nullptr;
    if (!rage::get_dispatch(rcx, fn)) {
        toast::Show(toast::Type::Error, "A2CB sweep: dispatcher unavailable");
        return false;
    }

    uint64_t opcode = 0xA2CB726EULL;
    int sent = 0;
    int threw = 0;

    hook::g_allow_attack_send = true;
    for (uint32_t slot = 0; slot < 22; ++slot) {
        uint32_t buffer[3] = { 0xFFFFFFFFu, slot, 0u };
        __try {
            spoof_call(fn, (uint64_t)rcx,
                       (uint64_t*)&opcode, (uint64_t*)&opcode,
                       (void*)buffer, (int)12, (char)0xFF, (unsigned char)0);
            ++sent;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ++threw;
        }
    }
    hook::g_allow_attack_send = false;

    char b[160];
    fmt::snprintf(b, sizeof(b),
        "[AI] A2CB sweep: 22 slots, sent=%d threw=%d\r\n", sent, threw);
    log::debug(b);

    toast::Show(sent > 0 ? toast::Type::Success : toast::Type::Error,
                "A2CB 22-sweep fired");
    return sent > 0;
}
