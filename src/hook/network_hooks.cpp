#include "network_hooks.h"
#include "ept_hook.h"
#include "../offsets/offsets.h"
#include "../game/game.h"
#include "../features/sliders.h"
#include "../features/ai_difficulty.h"
#include "../features/ai_control.h"
#include "../features/settings.h"
#include "../features/proclub.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"

// Bypass flag — true only while WE are sending an attack opcode
volatile bool hook::g_allow_attack_send = false;
volatile bool hook::g_bypass_alt_tab = false;

namespace
{
    __declspec(align(4096)) ept::ept_hook_install_params_t g_netHookParams = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_altTabHookParams = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_matchTimerHookParams = {};

    // MatchTimer state — tracks previous frame's match clock to detect kickoff transition
    volatile float g_matchPrevTime = 0.0f;

    // ===== PlayerSide hook (EPT tiny patch on thunk) =====
    // Target is VMProtect'd — full 234-byte EPT stub corrupts computed jump targets.
    // Instead: EPT-patch the thunk's E9 displacement → code cave trampoline → our hook.
    typedef __int64 (__fastcall* PlayerSideFn_t)(__int64 a1, unsigned int a2, unsigned int a3);
    PlayerSideFn_t g_originalPlayerSide = nullptr;

    __int64 __fastcall HookedPlayerSide(__int64 a1, unsigned int a2, unsigned int a3)
    {
        if (a3 != 0xFFFFFFFF)
        {
            sliders::playerside = (int)a3;

            if (a3)
                toast::Show(toast::Type::Info, "Player is Away");
            else
                toast::Show(toast::Type::Info, "Player is Home");

            log::debug(a3 ? "[PlayerSide] Away\r\n" : "[PlayerSide] Home\r\n");
        }
        return g_originalPlayerSide(a1, a2, a3);
    }

    // ===== AltTabSender detour (block SystemOnAltTabMessage) =====
    // sub_145680200: no args, returns __int64
    // When bypass is on → skip original, return 0
    // When bypass is off → pass through to original
    extern "C" unsigned long long HookedAltTabSender(void* ctx)
    {
        if (hook::g_bypass_alt_tab) {
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;  // skip original
        }
        return 0;  // pass through
    }

    // ===== RouteGameMessage detour (crash/freeze protection) =====
    // EPT hook on vtable[9] of GameDispatchVTable.
    // return 1 + ctx->rax=0 = block (skip original, return 0)
    // return 0 = pass through (run original)
    extern "C" unsigned long long HookedRouteGameMessage(
        void* ctx,
        unsigned long long a1,
        unsigned int* a2,
        unsigned int* a3,
        int* a4,
        int a5,
        char a6,
        int a7)
    {
        if (!a2 || !a3) return 0;

        // Preserve the original RAX value so when we return 0 (pass through),
        // the stub sees RAX != 0 and executes the original handler.
        unsigned long long orig_rax = ((ept::register_context_t*)ctx)->rax;

        // ── Opcode census — runtime-gated by Settings > Trace Opcodes ─
        // Toggled live from the menu (settings::g_traceOpcodes). When false,
        // zero log I/O — the entire block is skipped without recompiling.
        // Filters out the 4 per-tick framing opcodes (~94% of traffic):
        //   0x5D4D4E4C  ball/score  0x38789943  timer sync
        //   0x90F87271  physics     0x8CD19B0C  heartbeat
        if (g_debugLog && settings::g_traceOpcodes)
        {
            unsigned int op_noise = *a2;
            bool is_noise =
                (op_noise == 0x5D4D4E4C) ||
                (op_noise == 0x38789943) ||
                (op_noise == 0x90F87271) ||
                (op_noise == 0x8CD19B0C);
            if (is_noise) goto after_op_diag;

            SYSTEMTIME st;
            GetLocalTime(&st);

            unsigned long long retAddr = 0;
            __try {
                unsigned long long rsp = ((ept::register_context_t*)ctx)->original_rsp;
                if (rsp) retAddr = *(unsigned long long*)rsp;
            } __except (1) {}

            unsigned int op2_log = *a2;
            unsigned int op3_log = *a3;

            char lb[2048];
            int pos = 0;

            pos += fmt::snprintf(lb + pos, sizeof(lb) - pos,
                "[%02d:%02d:%02d.%03d] ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

            if (op2_log == 0xA2CB726E || op3_log == 0xA2CB726E) {
                auto bd = reinterpret_cast<unsigned int*>(a4);
                unsigned int team   = (bd && a5 >= 4)  ? bd[0] : 0;
                unsigned int player = (bd && a5 >= 8)  ? bd[1] : 0;
                unsigned int b2     = (bd && a5 >= 12) ? bd[2] : 0;
                pos += fmt::snprintf(lb + pos, sizeof(lb) - pos,
                    "[Opcode 0xA2CB726E] Team=0x%08X Player=%u Slot=0x%02X Buf[2]=0x%08X Param7=%d RetAddr=%016llX\r\n",
                    team, player, (unsigned char)a6, b2, a7, retAddr);
            }
            else if (op2_log == 0x4E9507C9 || op3_log == 0x4E9507C9) {
                pos += fmt::snprintf(lb + pos, sizeof(lb) - pos,
                    "[Opcode 0x4E9507C9] sz=%d Slot=0x%02X Param7=%d RetAddr=%016llX\r\n",
                    a5, (unsigned char)a6, a7, retAddr);
            }
            else {
                pos += fmt::snprintf(lb + pos, sizeof(lb) - pos,
                    "[Opcode 0x%08X] a3=0x%08X sz=%d Slot=0x%02X Param7=%d RetAddr=%016llX",
                    op2_log, op3_log, a5, (unsigned char)a6, a7, retAddr);

                if (a4 && a5 > 0) {
                    int dump = a5 > 128 ? 128 : a5;
                    pos += fmt::snprintf(lb + pos, sizeof(lb) - pos, " buf[%d]=", dump);
                    unsigned char* bytes = (unsigned char*)a4;
                    __try {
                        for (int i = 0; i < dump && pos + 4 < (int)sizeof(lb); i++) {
                            pos += fmt::snprintf(lb + pos, sizeof(lb) - pos,
                                "%02X%s", bytes[i],
                                ((i & 3) == 3 && i != dump - 1) ? " " : "");
                        }
                    } __except (1) {
                        pos += fmt::snprintf(lb + pos, sizeof(lb) - pos, "<EX>");
                    }
                }
                pos += fmt::snprintf(lb + pos, sizeof(lb) - pos, "\r\n");
            }

            log::debug(lb);
        }
    after_op_diag:;

        // ── 0xA2CB726E (controller/AI opcode) — capture ourPlayerId ──
        // When game broadcasts controller assignments, buf[0]=team, buf[1]=player.
        // If team matches our side, we capture the player id for the AI takeover
        // cheater-signature (4-packet attack — see ai_control.cpp).
        {
            unsigned int op2_peek = *a2;
            unsigned int op3_peek = *a3;
            if ((op2_peek == 0xA2CB726E || op3_peek == 0xA2CB726E)
                && !hook::g_allow_attack_send
                && a4)
            {
                __try {
                    unsigned int* bd = reinterpret_cast<unsigned int*>(a4);
                    ai_control::OnIncomingControlOpcode(bd[0], bd[1]);
                } __except (1) {}
            }
        }

        // If WE are sending an attack, let it through — don't block ourselves
        if (hook::g_allow_attack_send) return 0;

        unsigned int op2 = *a2;
        unsigned int op3 = *a3;

        // ── Crash protection ──────────────────────────────────────────

        // Large buffer crash (opcode 0x6392FF71)
        if (op2 == 0x6392FF71 && a5 > 256) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::debug("[PROTECT] Blocked crash 0x6392FF71 (large buf)\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // Known crash opcodes (a2)
        if (op2 == 0x2D1FDF90 || op2 == 0x9B142841 || op2 == 0x75879024 ||
            op2 == 0xF313C005 || op2 == 0x399143E7) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::debug("[PROTECT] Blocked crash opcode\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0x5D4D4E4C with large buffer
        if (op2 == 0x5D4D4E4C && a5 > 64 && a4 != 0) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::debug("[PROTECT] Blocked crash 0x5D4D4E4C\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // Combo crashes (a2+a3 or a3 alone)
        if ((op2 == 0x809A6BC4 && op3 == 0x809A6BC4) ||
            op3 == 0xF501C37E || op3 == 0x5CB533F5 ||
            op3 == 0x2480F3C1 || op3 == 0xF30B99EF) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::debug("[PROTECT] Blocked crash combo\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0x82E9A020 duplicate with a4 > 1
        if (a4 && op2 == 0x82E9A020 && op3 == 0x82E9A020 && (unsigned int)*a4 > 1) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::debug("[PROTECT] Blocked crash 0x82E9A020\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // a5 == 0x96 crash
        if (a5 == 0x96) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::debug("[PROTECT] Blocked crash a5==0x96\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // a4 == 0xFFFFFFFF crash variants
        if (a4 && *a4 == (int)0xFFFFFFFF &&
            (op3 == 0x76A8609D || op3 == 0xFEBDCA3D || op3 == 0x8904984F)) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::debug("[PROTECT] Blocked crash (a4=FFFFFFFF)\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // ── Freeze protection ─────────────────────────────────────────

        // 0x9774D53D (high confidence freeze)
        if (op2 == 0x9774D53D || op3 == 0x9774D53D) {
            toast::Show(toast::Type::Error, "Blocked freeze from opponent");
            log::debug("[PROTECT] Blocked freeze 0x9774D53D\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0x406CE419 (pause_op_game freeze)
        if (op2 == 0x406CE419 || op3 == 0x406CE419) {
            toast::Show(toast::Type::Error, "Blocked freeze from opponent");
            log::debug("[PROTECT] Blocked freeze 0x406CE419\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0xA477B52B (Freeze 2)
        if (op2 == 0xA477B52B || op3 == 0xA477B52B) {
            toast::Show(toast::Type::Error, "Blocked freeze from opponent");
            log::debug("[PROTECT] Blocked freeze 0xA477B52B\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0xE0A38D91 freeze (a5=1, a6=-1, a4[0]=0xFF)
        if ((op2 == 0xE0A38D91 || op3 == 0xE0A38D91) &&
            a5 == 1 && a6 == -1 && a4 && *reinterpret_cast<unsigned char*>(a4) == 0xFF) {
            toast::Show(toast::Type::Error, "Blocked freeze from opponent");
            log::debug("[PROTECT] Blocked freeze 0xE0A38D91\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // Pass through: restore original RAX so stub sees non-zero and runs original
        ((ept::register_context_t*)ctx)->rax = orig_rax;
        return 0;  // pass through to original
    }
}

void hook::install_network_hooks()
{
    if (offsets::FnRouteGameMessage)
    {
        ept::install_hook(g_netHookParams,
            (unsigned char*)offsets::FnRouteGameMessage,
            (void*)&HookedRouteGameMessage, "RouteGameMessage");
        log::debug("[ZeroHook] RouteGameMessage hooked (crash/freeze protection)\r\n");
    }
    else
    {
        log::debug("[ZeroHook] WARNING: RouteGameMessage not found, protection disabled\r\n");
    }
}

void hook::install_alttab_hook()
{
    if (offsets::FnAltTabSender)
    {
        ept::install_hook(g_altTabHookParams,
            (unsigned char*)offsets::FnAltTabSender,
            (void*)&HookedAltTabSender, "AltTabSender");
        log::debug("[ZeroHook] AltTabSender hooked\r\n");
    }
    else
    {
        log::debug("[ZeroHook] WARNING: AltTabSender not found\r\n");
    }
}

// ===== MatchTimer EPT detour =====
// Hooks vtable[1] of the match timer object. Fires opcodes at kickoff
// (prev_time <= 0 && current_time > 0). Always passes through to the original.
//
// Signature: __int64 __fastcall MatchTimer(__int64 a1, __int64 a2)
//   a1 + 0xBC8  → pointer to timer instance
//   instance + 0x24 (float) → current match time in seconds
// ── Per-thread reentry guard ──────────────────────────────────────────
// If spoof_call or any downstream code touches another EPT-hooked page and
// that page maps back to MatchTimer (directly or transitively), we would
// re-enter this handler with our partially-updated state. On the wrong CPU
// microcode, nested EPT exits can also corrupt the hypervisor's internal
// state → PC freeze/restart. We bail out hard on reentry.
static thread_local unsigned int tl_matchTimerDepth = 0;

// Tick heartbeat — 1-in-N sampled, never per-frame. Used to tell "hook
// never fired" from "hook fired normally then hung" in post-mortem logs.
static volatile unsigned long long g_matchTimerTickCount = 0;
static volatile unsigned long long g_matchTimerReentryCount = 0;

extern "C" unsigned long long HookedMatchTimer(
    void* ctx,
    unsigned long long a1,
    unsigned long long /*a2*/)
{
    (void)ctx;

    // ── Reentry guard (H3 from investigation) ────────────────────────
    if (tl_matchTimerDepth != 0)
    {
        g_matchTimerReentryCount++;
        return 0;  // pass through, touch nothing else
    }
    tl_matchTimerDepth = 1;

    if (!a1) { tl_matchTimerDepth = 0; return 0; }

    // Rate-limited tick heartbeat — once every 600 entries (~10s at 60Hz).
    // Cheap atomic inc, no FlushFileBuffers.
    unsigned long long tick = ++g_matchTimerTickCount;
    if ((tick % 600) == 1)
    {
        log::debugf(
            "[MatchTimer] heartbeat tick=%llu tid=%u\r\n",
            tick, (unsigned)GetCurrentThreadId());
    }

    __try {
        uintptr_t instance = *reinterpret_cast<uintptr_t*>(a1 + 0xBC8);
        if (!instance) { tl_matchTimerDepth = 0; return 0; }

        float current_time = *reinterpret_cast<float*>(instance + 0x24);
        float prev_time    = g_matchPrevTime;

        if (prev_time <= 0.0f && current_time > 0.0f)
        {
            // Kickoff frame — condition is inherently one-shot per match.

            // NOTE: %.4f is not supported by fmt::vsnprintf; fall back to raw bits
            log::debugf(
                "[MatchTimer] KICKOFF tid=%u tick=%llu prev_bits=0x%08X cur_bits=0x%08X\r\n",
                (unsigned)GetCurrentThreadId(), tick,
                *(unsigned int*)&prev_time, *(unsigned int*)&current_time);

            ai_control::ResetCapture();  // next 0xA2CB726E broadcast refreshes ourPlayerId

            // Arm the AI-takeover path immediately. The old 3-second dwell
            // was nonsense — the cheat fires inside +0..+2s post-kickoff and
            // our own one-shot latch prevents spam. Arming at the transition
            // frame matches the cheat's observed window.
            ai_control::g_kickoffArmed = true;

#ifndef STANDARD_BUILD
            if (ai_difficulty::g_localLegendary)
            {
                ai_difficulty::send_local_legendary();
            }
            if (ai_difficulty::g_opponentBeginner)
            {
                ai_difficulty::send_opponent_beginner();
            }
#endif
        }
        else if (prev_time > 0.0f && current_time <= 0.0f)
        {
            // Match ended / timer reset — disarm + clear one-shot so next
            // match starts clean.
            ai_control::g_kickoffArmed    = false;
            ai_control::g_aiTakeoverFired = false;
            ai_control::ResetCapture();  // clear ourPlayerId so next match's broadcast refreshes it
            log::debug("[MatchTimer] match ended — g_kickoffArmed=false\r\n");
        }

        g_matchPrevTime = current_time;
    }
    __except (1) {
        // Swallow — never break the game's match timer
    }

    tl_matchTimerDepth = 0;
    return 0;  // always pass through
}

void hook::install_match_timer_hook()
{
    if (!offsets::FnMatchTimer)
    {
        log::debug("[ZeroHook] WARNING: MatchTimer not found, AI difficulty trigger disabled\r\n");
        return;
    }

    // ── Install-time diagnostics ──────────────────────────────────────
    // Primary hypothesis for client-side freeze/restart: pattern scan
    // matched a similar-but-wrong code site on some game builds, so
    // FnMatchTimer points at a critical function whose EPT hook destabilizes
    // the hypervisor. Dump everything we need to tell that apart from a
    // healthy resolve.
    uintptr_t fnAddr   = (uintptr_t)offsets::FnMatchTimer;
    uintptr_t vtAddr   = offsets::MatchTimerVTable;
    uintptr_t gameBase = (uintptr_t)offsets::GameBase;
    uintptr_t gameEnd  = gameBase + (uintptr_t)offsets::GameSize;
    bool fnInModule    = (fnAddr >= gameBase && fnAddr < gameEnd);
    bool vtInModule    = (vtAddr >= gameBase && vtAddr < gameEnd);

    log::debugf(
        "[MatchTimer] vtable=%p (inModule=%d) FnMatchTimer=%p (inModule=%d) gameBase=%p size=0x%lX\r\n",
        (void*)vtAddr, vtInModule ? 1 : 0,
        (void*)fnAddr, fnInModule ? 1 : 0,
        (void*)gameBase, offsets::GameSize);

    // Prologue bytes — 32 bytes. If this looks nothing like a normal
    // function prologue (no push rbp / sub rsp / mov rax,... / push rbx),
    // the pattern scan hit garbage and we should NOT install.
    if (fnInModule)
    {
        unsigned char prologue[32] = {};
        __try {
            for (int i = 0; i < 32; i++)
                prologue[i] = ((unsigned char*)fnAddr)[i];
        } __except (1) {
            log::debug("[MatchTimer] EXCEPTION reading prologue — aborting hook install\r\n");
            return;
        }

        if (g_debugLog) {
            char buf[512];
            int pos = fmt::snprintf(buf, sizeof(buf), "[MatchTimer] prologue:");
            for (int i = 0; i < 32 && pos + 4 < (int)sizeof(buf); i++)
                pos += fmt::snprintf(buf + pos, sizeof(buf) - pos, " %02X", prologue[i]);
            pos += fmt::snprintf(buf + pos, sizeof(buf) - pos, "\r\n");
            log::debug(buf);
        }
    }
    else
    {
        log::debug("[MatchTimer] WARNING: FnMatchTimer is OUTSIDE game module — pattern scan likely false-positive. Aborting install to prevent hypervisor corruption.\r\n");
        return;
    }

    bool ok = ept::install_hook(g_matchTimerHookParams,
        (unsigned char*)offsets::FnMatchTimer,
        (void*)&HookedMatchTimer, "MatchTimer");
    log::debugf(
        "[ZeroHook] MatchTimer hook install returned %d\r\n", ok ? 1 : 0);
}

void hook::install_playerside_hook()
{
    // EPT split hook: patch the thunk's E9 displacement to redirect to a
    // code cave trampoline. Execute view has patched bytes, read view shows
    // original — invisible to integrity checks. Uses CMD_EPT_PATCH_BYTES.
    if (!offsets::FnPlayerSide)
    {
        log::debug("[ZeroHook] WARNING: PlayerSide not found\r\n");
        return;
    }

    unsigned char* target = (unsigned char*)offsets::FnPlayerSide;

    // Follow E9/NOP chain, find the LAST thunk before the real (VMProtect'd) function
    unsigned char* patchE9 = nullptr;
    uintptr_t originalTarget = 0;

    for (int i = 0; i < 8; i++)
    {
        if (target[0] == 0x48 && target[1] == 0x8D && target[2] == 0x24 && target[3] == 0x24)
            target += 4;

        if (target[0] == 0xE9)
        {
            int32_t rel = *(int32_t*)(target + 1);
            unsigned char* next = target + 5 + rel;

            // Peek ahead: is next another thunk or the real function?
            unsigned char* peek = next;
            if (peek[0] == 0x48 && peek[1] == 0x8D && peek[2] == 0x24 && peek[3] == 0x24)
                peek += 4;

            if (peek[0] == 0xE9)
            {
                target = next;  // another thunk, keep following
                continue;
            }
            else
            {
                patchE9 = target;          // this E9 jumps to the real function
                originalTarget = (uintptr_t)next;
                break;
            }
        }
        else
            break;
    }

    if (!patchE9 || !originalTarget)
    {
        log::debug("[ZeroHook] WARNING: PlayerSide thunk chain not resolved\r\n");
        return;
    }

    log::debugf("[ZeroHook] PlayerSide patchE9=%p originalTarget=%p\r\n",
        patchE9, (void*)originalTarget);

    // Find a code cave (14+ padding bytes) within the game module
    unsigned char* cave = (unsigned char*)game::find_code_cave(
        offsets::GameBase, offsets::GameSize, 14, 12);

    if (!cave)
    {
        log::debug("[ZeroHook] WARNING: No code cave found for PlayerSide\r\n");
        return;
    }

    intptr_t caveDist = (intptr_t)cave - (intptr_t)(patchE9 + 5);
    if (caveDist > 0x7FFFFFFFL || caveDist < -(intptr_t)0x7FFFFFFFL)
    {
        log::debug("[ZeroHook] WARNING: Cave too far for rel32\r\n");
        return;
    }

    log::debugf("[ZeroHook] PlayerSide cave=%p dist=%llX\r\n",
        cave, (unsigned long long)caveDist);

    // Build 12-byte trampoline: mov rax, <hook>; jmp rax
    unsigned long long hookAddr = (unsigned long long)&HookedPlayerSide;
    unsigned char trampoline[12];
    trampoline[0] = 0x48;
    trampoline[1] = 0xB8;
    for (int i = 0; i < 8; i++)
        trampoline[2 + i] = ((unsigned char*)&hookAddr)[i];
    trampoline[10] = 0xFF;
    trampoline[11] = 0xE0;

    if (!game::ept_patch((uintptr_t)cave, trampoline, 12))
    {
        log::debug("[ZeroHook] WARNING: EPT patch cave failed\r\n");
        return;
    }
    log::debug("[ZeroHook] PlayerSide cave trampoline EPT-patched\r\n");

    // EPT patch the thunk: redirect E9 displacement to cave
    int newRel = (int)((long long)cave - (long long)(patchE9 + 5));
    unsigned char relBytes[4];
    for (int i = 0; i < 4; i++)
        relBytes[i] = ((unsigned char*)&newRel)[i];

    if (game::ept_patch((uintptr_t)(patchE9 + 1), relBytes, 4))
    {
        g_originalPlayerSide = (PlayerSideFn_t)originalTarget;
        log::debug("[ZeroHook] PlayerSide EPT hook installed (thunk + cave patched)\r\n");
    }
    else
    {
        log::debug("[ZeroHook] WARNING: EPT patch thunk failed\r\n");
    }
}

// ===== EAID Spoofer hook (EPT full-context hook via ept::install_hook) =====
// Function: unsigned char* __fastcall fn(unsigned char* a1)
// Original: fetches EAID from game structs → writes to a1+0x78 → returns a1+0x78
// Hook: if spoof ON → writes custom string to a1+0x78, sets rax=a1+0x78, skips original
//       if spoof OFF → passes through to original
namespace
{
    __declspec(align(4096)) ept::ept_hook_install_params_t g_eaidHookParams = {};

    extern "C" unsigned long long HookedEAID(void* ctx)
    {
        if (proclub::g_spoofEAID && proclub::g_spoofEAIDText[0])
        {
            auto* regs = (ept::register_context_t*)ctx;
            unsigned char* a1 = (unsigned char*)regs->rcx;
            if (!a1) return 0;  // pass through if game passes null

            constexpr int EAID_REGION = 0x15; // 21 bytes (0x8D - 0x78)
            __stosb(a1 + 0x78, 0, EAID_REGION);

            const char* src = proclub::g_spoofEAIDText;
            int len = 0;
            while (len < EAID_REGION && src[len]) len++;
            __movsb(a1 + 0x78, (const unsigned char*)src, len);

            regs->rax = (unsigned long long)(a1 + 0x78);
            return 1;  // skip original
        }
        return 0;  // pass through to original
    }
}

void hook::install_eaid_hook()
{
    if (!offsets::FnEAID)
    {
        log::debug("[ZeroHook] WARNING: EAID function not found\r\n");
        return;
    }

    ept::install_hook(g_eaidHookParams,
        (unsigned char*)offsets::FnEAID,
        (void*)&HookedEAID, "EAID");
    log::debug("[ZeroHook] EAID hooked\r\n");
}
