#include "network_hooks.h"
#include "ept_hook.h"
#include "../offsets/offsets.h"
#include "../features/sliders.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"

// Bypass flag — true only while WE are sending an attack opcode
volatile bool hook::g_allow_attack_send = false;
volatile bool hook::g_bypass_alt_tab = false;

namespace
{
    __declspec(align(4096)) ept::ept_hook_install_params_t g_netHookParams = {};

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

            log::to_file(a3 ? "[PlayerSide] Away\r\n" : "[PlayerSide] Home\r\n");
        }
        return g_originalPlayerSide(a1, a2, a3);
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

        // If WE are sending an attack, let it through — don't block ourselves
        if (hook::g_allow_attack_send) return 0;

        unsigned int op2 = *a2;
        unsigned int op3 = *a3;

        // ── Alt Tab bypass ──────────────────────────────────────────
        if (hook::g_bypass_alt_tab && op2 == 0x6D0D4E53) return 0;

        // ── Crash protection ──────────────────────────────────────────

        // Large buffer crash (opcode 0x6392FF71)
        if (op2 == 0x6392FF71 && a5 > 256) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::to_file("[PROTECT] Blocked crash 0x6392FF71 (large buf)\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // Known crash opcodes (a2)
        if (op2 == 0x2D1FDF90 || op2 == 0x9B142841 || op2 == 0x75879024 ||
            op2 == 0xF313C005 || op2 == 0x399143E7) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::to_file("[PROTECT] Blocked crash opcode\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0x5D4D4E4C with large buffer
        if (op2 == 0x5D4D4E4C && a5 > 64 && a4 != 0) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::to_file("[PROTECT] Blocked crash 0x5D4D4E4C\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // Combo crashes (a2+a3 or a3 alone)
        if ((op2 == 0x809A6BC4 && op3 == 0x809A6BC4) ||
            op3 == 0xF501C37E || op3 == 0x5CB533F5 ||
            op3 == 0x2480F3C1 || op3 == 0xF30B99EF) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::to_file("[PROTECT] Blocked crash combo\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0x82E9A020 duplicate with a4 > 1
        if (a4 && op2 == 0x82E9A020 && op3 == 0x82E9A020 && (unsigned int)*a4 > 1) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::to_file("[PROTECT] Blocked crash 0x82E9A020\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // a5 == 0x96 crash
        if (a5 == 0x96) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::to_file("[PROTECT] Blocked crash a5==0x96\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // a4 == 0xFFFFFFFF crash variants
        if (a4 && *a4 == (int)0xFFFFFFFF &&
            (op3 == 0x76A8609D || op3 == 0xFEBDCA3D || op3 == 0x8904984F)) {
            toast::Show(toast::Type::Warning, "Blocked crash from opponent");
            log::to_file("[PROTECT] Blocked crash (a4=FFFFFFFF)\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // ── Freeze protection ─────────────────────────────────────────

        // 0x9774D53D (high confidence freeze)
        if (op2 == 0x9774D53D || op3 == 0x9774D53D) {
            toast::Show(toast::Type::Error, "Blocked freeze from opponent");
            log::to_file("[PROTECT] Blocked freeze 0x9774D53D\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0x406CE419 (pause_op_game freeze)
        if (op2 == 0x406CE419 || op3 == 0x406CE419) {
            toast::Show(toast::Type::Error, "Blocked freeze from opponent");
            log::to_file("[PROTECT] Blocked freeze 0x406CE419\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0xA477B52B (Freeze 2)
        if (op2 == 0xA477B52B || op3 == 0xA477B52B) {
            toast::Show(toast::Type::Error, "Blocked freeze from opponent");
            log::to_file("[PROTECT] Blocked freeze 0xA477B52B\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

        // 0xE0A38D91 freeze (a5=1, a6=-1, a4[0]=0xFF)
        if ((op2 == 0xE0A38D91 || op3 == 0xE0A38D91) &&
            a5 == 1 && a6 == -1 && a4 && *reinterpret_cast<unsigned char*>(a4) == 0xFF) {
            toast::Show(toast::Type::Error, "Blocked freeze from opponent");
            log::to_file("[PROTECT] Blocked freeze 0xE0A38D91\r\n");
            ((ept::register_context_t*)ctx)->rax = 0;
            return 1;
        }

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
        log::to_file("[Ring-1] RouteGameMessage hooked (crash/freeze protection)\r\n");
    }
    else
    {
        log::to_file("[Ring-1] WARNING: RouteGameMessage not found, protection disabled\r\n");
    }
}

void hook::install_playerside_hook()
{
    // EPT split hook: patch the thunk's E9 displacement to redirect to a
    // code cave trampoline. Execute view has patched bytes, read view shows
    // original — invisible to integrity checks. Uses CMD_EPT_PATCH_BYTES.
    if (!offsets::FnPlayerSide)
    {
        log::to_file("[Ring-1] WARNING: PlayerSide not found\r\n");
        return;
    }

    char buf[256];
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
        log::to_file("[Ring-1] WARNING: PlayerSide thunk chain not resolved\r\n");
        return;
    }

    fmt::snprintf(buf, sizeof(buf), "[Ring-1] PlayerSide patchE9=%p originalTarget=%p\r\n",
        patchE9, (void*)originalTarget);
    log::to_file(buf);

    // Find a code cave (14+ CC bytes) within ±256KB of the thunk
    unsigned char* gameBase = (unsigned char*)offsets::GameBase;
    uintptr_t gameEnd = (uintptr_t)gameBase + offsets::GameSize;

    // Search entire game module for CC padding — thunk tables are dense,
    // but normal .text has CC padding between functions.
    // Any cave in the module is within ±2GB (module is ~440MB).
    unsigned char* searchLo = gameBase;
    unsigned char* searchHi = (unsigned char*)gameEnd;

    unsigned char* cave = nullptr;
    for (unsigned char* p = searchLo; p + 14 <= searchHi; p++)
    {
        // Accept runs of CC (int3 padding) or 00 (null padding, common in VMProtect'd binaries)
        unsigned char fill = p[0];
        if (fill != 0xCC && fill != 0x00) continue;

        bool ok = true;
        for (int j = 1; j < 14; j++)
        {
            if (p[j] != fill) { ok = false; p += j; break; }
        }
        if (ok)
        {
            unsigned int cavePageOff = (unsigned int)((uintptr_t)p & 0xFFF);
            if (cavePageOff + 12 > 0x1000) continue;
            cave = p;
            break;
        }
    }

    if (!cave)
    {
        fmt::snprintf(buf, sizeof(buf),
            "[Ring-1] WARNING: No code cave found for PlayerSide (searched %p-%p, %llu bytes)\r\n",
            searchLo, searchHi, (unsigned long long)(searchHi - searchLo));
        log::to_file(buf);
        return;
    }

    // Verify ±2GB range
    intptr_t caveDist = (intptr_t)cave - (intptr_t)(patchE9 + 5);
    if (caveDist > 0x7FFFFFFFL || caveDist < -(intptr_t)0x7FFFFFFFL)
    {
        log::to_file("[Ring-1] WARNING: Cave too far for rel32\r\n");
        return;
    }

    fmt::snprintf(buf, sizeof(buf), "[Ring-1] PlayerSide cave=%p dist=%lld\r\n",
        cave, (long long)caveDist);
    log::to_file(buf);

    // Build 12-byte trampoline: mov rax, <hook>; jmp rax
    // 48 B8 [imm64]  = mov rax, imm64 (10 bytes)
    // FF E0           = jmp rax        (2 bytes)
    unsigned long long hookAddr = (unsigned long long)&HookedPlayerSide;
    unsigned char trampoline[12];
    trampoline[0] = 0x48;
    trampoline[1] = 0xB8;
    for (int i = 0; i < 8; i++)
        trampoline[2 + i] = ((unsigned char*)&hookAddr)[i];
    trampoline[10] = 0xFF;
    trampoline[11] = 0xE0;

    // EPT patch the cave page: shadow exec view gets trampoline, read view stays original
    ept_patch_bytes_params_t caveParams = {};
    caveParams.patch_offset = (unsigned int)((unsigned long long)cave & 0xFFF);
    caveParams.patch_size = 12;
    for (int i = 0; i < 12; i++)
        caveParams.patch_bytes[i] = trampoline[i];

    implant_request_t req = {};
    req.command = CMD_EPT_PATCH_BYTES;
    req.param1 = (unsigned long long)cave;
    req.param2 = (unsigned long long)&caveParams;
    ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

    if (req.status != 0 || req.result != 1)
    {
        fmt::snprintf(buf, sizeof(buf), "[Ring-1] WARNING: EPT patch cave failed (status=%u result=%llu)\r\n",
            req.status, req.result);
        log::to_file(buf);
        return;
    }
    log::to_file("[Ring-1] PlayerSide cave trampoline EPT-patched\r\n");

    // EPT patch the thunk page: redirect E9 displacement to cave
    int newRel = (int)((long long)cave - (long long)(patchE9 + 5));

    ept_patch_bytes_params_t thunkParams = {};
    thunkParams.patch_offset = (unsigned int)(((unsigned long long)(patchE9 + 1)) & 0xFFF);
    thunkParams.patch_size = 4;
    for (int i = 0; i < 4; i++)
        thunkParams.patch_bytes[i] = ((unsigned char*)&newRel)[i];

    req = {};
    req.command = CMD_EPT_PATCH_BYTES;
    req.param1 = (unsigned long long)patchE9;
    req.param2 = (unsigned long long)&thunkParams;
    ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

    if (req.status == 0 && req.result == 1)
    {
        g_originalPlayerSide = (PlayerSideFn_t)originalTarget;
        log::to_file("[Ring-1] PlayerSide EPT hook installed (thunk + cave patched)\r\n");
    }
    else
    {
        fmt::snprintf(buf, sizeof(buf), "[Ring-1] WARNING: EPT patch thunk failed (status=%u result=%llu)\r\n",
            req.status, req.result);
        log::to_file(buf);
    }
}
