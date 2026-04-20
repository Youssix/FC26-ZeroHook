#include "offsets.h"
#include "../game/game.h"
#include "../log/log.h"
#include "../log/fmt.h"

// ── Globals ─────────────────────────────────────────────────────────
void*         offsets::GameBase      = nullptr;
unsigned long offsets::GameSize      = 0;
void*         offsets::SpoofLocation = nullptr;
void*         offsets::SwapChain     = nullptr;
uintptr_t     offsets::InputReader   = 0;
void*         offsets::FnIsKeyDown        = nullptr;
void*         offsets::FnWasKeyPressed    = nullptr;
void*         offsets::FnWasKeyReleased   = nullptr;
void*         offsets::FnIsMouseDown      = nullptr;
void*         offsets::FnWasMousePressed  = nullptr;
void*         offsets::FnWasMouseReleased = nullptr;
void*         offsets::FnGetMouseX        = nullptr;
void*         offsets::FnGetMouseY        = nullptr;
void*         offsets::FnGetMouseDeltaX   = nullptr;
void*         offsets::FnGetMouseDeltaY   = nullptr;
void*         offsets::FnGetMouseScroll   = nullptr;
uintptr_t     offsets::GameDispatchVTable = 0;
void*         offsets::FnRouteGameMessage = nullptr;
void*         offsets::FnAltTabSender     = nullptr;
uintptr_t     offsets::PlayerSideVTable   = 0;
void*         offsets::FnPlayerSide       = nullptr;
uintptr_t     offsets::MatchTimerVTable   = 0;
void*         offsets::FnMatchTimer       = nullptr;
void*         offsets::FnGetMatchCtx      = nullptr;
void*         offsets::FnAiSlotResolver   = nullptr;
void*         offsets::FnAiStateSync      = nullptr;
void*         offsets::FnAfkTakeover      = nullptr;  // sub_1427F7640
void*         offsets::FnAiTakeoverDispatch = nullptr; // sub_142812730
void*         offsets::FnAiTakeoverEnabler  = nullptr; // sub_1427FD810
void*         offsets::FnTakeOverSlot       = nullptr; // sub_142814760
void*         offsets::FnClaimSlot          = nullptr; // sub_14281B970
uintptr_t     offsets::StateRootPtrAddr   = 0;        // &qword_14D895190
uintptr_t     offsets::EAIDVTable        = 0;
void*         offsets::FnEAID            = nullptr;

// ── Helpers ─────────────────────────────────────────────────────────
namespace
{
    uintptr_t resolve_rip(uintptr_t instr, int disp_off, int instr_len)
    {
        int disp = *(int*)(instr + disp_off);
        return instr + instr_len + disp;
    }

    bool is_canonical(uintptr_t addr)
    {
        uintptr_t top = addr >> 47;
        return top == 0 || top == 0x1FFFF;
    }
}

// ── Init ────────────────────────────────────────────────────────────
bool offsets::Init()
{
    char buf[256];

    // ── 1. Game module ──────────────────────────────────────────────
    log::debug("[offsets] [1/7] find_module()...\r\n");
    game::ModuleInfo mod = game::find_module();
    if (!mod.base)
    {
        log::debug("[offsets] [1/7] FAIL: game module not found\r\n");
        return false;
    }
    GameBase = mod.base;
    GameSize = mod.size;
    fmt::snprintf(buf, sizeof(buf), "[offsets] [1/7] OK Game: %p  size=0x%lX\r\n", GameBase, GameSize);
    log::debug(buf);

    // ── 2. Spoof gadget (FF 23 = jmp [rbx]) ────────────────────────
    log::debug("[offsets] [2/7] Spoof gadget pattern scan...\r\n");
    void* gadgetMatch = game::pattern_scan(GameBase, GameSize, "E8 ? ? ? ? FF 23");
    if (gadgetMatch)
        SpoofLocation = (void*)((uintptr_t)gadgetMatch + 5);
    fmt::snprintf(buf, sizeof(buf), "[offsets] [2/7] %s SpoofLocation: %p\r\n",
        SpoofLocation ? "OK" : "FAIL", SpoofLocation);
    log::debug(buf);

    // ── 3. SwapChain ────────────────────────────────────────────────
    //   Pattern: mov [rip+disp32], rdi; mov [rip+disp32], r14
    log::debug("[offsets] [3/7] SwapChain pattern scan...\r\n");
    void* scMatch = game::pattern_scan(GameBase, GameSize, "48 89 3D ? ? ? ? 4C 89 35");
    if (scMatch)
    {
        uintptr_t globalAddr = resolve_rip((uintptr_t)scMatch, 3, 7);
        if (globalAddr)
        {
            __try {
                void* ptr = *(void**)globalAddr;
                if (ptr && is_canonical((uintptr_t)ptr))
                    SwapChain = ptr;
            } __except (1) {
                log::debug("[offsets] [3/7] EXCEPTION reading SwapChain global\r\n");
            }
        }
    }
    fmt::snprintf(buf, sizeof(buf), "[offsets] [3/7] %s SwapChain: %p\r\n",
        SwapChain ? "OK" : "FAIL (D3D not ready yet — normal at inject)", SwapChain);
    log::debug(buf);

    // ── 4. Frostbite InputReader ────────────────────────────────────
    //   Pattern inside EACoreKeyboardPoller::update:
    //   E8 call → getKeyboardReader → LEA RAX,[RIP+disp] → singleton
    log::debug("[offsets] [4/7] InputReader pattern scan...\r\n");
    void* irMatch = game::pattern_scan(GameBase, GameSize,
        "E8 ? ? ? ? 48 8D 94 24 ? ? 00 00 48 8B C8 4C 8B 00 41 FF 50 18");
    if (irMatch)
    {
        uintptr_t callSite  = (uintptr_t)irMatch;
        uintptr_t getReader = resolve_rip(callSite, 1, 5);

        // getKeyboardReader: 48 8D 05 [rel32] C3  (lea rax, [rip+disp]; ret)
        __try {
            if (*(unsigned char*)getReader == 0x48)
            {
                InputReader = resolve_rip(getReader, 3, 7);
            }
            else
            {
                fmt::snprintf(buf, sizeof(buf),
                    "[offsets] [4/7] InputReader unexpected opcode 0x%02X at %p\r\n",
                    *(unsigned char*)getReader, (void*)getReader);
                log::debug(buf);
            }
        } __except (1) {
            log::debug("[offsets] [4/7] EXCEPTION resolving InputReader\r\n");
        }
    }
    fmt::snprintf(buf, sizeof(buf), "[offsets] [4/7] %s InputReader: %p\r\n",
        InputReader ? "OK" : "FAIL", (void*)InputReader);
    log::debug(buf);

    // ── 5. InputReader vtable functions ──────────────────────────────
    log::debug("[offsets] [5/7] InputReader vtable read...\r\n");
    if (InputReader)
    {
        __try {
            void** vtable = *(void***)InputReader;
            if (vtable)
            {
                FnIsKeyDown        = vtable[8];
                FnWasKeyPressed    = vtable[9];
                FnWasKeyReleased   = vtable[10];
                FnIsMouseDown      = vtable[11];
                FnWasMousePressed  = vtable[12];
                FnWasMouseReleased = vtable[13];
                FnGetMouseX        = vtable[22];
                FnGetMouseY        = vtable[23];
                FnGetMouseDeltaX   = vtable[24];
                FnGetMouseDeltaY   = vtable[25];
                FnGetMouseScroll   = vtable[26];
                fmt::snprintf(buf, sizeof(buf),
                    "[offsets] [5/7] OK vtable=%p IsKeyDown=%p IsMouseDown=%p\r\n",
                    (void*)vtable, FnIsKeyDown, FnIsMouseDown);
                log::debug(buf);
            } else {
                log::debug("[offsets] [5/7] FAIL vtable is NULL\r\n");
            }
        } __except (1) {
            log::debug("[offsets] [5/7] EXCEPTION reading InputReader vtable\r\n");
        }
    } else {
        log::debug("[offsets] [5/7] SKIP (InputReader is NULL)\r\n");
    }

    // ── 6. GameDispatchVTable (RouteGameMessage) ───────────────────
    //   FC26 pattern: E8 ? ? ? ? 48 8D 8B ? ? ? ? FF 15 ? ? ? ? 48 8B CB
    //   resolve call target → +0xD has LEA with RIP-relative → vtable
    log::debug("[offsets] [6/7] GameDispatchVTable pattern scan...\r\n");
    void* gdvMatch = game::pattern_scan(GameBase, GameSize,
        "E8 ? ? ? ? 48 8D 8B ? ? ? ? FF 15 ? ? ? ? 48 8B CB");
    if (gdvMatch)
    {
        __try {
            // Resolve the E8 call target
            uintptr_t callTarget = resolve_rip((uintptr_t)gdvMatch, 1, 5);
            // At callTarget+0xD there's a LEA reg,[rip+disp32] → vtable address
            GameDispatchVTable = resolve_rip(callTarget + 0xD, 3, 7);

            if (GameDispatchVTable && is_canonical(GameDispatchVTable))
            {
                void** vtable = (void**)GameDispatchVTable;
                FnRouteGameMessage = vtable[9];
            }
        } __except (1) {
            log::debug("[offsets] [6/7] EXCEPTION resolving GameDispatchVTable\r\n");
        }
    }
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [6/7] %s GameDispatchVTable: %p  RouteGameMessage: %p\r\n",
        (GameDispatchVTable && FnRouteGameMessage) ? "OK" : "FAIL",
        (void*)GameDispatchVTable, FnRouteGameMessage);
    log::debug(buf);

    // ── 6b. AltTabSender (SystemOnAltTabMessage dispatch) ──────────
    FnAltTabSender = game::pattern_scan(GameBase, GameSize,
        "48 83 EC ? E8 ? ? ? ? 48 85 C0 74 ? 48 8D 0D");
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [6b] %s AltTabSender: %p\r\n",
        FnAltTabSender ? "OK" : "FAIL", FnAltTabSender);
    log::debug(buf);

    // ── 7. PlayerSide vtable (vtable[0xD]) ──────────────────────────
    log::debug("[offsets] [7/7] PlayerSide vtable pattern scan...\r\n");
    void* psMatch = game::pattern_scan(GameBase, GameSize,
        "48 8D 05 ? ? ? ? 48 8B 71 20 8B EA");
    if (psMatch)
    {
        __try {
            uintptr_t vtableAddr = resolve_rip((uintptr_t)psMatch, 3, 7);
            if (vtableAddr && is_canonical(vtableAddr))
            {
                PlayerSideVTable = vtableAddr;
                void** vtable = (void**)vtableAddr;
                FnPlayerSide = vtable[0xD];
            }
        } __except (1) {
            log::debug("[offsets] [7/7] EXCEPTION resolving PlayerSide vtable\r\n");
        }
    }
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [7/7] %s PlayerSideVTable: %p  FnPlayerSide: %p\r\n",
        (PlayerSideVTable && FnPlayerSide) ? "OK" : "FAIL",
        (void*)PlayerSideVTable, FnPlayerSide);
    log::debug(buf);

    // ── 8. MatchTimer vtable (vtable[1]) ────────────────────────────
    //   Pattern from FC26-Internal/features/offset.cpp:405 — a LEA RAX,[rip+match_time_vtable]
    //   followed by object construction calls. Ported verbatim.
    log::debug("[offsets] [8] MatchTimer vtable pattern scan...\r\n");
    void* mtMatch = game::pattern_scan(GameBase, GameSize,
        "48 8D 05 ? ? ? ? 49 8D 4E ? 49 89 06 E8 ? ? ? ? 48 8D 05 ? ? ? ? 33 ED 49 8D 4E ? 49 89 46 ? 49 89 6E ? E8 ? ? ? ? 48 8D 05 ? ? ? ? 49 89 6E");
    if (mtMatch)
    {
        __try {
            uintptr_t vtableAddr = resolve_rip((uintptr_t)mtMatch, 3, 7);
            if (vtableAddr && is_canonical(vtableAddr))
            {
                MatchTimerVTable = vtableAddr;
                void** vtable = (void**)vtableAddr;
                FnMatchTimer = vtable[1];
            }
        } __except (1) {
            log::debug("[offsets] [8] EXCEPTION resolving MatchTimer vtable\r\n");
        }
    }
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [8] %s MatchTimerVTable: %p  FnMatchTimer: %p\r\n",
        (MatchTimerVTable && FnMatchTimer) ? "OK" : "FAIL",
        (void*)MatchTimerVTable, FnMatchTimer);
    log::debug(buf);

    // ── 9. Match-ctx getter (sub_142805590) ────────────────────────
    //   Body: mov rax,[global]; cmp byte-guard; cmovz rax,0;
    //         mov rax,[rax+0x1080]; mov rax,[rax+0x130]; ret
    //   Returns the live match_ctx pointer. We call this each send —
    //   no more EPT AFK hook needed to capture context.
    FnGetMatchCtx = game::pattern_scan(GameBase, GameSize,
        "48 8B 05 ? ? ? ? 33 C9 38 0D ? ? ? ? 48 0F 44 C1 48 8B 80 80 10 00 00 48 8B 80 30 01 00 00 C3");
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [9] %s FnGetMatchCtx: %p\r\n",
        FnGetMatchCtx ? "OK" : "FAIL", FnGetMatchCtx);
    log::debug(buf);

    // ── 10. AI slot resolver (sub_142329490) ───────────────────────
    //   Prologue: xor eax,eax; mov r9d,edx; mov r10d,0xFFFFFFFF
    //   Given (match_ctx, team_token) returns our field slot [0..21]
    //   or 0xFFFFFFFF if not found. team_token must come from the
    //   per-round table (not playerside) — see SendAiTakeover.
    FnAiSlotResolver = game::pattern_scan(GameBase, GameSize,
        "33 C0 44 8B CA 41 BA");
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [10] %s FnAiSlotResolver: %p\r\n",
        FnAiSlotResolver ? "OK" : "FAIL", FnAiSlotResolver);
    log::debug(buf);

    // ── 11. AI state sync broadcast (sub_14282B1D0) ────────────────
    //   Prologue distinctive: mov rax,rsp / mov [rax+18],rbx /
    //   push rbp/rsi/rdi/r12/r13/r14/r15 / lea rbp,[rax-628] /
    //   sub rsp,0x790 — a large-frame state builder that walks the
    //   22-slot array at match_ctx+0x10 and broadcasts opcode
    //   0x4E9507C9 with a 0x290-byte payload.
    FnAiStateSync = game::pattern_scan(GameBase, GameSize,
        "48 8B C4 48 89 58 18 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 D8 F9 FF FF 48 81 EC 90 07 00 00");
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [11] %s FnAiStateSync: %p\r\n",
        FnAiStateSync ? "OK" : "FAIL", FnAiStateSync);
    log::debug(buf);

    // ── 12. AFK takeover handler (sub_1427F7640) ───────────────────
    //   Prologue: push rbp/rsi/rdi/r13; lea rbp,[rsp-0x3F];
    //             sub rsp,0xC8; mov rax,cs:__security_cookie;
    //             xor rax,rsp; mov [rbp+7],rax;
    //             movsxd rsi,edx; movzx r13d,r8b
    //   Distinctive because of the signed-extend of team_idx (edx) and
    //   the sec-cookie dance right after the large stack allocation.
    FnAfkTakeover = game::pattern_scan(GameBase, GameSize,
        "40 55 56 57 41 55 48 8D 6C 24 C1 48 81 EC C8 00 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 48 63 F2 45 0F B6 E8");
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [12] %s FnAfkTakeover: %p\r\n",
        FnAfkTakeover ? "OK" : "FAIL", FnAfkTakeover);
    log::debug(buf);

    // ── 12b. AI takeover dispatcher (sub_142812730) ────────────────
    //   The canonical cursor/AI-controller state machine entry point.
    //   Signature: (int mode, uint8_t ack) → __int64.
    //     mode=0 → invokes sub_1427FD810 (AI takeover enabler, sets the
    //              cursor-suppress latch at stateRoot+0x1AA8 and emits
    //              the 4-cascade 0xA2CB726E peer notification)
    //     mode=1..0x17 → activates cursor paths (do not use)
    //   Prologue saves rbx/rbp, pushes rdi, sub rsp,0x20, loads state-root
    //   via mov rbx, [rip+disp] (the qword_14D895190 ref).
    FnAiTakeoverDispatch = game::pattern_scan(GameBase, GameSize,
        "48 89 5C 24 10 48 89 6C 24 18 57 48 83 EC 20 48 8B 1D ? ? ? ? 33 C0 38 05");
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [12b] %s FnAiTakeoverDispatch: %p\r\n",
        FnAiTakeoverDispatch ? "OK" : "FAIL", FnAiTakeoverDispatch);
    log::debug(buf);

    // ── 12c. AI takeover enabler (sub_1427FD810) ───────────────────
    //   Invoked by FnAiTakeoverDispatch on mode=0 path. Does the heavy
    //   lifting: writes ctx[0x1AB0]=mode, ctx[0x1AA8]=1, ctx[0x1AB5]=0,
    //   ctx[0x14C]=-1, ctx[0x150]=0/1, marks matchData dirty, then fires
    //   the 22-player 0xA2CB726E emit loop via sub_1428F7B00.
    //   Prologue: push rbp; push rbx; push rdi; push r13;
    //             lea rbp,[rsp-158h]; sub rsp,258h;
    //             mov rax,cs:__security_cookie; xor rax,rsp;
    //             mov [rbp+130h],rax; cmp byte [rcx+1AA8h],0
    //   The 0x1AA8 compare on entry is the anchor — no other function
    //   in the binary checks this exact offset with this prologue shape.
    FnAiTakeoverEnabler = game::pattern_scan(GameBase, GameSize,
        "40 55 53 57 41 55 48 8D AC 24 A8 FE FF FF 48 81 EC 58 02 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 A8 1A 00 00 00");
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [12c] %s FnAiTakeoverEnabler: %p\r\n",
        FnAiTakeoverEnabler ? "OK" : "FAIL", FnAiTakeoverEnabler);
    log::debug(buf);

    // ── 12d. Public TakeOver API (sub_142814760) ────────────────────
    //   Per-slot AFK/AI takeover. Writes slot+0x194=1 (the local-away
    //   bit read by IsAway) + conditional slot+0x193=1, slot+0x177=1,
    //   + network announce via sub_142814510 (vtable 0xC0 dispatch).
    //   Prologue: mov [rsp+arg_10],rbx; push rbp/rsi/rdi/r12/r13/r14/r15;
    //             mov eax, 2430h; call __alloca_probe; sub rsp,rax
    //   The 0x2430 stack allocation for 22-slot snapshot is distinctive.
    FnTakeOverSlot = game::pattern_scan(GameBase, GameSize,
        "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 B8 30 24 00 00 E8");
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [12d] %s FnTakeOverSlot: %p\r\n",
        FnTakeOverSlot ? "OK" : "FAIL", FnTakeOverSlot);
    log::debug(buf);

    // ── 12e. Low-level CLAIM primitive (sub_14281B970) ──────────────
    //   Signature: void __fastcall(matchData*, uint32_t team_player[2]).
    //   Prologue: mov r11, rsp; push rbp; push rbx; push rdi; push r13;
    //             push r15; lea rbp,[r11-0x5F]; sub rsp, 0xB0;
    //             mov rax, cs:__security_cookie
    //   The r11-base + 0xB0 stack frame + 5-register push sequence is
    //   a unique signature among the slot-handler family (B970/BEE0/AA60
    //   all differ at this offset). Byte 17 onward (0xB0 00 00 00) is
    //   the stack-frame size — stable across minor updates.
    FnClaimSlot = game::pattern_scan(GameBase, GameSize,
        "4C 8B DC 55 53 57 41 55 41 57 49 8D 6B A1 48 81 EC B0 00 00 00 48 8B 05");
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [12e] %s FnClaimSlot: %p\r\n",
        FnClaimSlot ? "OK" : "FAIL", FnClaimSlot);
    log::debug(buf);

    // ── 13. State-root pointer global (qword_14D895190) ────────────
    //   First instruction of sub_142805590 is:
    //     mov rax, cs:qword_14D895190    ; 48 8B 05 <rel32>
    //   RIP-resolve the rel32 to get the global's address.
    if (FnGetMatchCtx)
    {
        __try {
            uintptr_t instr = (uintptr_t)FnGetMatchCtx;
            // Instruction is 7 bytes: 48 8B 05 XX XX XX XX
            // next_rip = instr + 7; disp32 at instr+3
            int disp = *reinterpret_cast<int*>(instr + 3);
            StateRootPtrAddr = instr + 7 + (intptr_t)disp;
        } __except (1) {
            StateRootPtrAddr = 0;
        }
    }
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [13] %s StateRootPtrAddr: %p\r\n",
        StateRootPtrAddr ? "OK" : "FAIL", (void*)StateRootPtrAddr);
    log::debug(buf);

    // ── 14. EAID vtable (vtable[23]) ─────────────────────────────────
    //   Pattern: LEA RAX,[rip+vtable]; xor edi,edi; mov [rbx],rax;
    //   LEA RAX,[rip+vtable2]; mov [rbx+28h],rax; LEA RAX,...
    log::debug("[offsets] [14] EAID vtable pattern scan...\r\n");
    void* eaidMatch = game::pattern_scan(GameBase, GameSize,
        "48 8D 05 ? ? ? ? 31 FF 48 89 03 48 8D 05 ? ? ? ? 48 89 43 ? 48 8D 05");
    if (eaidMatch)
    {
        __try {
            uintptr_t vtableAddr = resolve_rip((uintptr_t)eaidMatch, 3, 7);
            if (vtableAddr && is_canonical(vtableAddr))
            {
                EAIDVTable = vtableAddr;
                void** vtable = (void**)vtableAddr;
                FnEAID = vtable[23];
            }
        } __except (1) {
            log::debug("[offsets] [14] EXCEPTION resolving EAID vtable\r\n");
        }
    }
    fmt::snprintf(buf, sizeof(buf),
        "[offsets] [14] %s EAIDVTable: %p  FnEAID: %p\r\n",
        (EAIDVTable && FnEAID) ? "OK" : "FAIL",
        (void*)EAIDVTable, FnEAID);
    log::debug(buf);

    log::debug("[offsets] Init complete\r\n");
    return true;
}
