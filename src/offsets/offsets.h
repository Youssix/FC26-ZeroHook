#pragma once
#include <Windows.h>

namespace offsets
{
    // Game module
    extern void*         GameBase;
    extern unsigned long GameSize;

    // Spoof call gadget (FF 23 = jmp [rbx])
    extern void* SpoofLocation;

    // DXGI SwapChain pointer
    extern void* SwapChain;

    // Frostbite InputReader singleton
    extern uintptr_t InputReader;

    // InputReader vtable function pointers (for EPT hooks + spoof_call)
    extern void* FnIsKeyDown;          // [8]
    extern void* FnWasKeyPressed;      // [9]
    extern void* FnWasKeyReleased;     // [10]
    extern void* FnIsMouseDown;        // [11]
    extern void* FnWasMousePressed;    // [12]
    extern void* FnWasMouseReleased;   // [13]
    extern void* FnGetMouseX;          // [22]
    extern void* FnGetMouseY;          // [23]
    extern void* FnGetMouseDeltaX;     // [24]
    extern void* FnGetMouseDeltaY;     // [25]
    extern void* FnGetMouseScroll;     // [26]

    // Network dispatch (RouteGameMessage = vtable[9])
    extern uintptr_t GameDispatchVTable;
    extern void*     FnRouteGameMessage;

    // Alt-Tab sender (SystemOnAltTabMessage dispatch)
    extern void*     FnAltTabSender;

    // PlayerSide (vtable[0xD]) — VTable hook, not EPT (target is VMProtect'd)
    extern uintptr_t PlayerSideVTable;
    extern void*     FnPlayerSide;

    // MatchTimer (vtable[1]) — hooked to detect kickoff for AI Difficulty
    extern uintptr_t MatchTimerVTable;
    extern void*     FnMatchTimer;

    // AI controller subsystem — fixes AI vs Opps DC at goal/half-time.
    //   FnGetMatchCtx     = sub_142805590() — returns the live match_ctx pointer.
    //                       Mirrors `*(*(qword_14D895190 + 0x1080) + 0x130)`.
    //   FnAiSlotResolver  = sub_142329490(match_ctx, team_token) — returns the
    //                       field slot index [0..21] of our local player.
    //   FnAiStateSync     = sub_14282B1D0(match_ctx, slot, 0) — internally
    //                       broadcasts opcode 0x4E9507C9 (0x290 bytes, full
    //                       controller-profile snapshot). MUST be called
    //                       before dispatching 0xA2CB726E, otherwise the peer
    //                       receives the controller-change opcode without the
    //                       state context that makes it valid, and the hash
    //                       check fires → DataMismatch DC.
    extern void* FnGetMatchCtx;
    extern void* FnAiSlotResolver;
    extern void* FnAiStateSync;
    extern void* FnAfkTakeover;      // sub_1427F7640

    // sub_142812730 — the canonical cursor/AI-controller dispatcher. Called
    // with (mode=0, ack=0) this invokes sub_1427FD810 which sets the master
    // cursor-suppress latch at matchCtx+0x1AA8, copies slot arrays, flips the
    // alt flag, and emits the 4-cascade 0xA2CB726E peer notification via
    // sub_1428F7B00. This matches the exact fingerprint in the 3 cheat logs
    // (RetAddr 0x14566C4D4 + cascade to 0x1450965A5/0x14291EDAD/0x14218E1E9).
    // Calling with mode!=0 activates cursor paths instead — avoid.
    extern void* FnAiTakeoverDispatch; // sub_142812730

    // sub_1427FD810 — the AI-takeover enabler called from FnAiTakeoverDispatch
    // on the mode=0 path. Signature: (match_ctx*, int mode, u8 ack) → char.
    // Writes ctx[0x1AB0]=mode, ctx[0x1AA8]=1, ctx[0x1AB5]=0, ctx[0x14C]=-1,
    // ctx[0x150]=0 or 1, ctx[0x1080]->[0x130][0x8]=1 (matchData dirty), then
    // iterates 22-player loop emitting 0xA2CB726E packets via sub_1428F7B00.
    // Early-exits if ctx[0x1AA8] != 0 (re-entry gate). ctx here is the OUTER
    // state-root (qword_14D895190 dereffed), NOT matchData from FnGetMatchCtx.
    extern void* FnAiTakeoverEnabler;  // sub_1427FD810

    // Address of qword_14D895190 (global state-root pointer). Resolved
    // from the first instruction of sub_142805590 (mov rax, cs:...).
    // Used to override mode at +0x1A0 during AFK takeover call so the
    // sub_14280B0F0/sub_14280B220 gates pass and the dispatch fires.
    extern uintptr_t StateRootPtrAddr;

    // EAID vtable — vtable[23] is the function that returns the EA ID string
    extern uintptr_t EAIDVTable;
    extern void*     FnEAID;

    // DataMismatch gate (sub_142825AC0). Validates incoming 0xA2CB726E and
    // 0x4E9507C9 packets; returns 1 → caller submits DC. We EPT-hook this to
    // bypass validation for those two opcodes so forged packets don't trigger
    // DataMismatch. The hook calls FnBaseHandler (sub_145096120) directly when
    // bypassing so the normal message processing still runs.
    extern void* FnMismatchGate;    // sub_142825AC0
    extern void* FnBaseHandler;     // sub_145096120 — real message pre-processor

    // Physics-sync checksum verifier (sub_1445C9CE0). Called by sub_1445BF230
    // to compare local vs peer physics state hashes. Returns 1 = mismatch
    // (which routes through "Checksum mismatch for %s" → sub_144554810 DC
    // submission), 0 = OK. We EPT-hook this to force return 0 always —
    // physics-sync DataMismatch becomes unreachable. The check is gated by
    // a ~60-120s time window post-kickoff; our hook neutralizes it globally.
    extern void* FnChecksumCheck;   // sub_1445C9CE0

    // Resolve everything — call once from DllMain before hooks
    bool Init();
}
