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

    // Resolve everything — call once from DllMain before hooks
    bool Init();
}
