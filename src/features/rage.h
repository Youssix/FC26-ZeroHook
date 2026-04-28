#pragma once
#include <cstdint>

namespace rage
{
    // Pattern-scanned pointers (resolved in offsets::Init)
    extern uintptr_t slider_ptr;
    extern uintptr_t msg_dispatcher;
    // Dispatch forwarder thunk: reads vtable[9] from rcx, tail-calls it.
    // Removes need to resolve vtable[9] manually — usable as outFn directly.
    extern uintptr_t dispatch_action_vfunc;

    // Frostbite dispatcher signature: vtable[9] of message dispatcher object.
    //   ((void(*)(this, opcode_a, opcode_b, payload, size, flag1, flag2))fn)(rcx, ...)
    typedef void(__fastcall* dispatch_fn_t)(
        uint64_t rcx, uint64_t* rdx, uint64_t* r8, void* r9,
        int param1, char param2, unsigned char param3);

    // Resolves the dispatcher object + vtable[9] dynamically.
    // Walks: msg_dispatcher → *wrapper → object → vtable → vtable[9]
    // Returns true if both outRcx and outFn are valid.
    bool get_dispatch(uintptr_t& outRcx, dispatch_fn_t& outFn);

    // Initialize rage offsets — call after offsets::GameBase is set
    bool InitOffsets(void* gameBase, unsigned long gameSize);

    // Kick (available in all builds)
    void kick_opponent(int dcReason);

    // Rage actions (Premium only)
#ifndef STANDARD_BUILD
    void crash_opps();
    void pause_op_game();       // Freeze 1 (PC/XBOX)
    void pause_op_game_new();   // Freeze 2
    void slider_bomb();
#endif
}
