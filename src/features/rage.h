#pragma once
#include <cstdint>

namespace rage
{
    // Pattern-scanned pointers (resolved in offsets::Init)
    extern uintptr_t slider_ptr;
    extern uintptr_t msg_dispatcher;
    extern uintptr_t dispatch_vfunc;

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
