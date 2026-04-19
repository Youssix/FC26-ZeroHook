#pragma once
#include <cstdint>

// AI-takeover call tracing. Installs EPT hooks on every function involved in
// the pause→AI→resume state machine (sub_1427FA200, sub_1427FCBD0,
// sub_148A9FEB0, sub_148A9FFA0, sub_148ACCB00, sub_146549750, sub_146E98A00),
// logs each entry with args/retaddr/timestamp, and returns to the original so
// the game's behavior is untouched. Writes to a dedicated trace log file.
//
// Flip kEnabled to false (rebuild) to skip all installs — the hooks become
// no-ops. All detours are pass-through only; no state is mutated.

namespace ai_trace
{
    inline constexpr bool kEnabled = true;

    // Runtime toggle for the RouteGameMessage opcode-census log inside
    // HookedRouteGameMessage (src/hook/network_hooks.cpp). Flipped live from
    // the menu (Settings > Trace Opcodes). When false, the opcode block
    // short-circuits with zero log I/O.
    //
    // Default OFF so fresh installs don't spam zerohook.log until someone
    // explicitly asks for packet-level visibility.
    extern volatile bool g_traceOpcodes;

    // Dedicated log path: %USERPROFILE%\Documents\zerohook_ai_trace.log
    void log_line(const char* msg);

    // Pattern-scan targets + install EPT trace hooks. Called once at boot,
    // after offsets::Init() and main hook installs. Silently skips targets
    // whose patterns fail to resolve on this build.
    void install_all();
}
