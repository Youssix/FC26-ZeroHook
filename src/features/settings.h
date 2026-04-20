#pragma once

// Runtime toggles for debug/diagnostic features. Exposed in the menu under
// Settings > Debug Logging. `volatile` because they're flipped from the UI
// thread and read from game hook threads without a lock.
namespace settings
{
    // Log every inbound RouteGameMessage opcode (minus 4 framing opcodes) to
    // zerohook.log. OFF by default — turn on from the menu when you need an
    // opcode census, toggle off when done to stop log I/O.
    extern volatile bool g_traceOpcodes;
}
