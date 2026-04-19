#pragma once
#include <Windows.h>
#include <intrin.h>

namespace game
{
    struct ModuleInfo {
        void* base;
        ULONG size;
    };

    ModuleInfo find_module();
    void* pattern_scan(void* module_base, unsigned long module_size, const char* sig);

    // Find a run of `minBytes` identical padding bytes (CC or 00) in [base, base+size).
    // Returned cave will NOT cross a 4KB page boundary for the first `payloadBytes`.
    // Stateful: each call returns a different cave (bump allocator).
    void* find_code_cave(void* base, unsigned long size,
                         int minBytes = 14, int payloadBytes = 12);

    // EPT-patch `size` bytes at `addr` (shadow execute page).
    // Returns false if patch would cross a 4KB page boundary.
    bool ept_patch(uintptr_t addr, const unsigned char* bytes, int size);
}
