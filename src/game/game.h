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
}
