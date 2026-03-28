// dda.cpp — DDA / Adaptive Difficulty Bypass via vtable pointer swap
// NoCRT-safe: no std:: anything. Uses CMD_WRITE_MEMORY via NtClose channel.

#include "dda.h"
#include <intrin.h>
#include <Windows.h>
#include "../game/game.h"
#include "../comms/comms.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"

namespace
{
    // Address of the vtable slot for the DDA checker at offset 0xA0
    uintptr_t g_vtableSlotAddr = 0;

    // Original function pointer stored in the vtable slot
    unsigned long long g_originalValue = 0;

    // Address of the xor eax,eax; ret gadget
    uintptr_t g_gadgetAddr = 0;

    // Whether the swap is currently active
    bool g_swapped = false;

    bool SafeRead8(uintptr_t addr, unsigned long long* out)
    {
        __try {
            *out = *(unsigned long long*)addr;
            return true;
        } __except (1) {
            return false;
        }
    }

    bool SafeReadPtr(uintptr_t addr, uintptr_t* out)
    {
        __try {
            *out = *(uintptr_t*)addr;
            return true;
        } __except (1) {
            return false;
        }
    }

    // Scan game module for 33 C0 C3 or 31 C0 C3 (xor eax,eax; ret)
    uintptr_t FindRetZeroGadget(void* gameBase, unsigned long gameSize)
    {
        unsigned char* base = (unsigned char*)gameBase;
        unsigned char* end = base + gameSize;

        for (unsigned char* p = base; p + 3 <= end; p++)
        {
            if (p[0] == 0x33 && p[1] == 0xC0 && p[2] == 0xC3)
                return (uintptr_t)p;
            if (p[0] == 0x31 && p[1] == 0xC0 && p[2] == 0xC3)
                return (uintptr_t)p;
        }
        return 0;
    }
}

bool dda::Init(void* gameBase, unsigned long gameSize)
{
    char buf[256];
    initialized = false;

    if (!gameBase || !gameSize) {
        log::to_file("[DDA] Init: no game module\r\n");
        return false;
    }

    log::to_file("[DDA] Scanning DDA wrapper pattern...\r\n");

    // 1. Pattern scan to find the DDA wrapper function
    //    48 83 EC ?                     sub rsp, XX
    //    48 8B 0D ? ? ? ?               mov rcx, [rip+disp32]    <-- g_FifaSettingsAdapterObject
    //    48 8B 01                        mov rax, [rcx]           (vtable)
    //    FF 90 ? ? ? ?                   call qword [rax+offset]  <-- vtable offset
    //    0F B6 C8                        movzx ecx, al
    //    48 83 C4 ?                      add rsp, XX
    //    E9                              jmp ...
    void* match = game::pattern_scan(gameBase, gameSize,
        "48 83 EC ? 48 8B 0D ? ? ? ? 48 8B 01 FF 90 ? ? ? ? 0F B6 C8 48 83 C4 ? E9");
    if (!match) {
        log::to_file("[DDA] ERROR: wrapper pattern not found\r\n");
        return false;
    }

    uintptr_t wrapperAddr = (uintptr_t)match;
    fmt::snprintf(buf, sizeof(buf), "[DDA] Wrapper function: %p\r\n", (void*)wrapperAddr);
    log::to_file(buf);

    // 2. Decode: bytes[3..9] = 48 8B 0D [disp32] → resolve RIP-relative to get global addr
    //    Instruction at wrapperAddr+3: 48 8B 0D XX XX XX XX (7 bytes)
    //    disp32 is at wrapperAddr+6, instruction ends at wrapperAddr+10
    int globalDisp = *(int*)(wrapperAddr + 6);
    uintptr_t globalAddr = wrapperAddr + 10 + globalDisp;

    fmt::snprintf(buf, sizeof(buf), "[DDA] Settings adapter global: %p\r\n", (void*)globalAddr);
    log::to_file(buf);

    // 3. Extract vtable offset from FF 90 XX XX XX XX at wrapperAddr+13
    //    bytes[14..17] contain the dword vtable offset
    unsigned int vtableOffset = *(unsigned int*)(wrapperAddr + 15);

    fmt::snprintf(buf, sizeof(buf), "[DDA] Vtable offset: 0x%X\r\n", vtableOffset);
    log::to_file(buf);

    // 4. Read the adapter global → deref to object → deref to vtable → entry at offset
    uintptr_t adapterObj = 0;
    if (!SafeReadPtr(globalAddr, &adapterObj) || !adapterObj) {
        log::to_file("[DDA] ERROR: adapter global is null or unreadable\r\n");
        return false;
    }

    fmt::snprintf(buf, sizeof(buf), "[DDA] Adapter object: %p\r\n", (void*)adapterObj);
    log::to_file(buf);

    uintptr_t vtablePtr = 0;
    if (!SafeReadPtr(adapterObj, &vtablePtr) || !vtablePtr) {
        log::to_file("[DDA] ERROR: vtable pointer is null or unreadable\r\n");
        return false;
    }

    fmt::snprintf(buf, sizeof(buf), "[DDA] Vtable: %p\r\n", (void*)vtablePtr);
    log::to_file(buf);

    // The vtable slot address
    g_vtableSlotAddr = vtablePtr + vtableOffset;

    // Read original function pointer
    unsigned long long origFn = 0;
    if (!SafeRead8(g_vtableSlotAddr, &origFn) || !origFn) {
        log::to_file("[DDA] ERROR: vtable slot unreadable or null\r\n");
        return false;
    }

    g_originalValue = origFn;

    fmt::snprintf(buf, sizeof(buf), "[DDA] Vtable slot: %p -> original fn: %p\r\n",
        (void*)g_vtableSlotAddr, (void*)(uintptr_t)origFn);
    log::to_file(buf);

    // 5. Find xor eax,eax; ret gadget
    g_gadgetAddr = FindRetZeroGadget(gameBase, gameSize);
    if (!g_gadgetAddr) {
        log::to_file("[DDA] ERROR: xor eax,eax; ret gadget not found\r\n");
        return false;
    }

    fmt::snprintf(buf, sizeof(buf), "[DDA] Gadget (ret 0): %p\r\n", (void*)g_gadgetAddr);
    log::to_file(buf);

    initialized = true;
    g_swapped = false;
    log::to_file("[DDA] Init OK\r\n");
    return true;
}

bool dda::IsReady()
{
    return initialized;
}

void dda::SetEnabled(bool enable)
{
    if (!initialized) return;

    char buf[256];

    if (enable && !g_swapped)
    {
        // Write gadget address to vtable slot
        implant_request_t req = {};
        req.command = CMD_WRITE_MEMORY;
        req.param1 = (unsigned long long)g_vtableSlotAddr;
        req.param2 = (unsigned long long)g_gadgetAddr;
        req.param3 = 8;
        ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

        if (req.status == 0) {
            g_swapped = true;
            bypassEnabled = true;
            toast::Show(toast::Type::Success, "DDA bypass enabled");
            log::to_file("[DDA] Enabled: vtable swapped to gadget\r\n");
        } else {
            fmt::snprintf(buf, sizeof(buf), "[DDA] ERROR: write failed (status=%u)\r\n", req.status);
            log::to_file(buf);
            bypassEnabled = false;
            toast::Show(toast::Type::Error, "DDA bypass failed");
        }
    }
    else if (!enable && g_swapped)
    {
        // Restore original function pointer
        implant_request_t req = {};
        req.command = CMD_WRITE_MEMORY;
        req.param1 = (unsigned long long)g_vtableSlotAddr;
        req.param2 = g_originalValue;
        req.param3 = 8;
        ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

        if (req.status == 0) {
            g_swapped = false;
            bypassEnabled = false;
            toast::Show(toast::Type::Info, "DDA bypass disabled");
            log::to_file("[DDA] Disabled: vtable restored\r\n");
        } else {
            fmt::snprintf(buf, sizeof(buf), "[DDA] ERROR: restore failed (status=%u)\r\n", req.status);
            log::to_file(buf);
            bypassEnabled = true;
            toast::Show(toast::Type::Error, "DDA restore failed");
        }
    }
}

bool dda::IsEnabled()
{
    return g_swapped;
}
