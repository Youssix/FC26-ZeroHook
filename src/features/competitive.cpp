// competitive.cpp — Competitive Settings Unlock via vtable pointer swap
// NoCRT-safe: no std:: anything. Uses CMD_WRITE_MEMORY via NtClose channel.

#include "competitive.h"
#include <intrin.h>
#include <Windows.h>
#include "../game/game.h"
#include "../comms/comms.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"

namespace
{
    // Checker function found by pattern scan
    uintptr_t g_checkerAddr = 0;

    // Address of the vtable slot pointing to checker
    uintptr_t g_vtableSlotAddr = 0;

    // Original value stored in the vtable slot (== g_checkerAddr)
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

    // Scan .rdata section for an 8-byte value matching target
    uintptr_t FindVtableEntry(void* gameBase, unsigned long gameSize, uintptr_t target)
    {
        auto dos = (PIMAGE_DOS_HEADER)gameBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto nt = (PIMAGE_NT_HEADERS)((uintptr_t)gameBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
        {
            // Look for .rdata section
            bool isRdata = (section->Name[0] == '.' &&
                            section->Name[1] == 'r' &&
                            section->Name[2] == 'd' &&
                            section->Name[3] == 'a' &&
                            section->Name[4] == 't' &&
                            section->Name[5] == 'a');
            if (!isRdata) continue;

            uintptr_t scanBase = (uintptr_t)gameBase + section->VirtualAddress;
            uintptr_t scanEnd = scanBase + section->Misc.VirtualSize;
            if (scanEnd > (uintptr_t)gameBase + gameSize)
                scanEnd = (uintptr_t)gameBase + gameSize;

            // Scan aligned 8-byte values
            for (uintptr_t addr = scanBase; addr + 8 <= scanEnd; addr += 8)
            {
                unsigned long long val = 0;
                if (SafeRead8(addr, &val) && val == (unsigned long long)target)
                    return addr;
            }
        }
        return 0;
    }

    // Scan game module for 33 C0 C3 (xor eax,eax; ret)
    uintptr_t FindRetZeroGadget(void* gameBase, unsigned long gameSize)
    {
        unsigned char* base = (unsigned char*)gameBase;
        unsigned char* end = base + gameSize;

        for (unsigned char* p = base; p + 3 <= end; p++)
        {
            // 33 C0 C3 = xor eax,eax; ret
            if (p[0] == 0x33 && p[1] == 0xC0 && p[2] == 0xC3)
                return (uintptr_t)p;
            // 31 C0 C3 = xor eax,eax; ret (alternate encoding)
            if (p[0] == 0x31 && p[1] == 0xC0 && p[2] == 0xC3)
                return (uintptr_t)p;
        }
        return 0;
    }
}

bool competitive::Init(void* gameBase, unsigned long gameSize)
{
    char buf[256];
    initialized = false;

    if (!gameBase || !gameSize) {
        log::to_file("[COMP] Init: no game module\r\n");
        return false;
    }

    log::to_file("[COMP] Scanning competitive checker pattern...\r\n");

    // 1. Pattern scan to find the checker function
    void* match = game::pattern_scan(gameBase, gameSize,
        "48 89 5C 24 10 48 89 6C 24 18 56 57 41 56 48 83 EC 20 4C 8B F1 C6 44 24 40 00 E8");
    if (!match) {
        log::to_file("[COMP] ERROR: checker pattern not found\r\n");
        return false;
    }

    g_checkerAddr = (uintptr_t)match;
    fmt::snprintf(buf, sizeof(buf), "[COMP] Checker function: %p\r\n", (void*)g_checkerAddr);
    log::to_file(buf);

    // 2. Find the vtable entry in .rdata that points to checker
    g_vtableSlotAddr = FindVtableEntry(gameBase, gameSize, g_checkerAddr);
    if (!g_vtableSlotAddr) {
        log::to_file("[COMP] ERROR: vtable entry for checker not found in .rdata\r\n");
        return false;
    }

    fmt::snprintf(buf, sizeof(buf), "[COMP] Vtable slot: %p\r\n", (void*)g_vtableSlotAddr);
    log::to_file(buf);

    // Save original value
    g_originalValue = (unsigned long long)g_checkerAddr;

    // 3. Find xor eax,eax; ret gadget in game module
    g_gadgetAddr = FindRetZeroGadget(gameBase, gameSize);
    if (!g_gadgetAddr) {
        log::to_file("[COMP] ERROR: xor eax,eax; ret gadget not found\r\n");
        return false;
    }

    fmt::snprintf(buf, sizeof(buf), "[COMP] Gadget (ret 0): %p\r\n", (void*)g_gadgetAddr);
    log::to_file(buf);

    initialized = true;
    g_swapped = false;
    log::to_file("[COMP] Init OK\r\n");
    return true;
}

bool competitive::IsReady()
{
    return initialized;
}

void competitive::SetEnabled(bool enable)
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
            unlockEnabled = true;
            toast::Show(toast::Type::Success, "Competitive settings unlocked");
            log::to_file("[COMP] Enabled: vtable swapped to gadget\r\n");
        } else {
            fmt::snprintf(buf, sizeof(buf), "[COMP] ERROR: write failed (status=%u)\r\n", req.status);
            log::to_file(buf);
            unlockEnabled = false;
            toast::Show(toast::Type::Error, "Competitive unlock failed");
        }
    }
    else if (!enable && g_swapped)
    {
        // Restore original checker address
        implant_request_t req = {};
        req.command = CMD_WRITE_MEMORY;
        req.param1 = (unsigned long long)g_vtableSlotAddr;
        req.param2 = g_originalValue;
        req.param3 = 8;
        ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

        if (req.status == 0) {
            g_swapped = false;
            unlockEnabled = false;
            toast::Show(toast::Type::Info, "Competitive settings restored");
            log::to_file("[COMP] Disabled: vtable restored\r\n");
        } else {
            fmt::snprintf(buf, sizeof(buf), "[COMP] ERROR: restore failed (status=%u)\r\n", req.status);
            log::to_file(buf);
            unlockEnabled = true;
            toast::Show(toast::Type::Error, "Competitive restore failed");
        }
    }
}

bool competitive::IsEnabled()
{
    return g_swapped;
}
