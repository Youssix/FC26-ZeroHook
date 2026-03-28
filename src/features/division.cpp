// division.cpp -- Division Spoofer (EPT vtable hook) + Coop Rivals (byte patch)
// Ported from FC26-Internal: hooks divspoofer vtable[54], writes isElite/srPoints/progressionRank
// NoCRT-safe: no std:: anything.

#include "division.h"
#include "rage.h"
#include "../log/log.h"
#include "../log/fmt.h"
#include "../menu/toast.h"
#include "../game/game.h"
#include "../hook/ept_hook.h"
#include "../comms/comms.h"
#include "../offsets/offsets.h"
#include <intrin.h>

// ── Division data table ─────────────────────────────────────────────
namespace
{
    struct DivisionData {
        unsigned int isElite;
        unsigned int srPoints;
        unsigned int progressionRank;
        const char* name;
    };

    const DivisionData divisions[] = {
        { 0, 0, 0, "None" },
        { 0x01, 0x00000000, 0x00000001, "DIV 10" },
        { 0x01, 0x00000000, 0x00000005, "DIV 9" },
        { 0x01, 0x00000000, 0x0000000B, "DIV 8" },
        { 0x01, 0x00000000, 0x00000013, "DIV 7" },
        { 0x01, 0x00000000, 0x0000001D, "DIV 6" },
        { 0x01, 0x00000000, 0x00000029, "DIV 5" },
        { 0x01, 0x00000000, 0x00000035, "DIV 4" },
        { 0x01, 0x00000000, 0x00000041, "DIV 3" },
        { 0x01, 0x00000000, 0x0000004D, "DIV 2" },
        { 0x01, 0x00000000, 0x0000005A, "DIV 1" },
        { 0x02, 0x000001F4, 0x00000067, "ELITE 500" },
        { 0x02, 0x00000BB8, 0x00000067, "ELITE 3000" },
    };

    constexpr int DIV_COUNT = sizeof(divisions) / sizeof(divisions[0]);

    // ── Pattern-scanned addresses ───────────────────────────────────
    uintptr_t g_divspooferVtable = 0;   // vtable address (from pattern)
    uintptr_t g_divspooferFunc   = 0;   // vtable[54] function pointer
    uintptr_t g_coopRivalsAddr   = 0;   // coop rivals JZ/JNZ address

    bool g_hookInstalled   = false;
    bool g_coopRivalsActive = false;
    uint8_t g_coopOrigByte = 0x84;      // original JZ opcode byte

    // EPT hook params (page-aligned for hypervisor comms)
    __declspec(align(4096)) ept::ept_hook_install_params_t g_divHookParams = {};

    // ── Helper: resolve RIP-relative LEA (48 8D xx [disp32]) ────────
    uintptr_t resolve_rip3_7(uintptr_t addr)
    {
        if (!addr) return 0;
        int32_t disp = *reinterpret_cast<int32_t*>(addr + 3);
        return addr + 7 + disp;
    }

    // ── EPT Hook detour ─────────────────────────────────────────────
    // Called by the EPT stub with the original function's register context.
    // FC26-Internal hooks vtable[54] which is: bool __fastcall fn(__int64 a1, __int64 a2)
    // We intercept and write division values to the a2 struct.
    // Return 0 = pass through to original function.
    extern "C" unsigned long long DivSpooferDetour(
        void* ctx,
        unsigned long long a1,
        unsigned long long a2)
    {
        if (division::selectedDivision > 0 && division::selectedDivision < DIV_COUNT && a2)
        {
            __try {
                *reinterpret_cast<unsigned int*>(a2 + 0x34)  = division::isElite;
                *reinterpret_cast<unsigned int*>(a2 - 0x18)  = division::srPoints;
                *reinterpret_cast<unsigned int*>(a2 - 0x240) = division::progressionRank;

                static bool s_toasted = false;
                if (!s_toasted) {
                    toast::Show(toast::Type::Success, "Division spoof applied");
                    s_toasted = true;
                }
            } __except(1) {}
        }

        return 0; // pass through to original
    }
}

// ── Public API ──────────────────────────────────────────────────────

const char* division::GetDivisionName(int idx)
{
    // NOTE: divisions[].name contains unrelocated pointers in manually mapped DLL.
    // Use g_divLabels from overlay.cpp instead for UI display.
    (void)idx;
    return "???";
}

int division::GetDivisionCount()
{
    return DIV_COUNT;
}

bool division::Init(void* gameBase, unsigned long gameSize)
{
    char buf[256];
    initialized = false;

    if (!gameBase || !gameSize) {
        log::debug("[DIV] Init: no game module\r\n");
        return false;
    }

    log::debug("[DIV] Scanning patterns...\r\n");

    // 1. divspoofer_vtable pattern: "48 8D 0D ? ? ? ? 33 ED 8B C5"
    //    This is a LEA RCX,[rip+disp32] that loads the vtable address
    void* m1 = game::pattern_scan(gameBase, gameSize,
        "48 8D 0D ? ? ? ? 33 ED 8B C5");
    if (m1) {
        g_divspooferVtable = resolve_rip3_7((uintptr_t)m1);
        fmt::snprintf(buf, sizeof(buf), "[DIV] divspoofer_vtable: %p\r\n", (void*)g_divspooferVtable);
        log::debug(buf);

        // Read vtable[54] -- the function we need to hook
        if (g_divspooferVtable) {
            __try {
                uintptr_t* vtable = reinterpret_cast<uintptr_t*>(g_divspooferVtable);
                g_divspooferFunc = vtable[54];
                fmt::snprintf(buf, sizeof(buf), "[DIV] vtable[54] thunk: %p\r\n", (void*)g_divspooferFunc);
                log::debug(buf);

                // vtable[54] is a thunk: mov rcx, rdx (48 89 D1); jmp real_func (E9 xx xx xx xx)
                // EPT hook needs >= 14 bytes prologue, thunk is only 8 bytes.
                // Follow the JMP to reach the real function with a proper prologue.
                unsigned char* fn = reinterpret_cast<unsigned char*>(g_divspooferFunc);
                if (fn[0] == 0x48 && fn[1] == 0x89 && fn[2] == 0xD1 && fn[3] == 0xE9) {
                    int32_t rel = *reinterpret_cast<int32_t*>(fn + 4);
                    g_divspooferFunc = (uintptr_t)(fn + 8 + rel);
                    fmt::snprintf(buf, sizeof(buf), "[DIV] vtable[54] real func: %p\r\n", (void*)g_divspooferFunc);
                    log::debug(buf);
                }
            } __except(1) {
                log::debug("[DIV] ERROR: exception reading vtable[54]\r\n");
                g_divspooferFunc = 0;
            }
        }
    } else {
        log::debug("[DIV] WARNING: divspoofer_vtable pattern not found\r\n");
    }

    // 2. Coop Rivals pattern: "0F 84 ? ? ? ? 49 8B 45 ? 49 8B CD FF 90 ? ? ? ? 89 45"
    //    This is a JZ instruction we patch to JNZ
    void* m2 = game::pattern_scan(gameBase, gameSize,
        "0F 84 ? ? ? ? 49 8B 45 ? 49 8B CD FF 90 ? ? ? ? 89 45");
    if (m2) {
        g_coopRivalsAddr = (uintptr_t)m2;
        fmt::snprintf(buf, sizeof(buf), "[DIV] coop_rivals_addr: %p\r\n", (void*)g_coopRivalsAddr);
        log::debug(buf);
    } else {
        log::debug("[DIV] WARNING: coop_rivals pattern not found\r\n");
    }

    initialized = (g_divspooferFunc != 0);

    fmt::snprintf(buf, sizeof(buf), "[DIV] Init %s (vtable=%d coop=%d)\r\n",
        initialized ? "OK" : "PARTIAL",
        g_divspooferFunc != 0 ? 1 : 0,
        g_coopRivalsAddr != 0 ? 1 : 0);
    log::debug(buf);

    return initialized;
}

bool division::IsReady()
{
    return initialized;
}

bool division::InstallHook()
{
    if (!initialized || !g_divspooferFunc) {
        log::debug("[DIV] InstallHook: not initialized\r\n");
        return false;
    }

    if (g_hookInstalled) {
        log::debug("[DIV] InstallHook: already installed\r\n");
        return true;
    }

    bool ok = ept::install_hook(g_divHookParams,
        reinterpret_cast<unsigned char*>(g_divspooferFunc),
        (void*)&DivSpooferDetour, "DivSpoofer");

    if (ok) {
        g_hookInstalled = true;
        log::debug("[DIV] EPT hook installed on divspoofer vtable[54]\r\n");
        toast::Show(toast::Type::Success, "Division spoofer hook active");
    } else {
        log::debug("[DIV] ERROR: EPT hook install failed\r\n");
        toast::Show(toast::Type::Error, "Division hook failed");
    }

    return ok;
}

bool division::IsHooked()
{
    return g_hookInstalled;
}

void division::UpdateValues(int divIndex)
{
    if (divIndex <= 0 || divIndex >= DIV_COUNT) {
        // Reset to defaults (DIV 10)
        isElite = 0x01;
        srPoints = 0x00000000;
        progressionRank = 0x00000001;
        return;
    }

    const DivisionData& div = divisions[divIndex];
    isElite = div.isElite;
    srPoints = div.srPoints;
    progressionRank = div.progressionRank;

    char buf[128];
    fmt::snprintf(buf, sizeof(buf), "[DIV] Values: elite=%u sr=%u prog=%u idx=%d\r\n",
        isElite, srPoints, progressionRank, divIndex);
    log::debug(buf);
}

void division::SetCoopRivals(bool enable)
{
    if (!g_coopRivalsAddr) {
        toast::Show(toast::Type::Error, "Coop Rivals addr not found");
        return;
    }

    // The pattern is "0F 84 ..." (JZ) -- we patch the second byte from 0x84 (JZ) to 0x85 (JNZ)
    // Use CMD_WRITE_MEMORY to write through the hypervisor for safety
    uintptr_t patchAddr = g_coopRivalsAddr + 1; // byte after the 0x0F prefix

    if (enable && !g_coopRivalsActive) {
        // Read original byte first
        __try {
            g_coopOrigByte = *reinterpret_cast<uint8_t*>(patchAddr);
        } __except(1) {
            g_coopOrigByte = 0x84;
        }

        // Patch to 0x85 (JNZ)
        implant_request_t req = {};
        req.command = CMD_WRITE_MEMORY;
        req.param1 = (unsigned long long)patchAddr;
        req.param2 = 0x85;
        req.param3 = 1;
        ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

        if (req.status == 0) {
            g_coopRivalsActive = true;
            toast::Show(toast::Type::Success, "Coop Rivals enabled");
            log::debug("[DIV] Coop Rivals: JZ -> JNZ\r\n");
        } else {
            char buf[128];
            fmt::snprintf(buf, sizeof(buf), "[DIV] Coop Rivals write failed (status=%u)\r\n", req.status);
            log::debug(buf);
            toast::Show(toast::Type::Error, "Coop Rivals patch failed");
        }
    }
    else if (!enable && g_coopRivalsActive) {
        // Restore original byte
        implant_request_t req = {};
        req.command = CMD_WRITE_MEMORY;
        req.param1 = (unsigned long long)patchAddr;
        req.param2 = (unsigned long long)g_coopOrigByte;
        req.param3 = 1;
        ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

        if (req.status == 0) {
            g_coopRivalsActive = false;
            toast::Show(toast::Type::Info, "Coop Rivals disabled");
            log::debug("[DIV] Coop Rivals: restored original\r\n");
        } else {
            char buf[128];
            fmt::snprintf(buf, sizeof(buf), "[DIV] Coop Rivals restore failed (status=%u)\r\n", req.status);
            log::debug(buf);
            toast::Show(toast::Type::Error, "Coop Rivals restore failed");
        }
    }
}

bool division::IsCoopRivalsEnabled()
{
    return g_coopRivalsActive;
}

void division::Apply()
{
    if (selectedDivision <= 0 || selectedDivision >= DIV_COUNT) {
        toast::Show(toast::Type::Warning, "Select a division first");
        return;
    }

    // Update the spoofed values
    UpdateValues(selectedDivision);

    // If hook is installed, spoofer is live -- values will be applied automatically
    if (g_hookInstalled) {
        toast::Show(toast::Type::Success, "Division spoof applied");
    } else {
        toast::Show(toast::Type::Warning, "Hook not installed - click Install Hook first");
    }
}
