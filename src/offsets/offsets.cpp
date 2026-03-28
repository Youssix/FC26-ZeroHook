#include "offsets.h"
#include "../game/game.h"
#include "../log/log.h"
#include "../log/fmt.h"

// ── Globals ─────────────────────────────────────────────────────────
void*         offsets::GameBase      = nullptr;
unsigned long offsets::GameSize      = 0;
void*         offsets::SpoofLocation = nullptr;
void*         offsets::SwapChain     = nullptr;
uintptr_t     offsets::InputReader   = 0;
void*         offsets::FnIsKeyDown        = nullptr;
void*         offsets::FnWasKeyPressed    = nullptr;
void*         offsets::FnWasKeyReleased   = nullptr;
void*         offsets::FnIsMouseDown      = nullptr;
void*         offsets::FnWasMousePressed  = nullptr;
void*         offsets::FnWasMouseReleased = nullptr;
void*         offsets::FnGetMouseX        = nullptr;
void*         offsets::FnGetMouseY        = nullptr;
void*         offsets::FnGetMouseDeltaX   = nullptr;
void*         offsets::FnGetMouseDeltaY   = nullptr;
void*         offsets::FnGetMouseScroll   = nullptr;
uintptr_t     offsets::GameDispatchVTable = 0;
void*         offsets::FnRouteGameMessage = nullptr;
uintptr_t     offsets::PlayerSideVTable   = 0;
void*         offsets::FnPlayerSide       = nullptr;

// ── Helpers ─────────────────────────────────────────────────────────
namespace
{
    uintptr_t resolve_rip(uintptr_t instr, int disp_off, int instr_len)
    {
        int disp = *(int*)(instr + disp_off);
        return instr + instr_len + disp;
    }

    bool is_canonical(uintptr_t addr)
    {
        uintptr_t top = addr >> 47;
        return top == 0 || top == 0x1FFFF;
    }
}

// ── Init ────────────────────────────────────────────────────────────
bool offsets::Init()
{
    char buf[256];

    // ── 1. Game module ──────────────────────────────────────────────
    game::ModuleInfo mod = game::find_module();
    if (!mod.base)
    {
        log::to_file("[offsets] FAIL: game module not found\r\n");
        return false;
    }
    GameBase = mod.base;
    GameSize = mod.size;

    fmt::snprintf(buf, sizeof(buf), "[offsets] Game: %p  size=0x%lX\r\n", GameBase, GameSize);
    log::to_file(buf);

    // ── 2. Spoof gadget (FF 23 = jmp [rbx]) ────────────────────────
    void* gadgetMatch = game::pattern_scan(GameBase, GameSize, "E8 ? ? ? ? FF 23");
    if (gadgetMatch)
        SpoofLocation = (void*)((uintptr_t)gadgetMatch + 5);

    fmt::snprintf(buf, sizeof(buf), "[offsets] SpoofLocation: %p\r\n", SpoofLocation);
    log::to_file(buf);

    // ── 3. SwapChain ────────────────────────────────────────────────
    //   Pattern: mov [rip+disp32], rdi; mov [rip+disp32], r14
    void* scMatch = game::pattern_scan(GameBase, GameSize, "48 89 3D ? ? ? ? 4C 89 35");
    if (scMatch)
    {
        uintptr_t globalAddr = resolve_rip((uintptr_t)scMatch, 3, 7);
        if (globalAddr)
        {
            void* ptr = *(void**)globalAddr;
            if (ptr && is_canonical((uintptr_t)ptr))
                SwapChain = ptr;
        }
    }

    fmt::snprintf(buf, sizeof(buf), "[offsets] SwapChain: %p\r\n", SwapChain);
    log::to_file(buf);

    // ── 4. Frostbite InputReader ────────────────────────────────────
    //   Pattern inside EACoreKeyboardPoller::update:
    //   E8 call → getKeyboardReader → LEA RAX,[RIP+disp] → singleton
    void* irMatch = game::pattern_scan(GameBase, GameSize,
        "E8 ? ? ? ? 48 8D 94 24 ? ? 00 00 48 8B C8 4C 8B 00 41 FF 50 18");
    if (irMatch)
    {
        uintptr_t callSite  = (uintptr_t)irMatch;
        uintptr_t getReader = resolve_rip(callSite, 1, 5);

        // getKeyboardReader: 48 8D 05 [rel32] C3  (lea rax, [rip+disp]; ret)
        if (*(unsigned char*)getReader == 0x48)
        {
            InputReader = resolve_rip(getReader, 3, 7);
        }
        else
        {
            fmt::snprintf(buf, sizeof(buf),
                "[offsets] InputReader: unexpected opcode 0x%02X at %p\r\n",
                *(unsigned char*)getReader, (void*)getReader);
            log::to_file(buf);
        }
    }

    fmt::snprintf(buf, sizeof(buf), "[offsets] InputReader: %p\r\n", (void*)InputReader);
    log::to_file(buf);

    // ── 5. InputReader vtable functions ──────────────────────────────
    if (InputReader)
    {
        void** vtable = *(void***)InputReader;
        if (vtable)
        {
            FnIsKeyDown        = vtable[8];
            FnWasKeyPressed    = vtable[9];
            FnWasKeyReleased   = vtable[10];
            FnIsMouseDown      = vtable[11];
            FnWasMousePressed  = vtable[12];
            FnWasMouseReleased = vtable[13];
            FnGetMouseX        = vtable[22];
            FnGetMouseY        = vtable[23];
            FnGetMouseDeltaX   = vtable[24];
            FnGetMouseDeltaY   = vtable[25];
            FnGetMouseScroll   = vtable[26];

            fmt::snprintf(buf, sizeof(buf), "[offsets] InputReader vtable: %p  isMouseDown=%p\r\n",
                (void*)vtable, FnIsMouseDown);
            log::to_file(buf);
        }
    }

    // ── 6. GameDispatchVTable (RouteGameMessage) ───────────────────
    //   FC26 pattern: E8 ? ? ? ? 48 8D 8B ? ? ? ? FF 15 ? ? ? ? 48 8B CB
    //   resolve call target → +0xD has LEA with RIP-relative → vtable
    void* gdvMatch = game::pattern_scan(GameBase, GameSize,
        "E8 ? ? ? ? 48 8D 8B ? ? ? ? FF 15 ? ? ? ? 48 8B CB");
    if (gdvMatch)
    {
        // Resolve the E8 call target
        uintptr_t callTarget = resolve_rip((uintptr_t)gdvMatch, 1, 5);
        // At callTarget+0xD there's a LEA reg,[rip+disp32] → vtable address
        GameDispatchVTable = resolve_rip(callTarget + 0xD, 3, 7);

        if (GameDispatchVTable && is_canonical(GameDispatchVTable))
        {
            void** vtable = (void**)GameDispatchVTable;
            FnRouteGameMessage = vtable[9];
        }
    }

    fmt::snprintf(buf, sizeof(buf), "[offsets] GameDispatchVTable: %p  RouteGameMessage: %p\r\n",
        (void*)GameDispatchVTable, FnRouteGameMessage);
    log::to_file(buf);

    // ── 7. PlayerSide vtable (vtable[0xD]) ──────────────────────────
    void* psMatch = game::pattern_scan(GameBase, GameSize,
        "48 8D 05 ? ? ? ? 48 8B 71 20 8B EA");
    if (psMatch)
    {
        uintptr_t vtableAddr = resolve_rip((uintptr_t)psMatch, 3, 7);
        if (vtableAddr && is_canonical(vtableAddr))
        {
            PlayerSideVTable = vtableAddr;
            void** vtable = (void**)vtableAddr;
            FnPlayerSide = vtable[0xD];
        }
    }

    fmt::snprintf(buf, sizeof(buf), "[offsets] PlayerSideVTable: %p  FnPlayerSide: %p\r\n",
        (void*)PlayerSideVTable, FnPlayerSide);
    log::to_file(buf);

    return true;
}
