// proclub.cpp — XP Boost + Skills 99 via EPT split hooks
// NoCRT-safe: no std:: anything. Uses CMD_EPT_PATCH_BYTES via NtClose channel.

#include "proclub.h"
#include <intrin.h>
#include "../game/game.h"
#include "../comms/comms.h"
#include "../offsets/offsets.h"
#include "../log/log.h"
#include "../log/fmt.h"

// ── Globals ─────────────────────────────────────────────────────────

namespace proclub
{
    bool g_xpBoost      = false;
    bool g_skills99     = false;
    bool g_searchAlone  = false;
    bool g_xpReady      = false;
    bool g_skillsReady  = false;
    bool g_searchAloneReady = false;
}

namespace
{
    // ── Helpers ──────────────────────────────────────────────────────

    // Find a code cave (run of CC or 00 bytes) that doesn't cross a page boundary.
    // Returns nullptr if none found. `after` skips past a previously used cave.
    unsigned char* FindCave(unsigned char* start, unsigned char* end,
                            int minSize, unsigned char* after = nullptr)
    {
        unsigned char* p = after ? after + 1 : start;
        for (; p + minSize <= end; p++)
        {
            unsigned char fill = p[0];
            if (fill != 0xCC && fill != 0x00) continue;

            bool ok = true;
            for (int j = 1; j < minSize; j++)
            {
                if (p[j] != fill) { ok = false; p += j; break; }
            }
            if (!ok) continue;

            // Must not span a 4 KB page boundary
            unsigned int pageOff = (unsigned int)((uintptr_t)p & 0xFFF);
            if (pageOff + (unsigned int)minSize > 0x1000) continue;

            return p;
        }
        return nullptr;
    }

    // EPT-patch `size` bytes at `addr` on the shadow execute page.
    bool EptPatch(uintptr_t addr, const unsigned char* bytes, int size)
    {
        ept_patch_bytes_params_t params = {};
        params.patch_offset = (unsigned int)(addr & 0xFFF);
        params.patch_size   = (unsigned int)size;
        for (int i = 0; i < size; i++)
            params.patch_bytes[i] = bytes[i];

        implant_request_t req = {};
        req.command = CMD_EPT_PATCH_BYTES;
        req.param1  = (unsigned long long)addr;
        req.param2  = (unsigned long long)&params;
        ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

        return (req.status == 0 && req.result == 1);
    }

    // Write a little-endian int32 into a byte buffer
    void PutI32(unsigned char* dst, int32_t v)
    {
        dst[0] = (unsigned char)(v);
        dst[1] = (unsigned char)(v >> 8);
        dst[2] = (unsigned char)(v >> 16);
        dst[3] = (unsigned char)(v >> 24);
    }

    // Write a little-endian uint64 into a byte buffer
    void PutU64(unsigned char* dst, uint64_t v)
    {
        for (int i = 0; i < 8; i++)
            dst[i] = (unsigned char)(v >> (i * 8));
    }

    // ── XP Boost ────────────────────────────────────────────────────
    //
    // Hooksite pattern: 89 86 ? ? ? ? 41 0F 10 81 ? ? ? ? ...
    //   H+0: mov [rsi+XXXX], eax          (6 bytes — overwritten with JMP+NOP)
    //   H+6: movups xmm0, [r9+0x554]      (8 bytes — untouched, runs normally)
    //
    // Cave payload (flag-based, 41 bytes):
    //   push rax
    //   mov  rax, <&g_xpBoost>
    //   cmp  byte [rax], 0
    //   pop  rax
    //   je   .disabled
    //   mov  dword [r9+0x554], 0x41200000   ; write 10.0f  (XP ×10)
    //   jmp  .done
    // .disabled:
    //   <original 6-byte instruction>
    // .done:
    //   jmp  hooksite+6

    // Track cave used by XP Boost so Skills 99 picks a different one
    unsigned char* g_xpCave = nullptr;

    bool InstallXpBoost(uintptr_t hooksite, unsigned char* gameStart, unsigned char* gameEnd)
    {
        char buf[192];
        constexpr int CAVE_SIZE = 41;
        constexpr int HOOK_OVERWRITE = 6;

        // Read original 6 bytes at hooksite
        unsigned char orig[6];
        __try {
            __movsb(orig, (const unsigned char*)hooksite, 6);
        } __except (1) {
            log::debug("[PROCLUB] XP: failed to read hooksite bytes\r\n");
            return false;
        }

        // Find a cave
        unsigned char* cave = FindCave(gameStart, gameEnd, CAVE_SIZE);
        if (!cave)
        {
            log::debug("[PROCLUB] XP: no code cave found\r\n");
            return false;
        }

        // Verify ±2 GB range for rel32 JMPs
        intptr_t dist = (intptr_t)cave - (intptr_t)(hooksite + 5);
        if (dist > 0x7FFFFFFFL || dist < -(intptr_t)0x7FFFFFFFL)
        {
            log::debug("[PROCLUB] XP: cave too far for rel32\r\n");
            return false;
        }

        fmt::snprintf(buf, sizeof(buf),
            "[PROCLUB] XP: hooksite=%p cave=%p dist=%lld\r\n",
            (void*)hooksite, cave, (long long)dist);
        log::debug(buf);

        // ── Build cave payload ──────────────────────────────────────
        unsigned char payload[CAVE_SIZE];
        __stosb(payload, 0x90, CAVE_SIZE);          // NOP fill
        int off = 0;

        // push rax
        payload[off++] = 0x50;

        // mov rax, <flag_addr>   (48 B8 imm64)
        payload[off++] = 0x48;
        payload[off++] = 0xB8;
        PutU64(&payload[off], (uint64_t)&proclub::g_xpBoost);
        off += 8;
        // off == 11

        // cmp byte [rax], 0     (80 38 00)
        payload[off++] = 0x80;
        payload[off++] = 0x38;
        payload[off++] = 0x00;
        // off == 14

        // pop rax
        payload[off++] = 0x58;
        // off == 15

        // je .disabled           (74 0D)  — skip 13 bytes (11 boost + 2 jmp)
        payload[off++] = 0x74;
        payload[off++] = 0x0D;
        // off == 17

        // ── Enabled: mov dword [r9+0x554], 0x41200000 ──
        // 41 C7 81 54050000 00002041
        payload[off++] = 0x41; payload[off++] = 0xC7; payload[off++] = 0x81;
        payload[off++] = 0x54; payload[off++] = 0x05; payload[off++] = 0x00; payload[off++] = 0x00;
        payload[off++] = 0x00; payload[off++] = 0x00; payload[off++] = 0x20; payload[off++] = 0x41;
        // off == 28

        // jmp .done              (EB 06)  — skip 6 bytes (original instruction)
        payload[off++] = 0xEB;
        payload[off++] = 0x06;
        // off == 30

        // ── .disabled: original 6 bytes ──
        for (int i = 0; i < 6; i++)
            payload[off++] = orig[i];
        // off == 36

        // ── .done: jmp hooksite+6 ──
        payload[off++] = 0xE9;
        PutI32(&payload[off], (int32_t)((hooksite + HOOK_OVERWRITE) - ((uintptr_t)cave + off + 4)));
        off += 4;
        // off == 41

        // ── EPT patch cave ──────────────────────────────────────────
        if (!EptPatch((uintptr_t)cave, payload, CAVE_SIZE))
        {
            log::debug("[PROCLUB] XP: EPT patch cave failed\r\n");
            return false;
        }
        log::debug("[PROCLUB] XP: cave EPT-patched\r\n");

        // ── EPT patch hooksite (E9 rel32 + NOP) ─────────────────────
        unsigned char jmp[6];
        jmp[0] = 0xE9;
        PutI32(&jmp[1], (int32_t)((uintptr_t)cave - (hooksite + 5)));
        jmp[5] = 0x90;

        if (!EptPatch(hooksite, jmp, HOOK_OVERWRITE))
        {
            log::debug("[PROCLUB] XP: EPT patch hooksite failed\r\n");
            return false;
        }
        g_xpCave = cave;
        log::debug("[PROCLUB] XP Boost EPT hook installed\r\n");
        return true;
    }

    // ── Skills 99 ───────────────────────────────────────────────────
    //
    // Hooksite pattern: 88 1E 48 FF C6
    //   H+0: mov [rsi], bl     (2 bytes)
    //   H+2: inc rsi           (3 bytes)   — total 5 bytes overwritten
    //
    // Cave payload (flag-based, 32 bytes):
    //   push rax
    //   mov  rax, <&g_skills99>
    //   cmp  byte [rax], 0
    //   pop  rax
    //   je   .disabled
    //   mov  byte [rsi], 0x63       ; 99 decimal
    //   jmp  .done
    // .disabled:
    //   mov  [rsi], bl              ; original
    // .done:
    //   inc  rsi
    //   jmp  hooksite+5

    bool InstallSkills99(uintptr_t hooksite, unsigned char* gameStart, unsigned char* gameEnd)
    {
        char buf[192];
        constexpr int CAVE_SIZE = 32;
        constexpr int HOOK_OVERWRITE = 5;

        // Find a cave (after the one used by XP Boost, if any)
        unsigned char* cave = FindCave(gameStart, gameEnd, CAVE_SIZE, g_xpCave);
        if (!cave)
        {
            log::debug("[PROCLUB] Skills99: no code cave found\r\n");
            return false;
        }

        intptr_t dist = (intptr_t)cave - (intptr_t)(hooksite + 5);
        if (dist > 0x7FFFFFFFL || dist < -(intptr_t)0x7FFFFFFFL)
        {
            log::debug("[PROCLUB] Skills99: cave too far for rel32\r\n");
            return false;
        }

        fmt::snprintf(buf, sizeof(buf),
            "[PROCLUB] Skills99: hooksite=%p cave=%p dist=%lld\r\n",
            (void*)hooksite, cave, (long long)dist);
        log::debug(buf);

        // ── Build cave payload ──────────────────────────────────────
        unsigned char payload[CAVE_SIZE];
        __stosb(payload, 0x90, CAVE_SIZE);
        int off = 0;

        // push rax
        payload[off++] = 0x50;

        // mov rax, <flag_addr>
        payload[off++] = 0x48;
        payload[off++] = 0xB8;
        PutU64(&payload[off], (uint64_t)&proclub::g_skills99);
        off += 8;
        // off == 11

        // cmp byte [rax], 0
        payload[off++] = 0x80;
        payload[off++] = 0x38;
        payload[off++] = 0x00;
        // off == 14

        // pop rax
        payload[off++] = 0x58;
        // off == 15

        // je .disabled            (74 05) — skip 5 bytes (3 mov + 2 jmp)
        payload[off++] = 0x74;
        payload[off++] = 0x05;
        // off == 17

        // ── Enabled: mov byte [rsi], 0x63 ──
        payload[off++] = 0xC6;
        payload[off++] = 0x06;
        payload[off++] = 0x63;
        // off == 20

        // jmp .done               (EB 02) — skip 2 bytes (original mov)
        payload[off++] = 0xEB;
        payload[off++] = 0x02;
        // off == 22

        // ── .disabled: mov [rsi], bl ──
        payload[off++] = 0x88;
        payload[off++] = 0x1E;
        // off == 24

        // ── .done: inc rsi ──
        payload[off++] = 0x48;
        payload[off++] = 0xFF;
        payload[off++] = 0xC6;
        // off == 27

        // jmp hooksite+5
        payload[off++] = 0xE9;
        PutI32(&payload[off], (int32_t)((hooksite + HOOK_OVERWRITE) - ((uintptr_t)cave + off + 4)));
        off += 4;
        // off == 32

        // ── EPT patch cave ──────────────────────────────────────────
        if (!EptPatch((uintptr_t)cave, payload, CAVE_SIZE))
        {
            log::debug("[PROCLUB] Skills99: EPT patch cave failed\r\n");
            return false;
        }
        log::debug("[PROCLUB] Skills99: cave EPT-patched\r\n");

        // ── EPT patch hooksite (E9 rel32) ────────────────────────────
        unsigned char jmp[5];
        jmp[0] = 0xE9;
        PutI32(&jmp[1], (int32_t)((uintptr_t)cave - (hooksite + 5)));

        if (!EptPatch(hooksite, jmp, HOOK_OVERWRITE))
        {
            log::debug("[PROCLUB] Skills99: EPT patch hooksite failed\r\n");
            return false;
        }
        log::debug("[PROCLUB] Skills 99 EPT hook installed\r\n");
        return true;
    }

    // ── Search Game Alone ───────────────────────────────────────────
    //
    // Single byte patch: JNZ (0x75) → JZ (0x74) at pattern match.
    // No cave needed — just EPT-patch the one byte on toggle change.

    uintptr_t g_searchAloneAddr = 0;
}

// ── Public Init ─────────────────────────────────────────────────────

bool proclub::Init(void* gameBase, unsigned long gameSize)
{
    char buf[192];
    log::debug("[PROCLUB] Scanning patterns...\r\n");

    unsigned char* base = (unsigned char*)gameBase;
    unsigned char* end  = base + gameSize;

    // ── XP Boost ────────────────────────────────────────────────────
    uintptr_t xpHook = 0;
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "89 86 ? ? ? ? 41 0F 10 81 ? ? ? ? 0F 11 86 ? ? ? ? 41 0F 10 89");
        if (m)
        {
            xpHook = (uintptr_t)m;
            fmt::snprintf(buf, sizeof(buf), "[PROCLUB] XP hooksite: %p\r\n", m);
            log::debug(buf);
        }
        else
            log::debug("[PROCLUB] ERROR: XP Boost pattern not found\r\n");
    }

    // ── Skills 99 ───────────────────────────────────────────────────
    uintptr_t skillsHook = 0;
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "88 1E 48 FF C6");
        if (m)
        {
            skillsHook = (uintptr_t)m;
            fmt::snprintf(buf, sizeof(buf), "[PROCLUB] Skills hooksite: %p\r\n", m);
            log::debug(buf);
        }
        else
            log::debug("[PROCLUB] ERROR: Skills 99 pattern not found\r\n");
    }

    // ── Search Game Alone ────────────────────────────────────────────
    {
        void* m = game::pattern_scan(gameBase, gameSize,
            "75 ? 83 FF ? 73 ? 48 8D 8B ? ? ? ? 0F BE 41");
        if (m)
        {
            g_searchAloneAddr = (uintptr_t)m;
            g_searchAloneReady = true;
            fmt::snprintf(buf, sizeof(buf), "[PROCLUB] SearchAlone: %p\r\n", m);
            log::debug(buf);
        }
        else
            log::debug("[PROCLUB] ERROR: SearchAlone pattern not found\r\n");
    }

    // ── Install EPT hooks ───────────────────────────────────────────
    if (xpHook)
        g_xpReady = InstallXpBoost(xpHook, base, end);

    if (skillsHook)
        g_skillsReady = InstallSkills99(skillsHook, base, end);

    fmt::snprintf(buf, sizeof(buf),
        "[PROCLUB] Init done — XP:%s Skills99:%s SearchAlone:%s\r\n",
        g_xpReady ? "OK" : "FAIL",
        g_skillsReady ? "OK" : "FAIL",
        g_searchAloneReady ? "OK" : "FAIL");
    log::debug(buf);

    return g_xpReady || g_skillsReady || g_searchAloneReady;
}

// ── Per-frame Update ────────────────────────────────────────────────

void proclub::Update()
{
    // SearchAlone: EPT-patch single byte only when toggle state changes
    static bool prevSearchAlone = false;
    if (g_searchAloneReady && g_searchAlone != prevSearchAlone)
    {
        unsigned char byte = g_searchAlone ? 0x74 : 0x75;  // JZ : JNZ
        EptPatch(g_searchAloneAddr, &byte, 1);
        prevSearchAlone = g_searchAlone;

        char buf[96];
        fmt::snprintf(buf, sizeof(buf), "[PROCLUB] SearchAlone %s (0x%02X)\r\n",
            g_searchAlone ? "ON" : "OFF", byte);
        log::debug(buf);
    }
}
