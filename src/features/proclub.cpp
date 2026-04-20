// proclub.cpp — Pro Club features (Premium only)
// SearchAlone      : single-byte EPT patch JNZ ↔ JZ.
// Skills 99        : EPT code-cave hook  mov [rsi],bl → mov byte [rsi],0x63.
// XP Boost         : EPT code-cave hook  movups xmm0,[r9+d] → write 10.0f.
// Tournament Spoof : EPT code-cave hook  force rax=0 → Round of 16.
// NoCRT-safe — no std::, no memset/memcpy.

#include "proclub.h"

#include <intrin.h>
#include "../game/game.h"
#include "../log/log.h"
#include "../log/fmt.h"

bool proclub::g_searchAlone      = false;
bool proclub::g_searchAloneReady = false;
bool proclub::g_skills99         = false;
bool proclub::g_skills99Ready    = false;
bool proclub::g_xpBoost          = false;
bool proclub::g_xpBoostReady     = false;
bool proclub::g_tournamentSpoof      = false;
bool proclub::g_tournamentSpoofReady = false;
bool proclub::g_spoofEAID            = false;
char proclub::g_spoofEAIDText[22]    = {};

namespace
{
    uintptr_t g_searchAloneAddr = 0;

    // Skills 99
    uintptr_t g_skills99Hooksite = 0;
    uintptr_t g_skills99Cave    = 0;
    unsigned char g_skills99OrigBytes[5] = {};

    // XP Boost
    uintptr_t g_xpBoostHooksite = 0;
    uintptr_t g_xpBoostCave     = 0;
    unsigned char g_xpBoostOrigBytes[8] = {};
    unsigned char g_xpBoostDisp[4] = {};

    // Tournament Spoof
    uintptr_t g_tourneyHooksite = 0;
    uintptr_t g_tourneyCave     = 0;
    unsigned char g_tourneyOrigBytes[5] = {};

    void log_bytes(const char* label, uintptr_t addr,
                   const unsigned char* bytes, int size)
    {
        if (!g_debugLog) return;
        char buf[256];
        int pos = fmt::snprintf(buf, sizeof(buf), "[PROCLUB] %s @%p [%d]: ",
            label, (void*)addr, size);
        for (int i = 0; i < size && pos + 4 < (int)sizeof(buf); i++)
            pos += fmt::snprintf(buf + pos, sizeof(buf) - pos,
                "%02X ", bytes[i]);
        pos += fmt::snprintf(buf + pos, sizeof(buf) - pos, "\r\n");
        log::debug(buf);
    }
}

bool proclub::Init(void* gameBase, unsigned long gameSize)
{
    // --- Search Alone ---
    log::debug("[PROCLUB] Scanning SearchAlone pattern...\r\n");
    void* m = game::pattern_scan(gameBase, gameSize,
        "75 ? 83 FF ? 73 ? 48 8D 8B ? ? ? ? 0F BE 41");
    if (m)
    {
        g_searchAloneAddr  = (uintptr_t)m;
        g_searchAloneReady = true;
        log::debugf("[PROCLUB] SearchAlone: %p\r\n", m);
    }
    else
        log::debug("[PROCLUB] ERROR: SearchAlone pattern not found\r\n");

    // --- Skills 99 ---
    log::debug("[PROCLUB] Scanning Skills99 pattern (88 1E 48 FF C6)...\r\n");
    void* s = game::pattern_scan(gameBase, gameSize, "88 1E 48 FF C6");
    if (s)
    {
        g_skills99Hooksite = (uintptr_t)s;
        for (int i = 0; i < 5; i++)
            g_skills99OrigBytes[i] = ((unsigned char*)s)[i];

        log_bytes("Skills99 orig bytes", (uintptr_t)s, g_skills99OrigBytes, 5);

        void* cave = game::find_code_cave(gameBase, gameSize, 14, 11);
        if (cave)
        {
            intptr_t dist = (intptr_t)cave - (intptr_t)((unsigned char*)s + 5);
            if (dist > 0x7FFFFFFFL || dist < -(intptr_t)0x7FFFFFFFL)
            {
                log::debugf(
                    "[PROCLUB] ERROR: Skills99 cave too far (dist=%llX)\r\n",
                    (unsigned long long)dist);
            }
            else
            {
                g_skills99Cave  = (uintptr_t)cave;
                g_skills99Ready = true;
                log::debugf(
                    "[PROCLUB] Skills99: hooksite=%p cave=%p dist=%llX\r\n",
                    s, cave, (unsigned long long)dist);
            }
        }
        else
            log::debug("[PROCLUB] ERROR: No code cave found for Skills99\r\n");
    }
    else
        log::debug("[PROCLUB] ERROR: Skills99 pattern not found\r\n");

    // --- XP Boost ---
    // Original: movups xmm0, [r9+disp32]  =  41 0F 10 81 [disp32]  (8 bytes)
    // Cave writes 10.0f into [r9+disp32] then executes the original movups.
    log::debug("[PROCLUB] Scanning XPBoost pattern...\r\n");
    void* x = game::pattern_scan(gameBase, gameSize,
        "41 0F 10 81 ? ? ? ? 0F 11 86 ? ? ? ? 41 0F 10 89 ? ? ? ? 0F 11 8E ? ? ? ? 41 0F 10 81 ? ? ? ? 0F 11 86 ? ? ? ? 41 0F 10 89");
    if (x)
    {
        g_xpBoostHooksite = (uintptr_t)x;
        for (int i = 0; i < 8; i++)
            g_xpBoostOrigBytes[i] = ((unsigned char*)x)[i];
        // Read the displacement from the instruction (bytes 4-7)
        for (int i = 0; i < 4; i++)
            g_xpBoostDisp[i] = ((unsigned char*)x)[4 + i];

        log_bytes("XPBoost orig bytes", (uintptr_t)x, g_xpBoostOrigBytes, 8);
        log_bytes("XPBoost disp32", (uintptr_t)x + 4, g_xpBoostDisp, 4);

        // 24-byte payload: mov [r9+disp],10.0f (11) + movups (8) + E9 (5)
        void* cave = game::find_code_cave(gameBase, gameSize, 28, 24);
        if (cave)
        {
            intptr_t dist = (intptr_t)cave - (intptr_t)((unsigned char*)x + 8);
            if (dist > 0x7FFFFFFFL || dist < -(intptr_t)0x7FFFFFFFL)
            {
                log::debugf(
                    "[PROCLUB] ERROR: XPBoost cave too far (dist=%llX)\r\n",
                    (unsigned long long)dist);
            }
            else
            {
                g_xpBoostCave  = (uintptr_t)cave;
                g_xpBoostReady = true;
                log::debugf(
                    "[PROCLUB] XPBoost: hooksite=%p cave=%p dist=%llX\r\n",
                    x, cave, (unsigned long long)dist);
            }
        }
        else
            log::debug("[PROCLUB] ERROR: No code cave found for XPBoost\r\n");
    }
    else
        log::debug("[PROCLUB] ERROR: XPBoost pattern not found\r\n");

    // --- Tournament Spoof ---
    // Original: xor edx,edx (33 D2) + movsxd r12,eax (4C 63 E0)  =  5 bytes
    // Cave: mov rax,0 (7) + xor edx,edx (2) + movsxd r12,eax (3) + E9 (5) = 17 bytes
    log::debug("[PROCLUB] Scanning TournamentSpoof pattern...\r\n");
    void* t = game::pattern_scan(gameBase, gameSize, "33 D2 4C 63 E0");
    if (t)
    {
        g_tourneyHooksite = (uintptr_t)t;
        for (int i = 0; i < 5; i++)
            g_tourneyOrigBytes[i] = ((unsigned char*)t)[i];

        log_bytes("Tourney orig bytes", (uintptr_t)t, g_tourneyOrigBytes, 5);

        void* cave = game::find_code_cave(gameBase, gameSize, 20, 17);
        if (cave)
        {
            intptr_t dist = (intptr_t)cave - (intptr_t)((unsigned char*)t + 5);
            if (dist > 0x7FFFFFFFL || dist < -(intptr_t)0x7FFFFFFFL)
            {
                log::debugf(
                    "[PROCLUB] ERROR: Tourney cave too far (dist=%llX)\r\n",
                    (unsigned long long)dist);
            }
            else
            {
                g_tourneyCave = (uintptr_t)cave;
                g_tournamentSpoofReady = true;
                log::debugf(
                    "[PROCLUB] Tourney: hooksite=%p cave=%p dist=%llX\r\n",
                    t, cave, (unsigned long long)dist);
            }
        }
        else
            log::debug("[PROCLUB] ERROR: No code cave found for Tourney\r\n");
    }
    else
        log::debug("[PROCLUB] ERROR: TournamentSpoof pattern not found\r\n");

    return g_searchAloneReady || g_skills99Ready || g_xpBoostReady
        || g_tournamentSpoofReady;
}

void proclub::Update()
{
    // --- Search Alone ---
    {
        static bool prev = false;
        if (g_searchAloneReady && g_searchAlone != prev)
        {
            unsigned char byte = g_searchAlone ? 0x74 : 0x75;
            bool ok = game::ept_patch(g_searchAloneAddr, &byte, 1);
            prev = g_searchAlone;
            log::debugf(
                "[PROCLUB] SearchAlone %s — wrote 0x%02X @%p (ok=%d)\r\n",
                g_searchAlone ? "ON" : "OFF", byte,
                (void*)g_searchAloneAddr, ok);
        }
    }

    // --- Skills 99 ---
    {
        static bool prevS = false;
        if (g_skills99Ready && g_skills99 != prevS)
        {
            if (g_skills99)
            {
                unsigned char payload[11];
                payload[0] = 0xC6;
                payload[1] = 0x06;
                payload[2] = 0x63;  // 99
                payload[3] = 0x48;
                payload[4] = 0xFF;
                payload[5] = 0xC6;
                int backRel = (int)((long long)(g_skills99Hooksite + 5)
                                  - (long long)(g_skills99Cave + 11));
                payload[6] = 0xE9;
                payload[7] = ((unsigned char*)&backRel)[0];
                payload[8] = ((unsigned char*)&backRel)[1];
                payload[9] = ((unsigned char*)&backRel)[2];
                payload[10]= ((unsigned char*)&backRel)[3];

                log::debugf(
                    "[PROCLUB] Skills99 backRel=0x%08X fwd hooksite+5=%p cave+11=%p\r\n",
                    (unsigned int)backRel,
                    (void*)(g_skills99Hooksite + 5),
                    (void*)(g_skills99Cave + 11));
                log_bytes("Skills99 cave payload", g_skills99Cave, payload, 11);

                bool ok = game::ept_patch(g_skills99Cave, payload, 11);
                if (ok)
                {
                    log::debug("[PROCLUB] Skills99 cave OK\r\n");

                    unsigned char jmp[5];
                    int fwdRel = (int)((long long)g_skills99Cave
                                     - (long long)(g_skills99Hooksite + 5));
                    jmp[0] = 0xE9;
                    jmp[1] = ((unsigned char*)&fwdRel)[0];
                    jmp[2] = ((unsigned char*)&fwdRel)[1];
                    jmp[3] = ((unsigned char*)&fwdRel)[2];
                    jmp[4] = ((unsigned char*)&fwdRel)[3];

                    log_bytes("Skills99 hooksite JMP", g_skills99Hooksite, jmp, 5);
                    ok = game::ept_patch(g_skills99Hooksite, jmp, 5);
                }

                if (ok)
                {
                    prevS = true;
                    log::debug("[PROCLUB] Skills99 ON\r\n");
                }
                else
                {
                    log::debug("[PROCLUB] ERROR: Skills99 patch failed\r\n");
                    g_skills99Ready = false;
                }
            }
            else
            {
                log_bytes("Skills99 restore", g_skills99Hooksite, g_skills99OrigBytes, 5);
                bool ok = game::ept_patch(g_skills99Hooksite, g_skills99OrigBytes, 5);
                prevS = false;
                log::debugf(
                    "[PROCLUB] Skills99 OFF (ok=%d)\r\n", ok);
            }
        }
    }

    // --- XP Boost ---
    // Cave layout (24 bytes):
    //   41 C7 81 [disp32] [00 00 20 41]    mov dword [r9+disp], 10.0f   (11)
    //   41 0F 10 81 [disp32]               movups xmm0, [r9+disp]       (8)
    //   E9 [rel32]                          jmp hooksite+8               (5)
    // Hooksite (8 bytes):  E9 [rel32] 90 90 90
    {
        static bool prevX = false;
        if (g_xpBoostReady && g_xpBoost != prevX)
        {
            if (g_xpBoost)
            {
                unsigned char payload[24];
                // mov dword ptr [r9+disp], 41200000h  (10.0f)
                payload[0]  = 0x41;
                payload[1]  = 0xC7;
                payload[2]  = 0x81;
                payload[3]  = g_xpBoostDisp[0];
                payload[4]  = g_xpBoostDisp[1];
                payload[5]  = g_xpBoostDisp[2];
                payload[6]  = g_xpBoostDisp[3];
                payload[7]  = 0x00;  // 41200000h little-endian
                payload[8]  = 0x00;
                payload[9]  = 0x20;
                payload[10] = 0x41;
                // movups xmm0, [r9+disp] (original instruction)
                payload[11] = 0x41;
                payload[12] = 0x0F;
                payload[13] = 0x10;
                payload[14] = 0x81;
                payload[15] = g_xpBoostDisp[0];
                payload[16] = g_xpBoostDisp[1];
                payload[17] = g_xpBoostDisp[2];
                payload[18] = g_xpBoostDisp[3];
                // E9 rel32 — jmp back to hooksite+8
                int backRel = (int)((long long)(g_xpBoostHooksite + 8)
                                  - (long long)(g_xpBoostCave + 24));
                payload[19] = 0xE9;
                payload[20] = ((unsigned char*)&backRel)[0];
                payload[21] = ((unsigned char*)&backRel)[1];
                payload[22] = ((unsigned char*)&backRel)[2];
                payload[23] = ((unsigned char*)&backRel)[3];

                log::debugf(
                    "[PROCLUB] XPBoost backRel=0x%08X (hooksite+8=%p cave+24=%p)\r\n",
                    (unsigned int)backRel,
                    (void*)(g_xpBoostHooksite + 8),
                    (void*)(g_xpBoostCave + 24));
                log_bytes("XPBoost cave payload", g_xpBoostCave, payload, 24);

                bool ok = game::ept_patch(g_xpBoostCave, payload, 24);
                if (ok)
                {
                    log::debug("[PROCLUB] XPBoost cave OK\r\n");

                    unsigned char jmp[8];
                    int fwdRel = (int)((long long)g_xpBoostCave
                                     - (long long)(g_xpBoostHooksite + 5));
                    jmp[0] = 0xE9;
                    jmp[1] = ((unsigned char*)&fwdRel)[0];
                    jmp[2] = ((unsigned char*)&fwdRel)[1];
                    jmp[3] = ((unsigned char*)&fwdRel)[2];
                    jmp[4] = ((unsigned char*)&fwdRel)[3];
                    jmp[5] = 0x90;
                    jmp[6] = 0x90;
                    jmp[7] = 0x90;

                    log_bytes("XPBoost hooksite JMP", g_xpBoostHooksite, jmp, 8);
                    ok = game::ept_patch(g_xpBoostHooksite, jmp, 8);
                }

                if (ok)
                {
                    prevX = true;
                    log::debug("[PROCLUB] XPBoost ON — 10.0x multiplier\r\n");
                }
                else
                {
                    log::debug("[PROCLUB] ERROR: XPBoost patch failed\r\n");
                    g_xpBoostReady = false;
                }
            }
            else
            {
                log_bytes("XPBoost restore", g_xpBoostHooksite, g_xpBoostOrigBytes, 8);
                bool ok = game::ept_patch(g_xpBoostHooksite, g_xpBoostOrigBytes, 8);
                prevX = false;
                log::debugf(
                    "[PROCLUB] XPBoost OFF (ok=%d)\r\n", ok);
            }
        }
    }

    // --- Tournament Spoof ---
    // Cave layout (17 bytes):
    //   48 C7 C0 00 00 00 00   mov rax, 0         (7)
    //   33 D2                  xor edx, edx       (2)
    //   4C 63 E0               movsxd r12, eax    (3)
    //   E9 [rel32]             jmp hooksite+5     (5)
    // Hooksite (5 bytes): E9 [rel32]
    {
        static bool prevT = false;
        if (g_tournamentSpoofReady && g_tournamentSpoof != prevT)
        {
            if (g_tournamentSpoof)
            {
                unsigned char payload[17];
                payload[0]  = 0x48;  // mov rax, 0
                payload[1]  = 0xC7;
                payload[2]  = 0xC0;
                payload[3]  = 0x00;
                payload[4]  = 0x00;
                payload[5]  = 0x00;
                payload[6]  = 0x00;
                payload[7]  = 0x33;  // xor edx, edx
                payload[8]  = 0xD2;
                payload[9]  = 0x4C;  // movsxd r12, eax
                payload[10] = 0x63;
                payload[11] = 0xE0;
                int backRel = (int)((long long)(g_tourneyHooksite + 5)
                                  - (long long)(g_tourneyCave + 17));
                payload[12] = 0xE9;
                payload[13] = ((unsigned char*)&backRel)[0];
                payload[14] = ((unsigned char*)&backRel)[1];
                payload[15] = ((unsigned char*)&backRel)[2];
                payload[16] = ((unsigned char*)&backRel)[3];

                log::debugf(
                    "[PROCLUB] Tourney backRel=0x%08X (hooksite+5=%p cave+17=%p)\r\n",
                    (unsigned int)backRel,
                    (void*)(g_tourneyHooksite + 5),
                    (void*)(g_tourneyCave + 17));
                log_bytes("Tourney cave payload", g_tourneyCave, payload, 17);

                bool ok = game::ept_patch(g_tourneyCave, payload, 17);
                if (ok)
                {
                    log::debug("[PROCLUB] Tourney cave OK\r\n");

                    unsigned char jmp[5];
                    int fwdRel = (int)((long long)g_tourneyCave
                                     - (long long)(g_tourneyHooksite + 5));
                    jmp[0] = 0xE9;
                    jmp[1] = ((unsigned char*)&fwdRel)[0];
                    jmp[2] = ((unsigned char*)&fwdRel)[1];
                    jmp[3] = ((unsigned char*)&fwdRel)[2];
                    jmp[4] = ((unsigned char*)&fwdRel)[3];

                    log_bytes("Tourney hooksite JMP", g_tourneyHooksite, jmp, 5);
                    ok = game::ept_patch(g_tourneyHooksite, jmp, 5);
                }

                if (ok)
                {
                    prevT = true;
                    log::debug("[PROCLUB] TournamentSpoof ON — Round of 16\r\n");
                }
                else
                {
                    log::debug("[PROCLUB] ERROR: Tourney patch failed\r\n");
                    g_tournamentSpoofReady = false;
                }
            }
            else
            {
                log_bytes("Tourney restore", g_tourneyHooksite, g_tourneyOrigBytes, 5);
                bool ok = game::ept_patch(g_tourneyHooksite, g_tourneyOrigBytes, 5);
                prevT = false;
                log::debugf(
                    "[PROCLUB] TournamentSpoof OFF (ok=%d)\r\n", ok);
            }
        }
    }
}
