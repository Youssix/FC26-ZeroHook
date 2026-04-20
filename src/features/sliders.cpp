// sliders.cpp — Slider V2 system (VEGA 25-block per-player sliders)
// NoCRT-safe: no std:: anything. Uses __stosb/__movsb, fmt::snprintf, spoof_call.

#include "sliders.h"
#include "rage.h"
#include <intrin.h>
#include "../game/game.h"
#include "../hook/network_hooks.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"
#include "../spoof/spoof_call.hpp"

// ── Helpers ──────────────────────────────────────────────────────────

namespace
{
    uintptr_t resolve_rip3_7(uintptr_t addr)
    {
        if (!addr) return 0;
        int32_t disp = *reinterpret_cast<int32_t*>(addr + 3);
        return addr + 7 + disp;
    }

    bool SafeReadMemory(const void* src, void* dst, size_t size)
    {
        __try {
            __movsb((unsigned char*)dst, (const unsigned char*)src, size);
            return true;
        } __except (1) {
            return false;
        }
    }

    // NoCRT string copy (char-by-char, null-terminated, bounded)
    void safe_strcpy(char* dst, const char* src, int maxLen)
    {
        int i = 0;
        while (src[i] && i < maxLen - 1) {
            dst[i] = src[i];
            i++;
        }
        dst[i] = '\0';
    }

    // Clamp float to byte (0..99)
    unsigned char clamp_byte(float val)
    {
        int v = (int)val;
        if (v < 0)  v = 0;
        if (v > 99) v = 99;
        return (unsigned char)v;
    }
}

// ── InitOffsets ──────────────────────────────────────────────────────

bool sliders::InitOffsets(void* gameBase, unsigned long gameSize)
{
    log::debug("[SLIDERS] Scanning patterns...\r\n");

    // 1. slider_buffer_fnc
    void* m1 = game::pattern_scan(gameBase, gameSize,
        "40 53 48 83 EC ? 33 D2 41 B8 ? ? ? ? 48 8B D9 E8 ? ? ? ? B9 ? ? ? ? 48 8D 43");
    if (m1) {
        slider_buffer_fnc = (uintptr_t)m1;
        log::debugf("[SLIDERS] slider_buffer_fnc: %p\r\n", (void*)slider_buffer_fnc);
    } else {
        log::debug("[SLIDERS] ERROR: slider_buffer_fnc not found\r\n");
    }

    // 2. g_pInGameDB (RIP-relative resolve)
    void* m2 = game::pattern_scan(gameBase, gameSize,
        "48 8B 05 ? ? ? ? 48 85 C0 0F 85 ? ? ? ? 48 89 0D");
    if (m2) {
        InGameDB = resolve_rip3_7((uintptr_t)m2);
        log::debugf("[SLIDERS] InGameDB: %p\r\n", (void*)InGameDB);
    } else {
        log::debug("[SLIDERS] ERROR: InGameDB not found\r\n");
    }

    bool ok = slider_buffer_fnc && InGameDB;
    log::debugf("[SLIDERS] InitOffsets: %s\r\n", ok ? "ALL OK" : "SOME MISSING");
    return ok;
}

// ── RefreshPlayerNames ───────────────────────────────────────────────

void sliders::RefreshPlayerNames()
{
    namesValid = false;
    playerCount[0] = 0;
    playerCount[1] = 0;
    __stosb((unsigned char*)teamNames, 0, sizeof(teamNames));

    if (!InGameDB) return;

    uintptr_t pInGameDB = 0;
    if (!SafeReadMemory((const void*)InGameDB, &pInGameDB, sizeof(pInGameDB)))
        return;
    if (!pInGameDB || pInGameDB < 0x10000)
        return;

    int localIdx = playerside;
    if (localIdx < 0 || localIdx > 1) localIdx = 0;
    int oppIdx = 1 - localIdx;
    int teamOrder[2] = { localIdx, oppIdx };

    for (int t = 0; t < 2; t++) {
        uintptr_t team = 0;
        uintptr_t teamOffset = pInGameDB + 0x08 + teamOrder[t] * 0x08;
        if (!SafeReadMemory((const void*)teamOffset, &team, sizeof(uintptr_t)))
            continue;
        if (!team) continue;

        char rawName[64];
        __stosb((unsigned char*)rawName, 0, sizeof(rawName));
        if (SafeReadMemory((const void*)team, rawName, 63)) {
            rawName[63] = '\0';
            if (rawName[0] >= 0x20 && rawName[0] < 0x7F) {
                safe_strcpy(teamNames[t], rawName, sizeof(teamNames[t]));
            } else {
                fmt::snprintf(teamNames[t], sizeof(teamNames[t]), "Team %d", t + 1);
            }
        } else {
            fmt::snprintf(teamNames[t], sizeof(teamNames[t]), "Team %d", t + 1);
        }

        int count = 0;
        for (int p = 0; p < MAX_PLAYERS; p++) {
            uintptr_t playerBlock = team + 0x2E8 + (uintptr_t)p * 0xBF0;
            uintptr_t nameAddr = playerBlock + 0x4E;

            char rawPlayerName[80];
            __stosb((unsigned char*)rawPlayerName, 0, sizeof(rawPlayerName));

            if (SafeReadMemory((const void*)nameAddr, rawPlayerName, 77)) {
                rawPlayerName[77] = '\0';
                if (rawPlayerName[0] == '\0') {
                    fmt::snprintf(playerNames[t][p], sizeof(playerNames[t][p]), "Player %d", p + 1);
                } else {
                    safe_strcpy(playerNames[t][p], rawPlayerName, sizeof(playerNames[t][p]));
                }
                count++;
            } else {
                break;
            }
        }
        playerCount[t] = count;
    }

    namesValid = (playerCount[0] > 0 || playerCount[1] > 0);
}

// ── ApplySliders ─────────────────────────────────────────────────────

void sliders::ApplySliders()
{
    uintptr_t rcx = 0;
    rage::dispatch_fn_t fn = nullptr;
    if (!rage::get_dispatch(rcx, fn)) {
        log::debug("[SLIDERS] ApplySliders: dispatch not ready\r\n");
        return;
    }

    alignas(16) unsigned char buffer[1924];
    __stosb(buffer, 0, sizeof(buffer));

    if (slider_buffer_fnc) {
        typedef void(__fastcall* slider_buf_fn_t)(__int64);
        auto fn = reinterpret_cast<slider_buf_fn_t>(slider_buffer_fnc);
        spoof_call(fn, (__int64)buffer);
    }

    int local_start = (playerside == 0) ? 0 : 25;
    int local_end   = local_start + 25;
    int opp_start   = (playerside == 0) ? 25 : 0;
    int opp_end     = opp_start + 25;

    for (int block = local_start; block < local_end; block++) {
        int playerIdx = block - local_start;

        if (usePlayerSelection && playerIdx < MAX_PLAYERS) {
            if (!playerSelected[0][playerIdx])
                continue;
        }

        unsigned char* base = buffer + block * 32;
        unsigned char* arr = base + 2;

        arr[-2] = arr[-1] = clamp_byte(local_sprint);
        arr[0] = arr[1] = clamp_byte(local_acceleration);
        arr[2] = arr[3] = clamp_byte(local_shoot_error);
        arr[4] = arr[5] = clamp_byte(local_header_shot_error);
        arr[6] = arr[7] = clamp_byte(local_pass_error);
        arr[8] = arr[9] = clamp_byte(local_header_pass_error);
        arr[10] = arr[11] = clamp_byte(local_first_touch_error);
        arr[12] = arr[13] = clamp_byte(local_intercept_error);
        arr[14] = clamp_byte(local_ball_deflection);
        arr[15] = clamp_byte(local_tackle_aggression);
        arr[18] = 0x32; arr[19] = 0x32;
        arr[20] = 50; arr[21] = 50;
        arr[22] = arr[23] = clamp_byte(local_shoot_speed);
        arr[24] = arr[25] = clamp_byte(local_pass_speed);
        arr[26] = arr[27] = clamp_byte(local_injury_frequency);
        arr[28] = arr[29] = clamp_byte(local_injury_severity);
    }

    for (int block = opp_start; block < opp_end; block++) {
        int playerIdx = block - opp_start;

        if (usePlayerSelection && playerIdx < MAX_PLAYERS) {
            if (!playerSelected[1][playerIdx])
                continue;
        } else if (!usePlayerSelection && !applyToOpponent) {
            continue;
        }

        unsigned char* base = buffer + block * 32;
        unsigned char* arr = base + 2;

        arr[-2] = arr[-1] = clamp_byte(opp_sprint);
        arr[0] = arr[1] = clamp_byte(opp_acceleration);
        arr[2] = arr[3] = clamp_byte(opp_shoot_error);
        arr[4] = arr[5] = clamp_byte(opp_header_shot_error);
        arr[6] = arr[7] = clamp_byte(opp_pass_error);
        arr[8] = arr[9] = clamp_byte(opp_header_pass_error);
        arr[10] = arr[11] = clamp_byte(opp_first_touch_error);
        arr[12] = arr[13] = clamp_byte(opp_intercept_error);
        arr[14] = clamp_byte(opp_ball_deflection);
        arr[15] = clamp_byte(opp_tackle_aggression);
        arr[18] = 0x32; arr[19] = 0x32;
        arr[20] = 50; arr[21] = 50;
        arr[22] = arr[23] = clamp_byte(opp_shoot_speed);
        arr[24] = arr[25] = clamp_byte(opp_pass_speed);
        arr[26] = arr[27] = clamp_byte(opp_injury_frequency);
        arr[28] = arr[29] = clamp_byte(opp_injury_severity);
    }

    for (int i = 0; i < 0x16; ++i)
        buffer[2 * i + 0x71C] = 0x32;

    {
        int idx = playerside;
        unsigned char* b = buffer;

        b[14 * idx + 0x700] = b[14 * idx + 0x701] = clamp_byte(local_position_marking);
        b[14 * idx + 0x702] = b[14 * idx + 0x703] = clamp_byte(local_position_line_length);
        b[14 * idx + 0x704] = b[14 * idx + 0x705] = clamp_byte(local_position_line_width);
        b[14 * idx + 0x706] = b[14 * idx + 0x707] = clamp_byte(local_position_defensive_line_height);
        b[14 * idx + 0x708] = b[14 * idx + 0x709] = clamp_byte(local_position_run_frequency);
        b[14 * idx + 0x70A] = b[14 * idx + 0x70B] = clamp_byte(local_position_fullback);
        b[14 * idx + 0x70C] = b[14 * idx + 0x70D] = clamp_byte(local_gk_ability);
        b[7 * idx + 0x748] = clamp_byte(local_tackle_aggression);
        b[0x738 + 2 * idx] = 0x32;
    }

    {
        int idx = 1 - playerside;
        unsigned char* b = buffer;

        b[14 * idx + 0x700] = b[14 * idx + 0x701] = clamp_byte(opp_position_marking);
        b[14 * idx + 0x702] = b[14 * idx + 0x703] = clamp_byte(opp_position_line_length);
        b[14 * idx + 0x704] = b[14 * idx + 0x705] = clamp_byte(opp_position_line_width);
        b[14 * idx + 0x706] = b[14 * idx + 0x707] = clamp_byte(opp_position_defensive_line_height);
        b[14 * idx + 0x708] = b[14 * idx + 0x709] = clamp_byte(opp_position_run_frequency);
        b[14 * idx + 0x70A] = b[14 * idx + 0x70B] = clamp_byte(opp_position_fullback);
        b[14 * idx + 0x70C] = b[14 * idx + 0x70D] = clamp_byte(opp_gk_ability);
        b[7 * idx + 0x748] = clamp_byte(opp_tackle_aggression);
        b[0x738 + 2 * idx] = 0x32;
    }

    uint64_t opcode = 0x5EE6BB89;

    hook::g_allow_attack_send = true;
    spoof_call(fn, (uint64_t)rcx, (uint64_t*)&opcode, (uint64_t*)&opcode,
        (void*)buffer, (int)1924, (char)0xFFFFFFFF, (unsigned char)0);
    hook::g_allow_attack_send = false;

    toast::Show(toast::Type::Success, "Sliders applied");
    log::debug("[SLIDERS] ApplySliders sent\r\n");
}

// ── SwapSettings ─────────────────────────────────────────────────────

void sliders::SwapSettings()
{
    float tmp;

    #define SWAP_SLIDER(a, b) do { tmp = a; a = b; b = tmp; } while(0)

    SWAP_SLIDER(local_acceleration,                    opp_acceleration);
    SWAP_SLIDER(local_sprint,                          opp_sprint);
    SWAP_SLIDER(local_shoot_error,                     opp_shoot_error);
    SWAP_SLIDER(local_shoot_speed,                     opp_shoot_speed);
    SWAP_SLIDER(local_pass_error,                      opp_pass_error);
    SWAP_SLIDER(local_pass_speed,                      opp_pass_speed);
    SWAP_SLIDER(local_first_touch_error,               opp_first_touch_error);
    SWAP_SLIDER(local_header_shot_error,               opp_header_shot_error);
    SWAP_SLIDER(local_header_pass_error,               opp_header_pass_error);
    SWAP_SLIDER(local_intercept_error,                 opp_intercept_error);
    SWAP_SLIDER(local_ball_deflection,                 opp_ball_deflection);
    SWAP_SLIDER(local_position_marking,                opp_position_marking);
    SWAP_SLIDER(local_position_line_length,            opp_position_line_length);
    SWAP_SLIDER(local_position_line_width,             opp_position_line_width);
    SWAP_SLIDER(local_position_defensive_line_height,  opp_position_defensive_line_height);
    SWAP_SLIDER(local_position_run_frequency,          opp_position_run_frequency);
    SWAP_SLIDER(local_position_fullback,               opp_position_fullback);
    SWAP_SLIDER(local_gk_ability,                      opp_gk_ability);
    SWAP_SLIDER(local_tackle_aggression,               opp_tackle_aggression);
    SWAP_SLIDER(local_injury_severity,                 opp_injury_severity);
    SWAP_SLIDER(local_injury_frequency,                opp_injury_frequency);

    #undef SWAP_SLIDER

    toast::Show(toast::Type::Info, "Slider settings swapped");
}

// ── SelectAll ────────────────────────────────────────────────────────

void sliders::SelectAll(int team, bool selected)
{
    if (team < 0 || team > 1) return;
    for (int i = 0; i < MAX_PLAYERS; i++)
        playerSelected[team][i] = selected;
}
