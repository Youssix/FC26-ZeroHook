#pragma once
#include <cstdint>

namespace sliders
{
    // ── Player Selection ──
    constexpr int MAX_PLAYERS = 25;
    inline bool usePlayerSelection = false;
    inline bool applyToOpponent = true;
    inline bool playerSelected[2][MAX_PLAYERS] = {};
    inline int  playerCount[2] = {};
    inline char playerNames[2][MAX_PLAYERS][80] = {};
    inline char teamNames[2][64] = {};
    inline bool namesValid = false;
    inline int  playerside = 0;  // 0=home, 1=away

    // ── Local Sliders (defaults favor us) ──
    inline float local_acceleration = 99.0f;
    inline float local_sprint = 99.0f;
    inline float local_shoot_error = 1.0f;
    inline float local_shoot_speed = 99.0f;
    inline float local_pass_error = 1.0f;
    inline float local_pass_speed = 99.0f;
    inline float local_first_touch_error = 1.0f;
    inline float local_header_shot_error = 1.0f;
    inline float local_header_pass_error = 1.0f;
    inline float local_intercept_error = 1.0f;
    inline float local_ball_deflection = 50.0f;
    inline float local_position_marking = 99.0f;
    inline float local_position_line_length = 99.0f;
    inline float local_position_line_width = 50.0f;
    inline float local_position_defensive_line_height = 50.0f;
    inline float local_position_run_frequency = 99.0f;
    inline float local_position_fullback = 99.0f;
    inline float local_gk_ability = 99.0f;
    inline float local_tackle_aggression = 50.0f;
    inline float local_injury_severity = 1.0f;
    inline float local_injury_frequency = 1.0f;

    // ── Opponent Sliders (defaults nerf them) ──
    inline float opp_acceleration = 1.0f;
    inline float opp_sprint = 1.0f;
    inline float opp_shoot_error = 99.0f;
    inline float opp_shoot_speed = 1.0f;
    inline float opp_pass_error = 99.0f;
    inline float opp_pass_speed = 1.0f;
    inline float opp_first_touch_error = 99.0f;
    inline float opp_header_shot_error = 99.0f;
    inline float opp_header_pass_error = 99.0f;
    inline float opp_intercept_error = 99.0f;
    inline float opp_ball_deflection = 50.0f;
    inline float opp_position_marking = 1.0f;
    inline float opp_position_line_length = 1.0f;
    inline float opp_position_line_width = 1.0f;
    inline float opp_position_defensive_line_height = 1.0f;
    inline float opp_position_run_frequency = 1.0f;
    inline float opp_position_fullback = 1.0f;
    inline float opp_gk_ability = 1.0f;
    inline float opp_tackle_aggression = 1.0f;
    inline float opp_injury_severity = 99.0f;
    inline float opp_injury_frequency = 99.0f;

    // ── Offsets (pattern scanned) ──
    inline uintptr_t InGameDB = 0;
    inline uintptr_t slider_buffer_fnc = 0;

    // ── Functions ──
    bool InitOffsets(void* gameBase, unsigned long gameSize);
    void ApplySliders();
    void SwapSettings();
    void RefreshPlayerNames();
    void SelectAll(int team, bool selected);
}
