#pragma once
#include <cstdint>

// AI Difficulty override — Premium only.
// Sends opcodes 0x4837B24B (12B simple) + 0x298B28B1 (112B with ID) at kickoff,
// fired by the match-timer hook when these flags are set.
namespace ai_difficulty
{
#ifndef STANDARD_BUILD
    extern bool g_localLegendary;
    extern bool g_opponentBeginner;

    void send_local_legendary();
    void send_opponent_beginner();
#endif
}
