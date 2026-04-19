#pragma once
#include <cstdint>

// AI vs Opps / Disable Opponent AI — based on the proven-working commit
// dd7b1f3 of FC26-Internal. The "cheater signature" is 4 consecutive
// identical 0xA2CB726E packets sent after the game's own 44-packet match
// setup broadcast:
//
//   buf  = { 0xFFFFFFFF, ourPlayerId, 0 }    // ourPlayerId captured from traffic
//   slot = playerside                         // 0 for home, 1 for away
//   p7   = 0
//   size = 12
//   ×4 identical sends
//
// ourPlayerId is harvested from incoming 0xA2CB726E traffic during match
// setup by the RouteGameMessage hook: when a packet's buf[0] (team) matches
// sliders::playerside, we capture buf[1] as ourPlayerId. Reset each match.
namespace ai_control
{
    // Captured from incoming 0xA2CB726E traffic during match setup.
    // Zero until seen at least once.
    extern volatile uint32_t g_ourPlayerId;
    extern volatile bool     g_playerIdCaptured;

    // Kickoff gate — true only AFTER the match timer has transitioned from
    // <=0 to >0 (real kickoff). Prevents SendAiTakeover from firing during
    // the pre-kickoff setup phase where IsInActiveGameplay(ctx) is already
    // true but the game is still broadcasting its own 22-slot setup sweeps.
    // Firing during that window interleaves our packets with the game's own
    // and causes server "DestroyMatch" cancel.
    extern volatile bool g_kickoffArmed;

    // One-shot latch — set true after SendAiTakeover succeeds once per match.
    // The fix is a single captain-slot write + state-sync paired call, not
    // a periodic poll. Repeating the write retriggers the game's dispatcher
    // to rebroadcast 0xA2CB726E with Buf[2]=0x00000001 for opponent players,
    // which the peer flags as DataMismatch on opponent squad.
    // Reset to false at match-ended and on new kickoff.
    extern volatile bool g_aiTakeoverFired;

    // Deep-hook AI takeover toggle. When true, the AFK_DECISION_BRAIN hook
    // (sub_14282BB00) intercepts calls for our own slots and invokes the
    // game's own sub_1427F7640 (FnAfkTakeover) directly with the exact args
    // the brain would have produced — then skips the brain's normal path.
    // No packet forging, no state replication; the game's own validated
    // code does the takeover.
    // Runtime-toggled via Settings > Deep Hook AI Takeover.
    extern volatile bool g_deepHookAiTakeover;

    // Reset capture flag (called on match start / kickoff frame).
    void ResetCapture();

    // Called from HookedRouteGameMessage when an 0xA2CB726E packet
    // passes through; harvests ourPlayerId when team matches playerside.
    void OnIncomingControlOpcode(uint32_t team, uint32_t player);

    // Fire the 4-packet "attack" — give our side to AI.
    bool SendAiTakeover();

    // Fire for the opponent side (slot = opposite of playerside).
    bool SendDisableOpponentAi();
}
