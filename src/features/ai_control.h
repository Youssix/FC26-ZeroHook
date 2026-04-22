#pragma once
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────
//  OPCODE MAP (for this project — full inventory in memory/opcode_inventory.md)
// ─────────────────────────────────────────────────────────────────────────
//
//  CONTROLLER / ROSTER ────────────────────────────────────────────────────
//    0xA2CB726E  — Controller Reassign (sz=12, {team,slot,0}). Peer-gated
//                  by sub_142825AC0 owner-check. Our sends via spoof_call
//                  trigger DataMismatch for non-owned slots (patched FIFA23+).
//    0xFAE6B64D  — "Player in Lobby" roster entry (sz=0x38). OLD forged
//                  method used by SendDisableOpponentAi() — patched.
//    0x8B6ADB85  — Controller-Assign NAK (sz=8). Emitted by sub_14281B970
//                  on claim-failure.
//    0x0FAC4147  — PLAYER_RELEASED (sz=8). Sibling of ClaimSlot in
//                  sub_14281BEE0 (Release/Leave).
//    0x817F6893  — Ack/Reference (sz=0x18). Tail of sub_14281A4F0.
//    0xB903E184  — Ack companion to 0x817F6893.
//
//  AFK / IDLE ─────────────────────────────────────────────────────────────
//    0xA76FB4ED  — AFK countdown (sz=4). FnAfkTakeover periodic.
//    0xA53EAAB2  — "Not Actively Playing" UI banner (sz=0x24). Cosmetic.
//    0x4E9507C9  — HLI 22-slot state sync (sz=0x290 = 656). sub_14282B1D0.
//
//  HOST STATE / LOBBY CLASS ───────────────────────────────────────────────
//    0x999C804A  — HostFullStateBroadcast envelope (sz=0x15D0 = 5584).
//                  Arms peer gate matchCtx+0x120=1 via sub_142825AC0.
//    0x10C4BF57  — Alternate arm (same effect as 0x999C804A).
//    0xE0A38D91  — Disarm (matchCtx+0x120=0).
//    0xEEA05BB1  — Router cmd that triggers sub_14218F5D0 broadcast.
//    0xDEAA09DC  — Match teardown router cmd.
//
//  AI DRIVER (LOCAL-ONLY, no peer subscriber) ─────────────────────────────
//    0xE81D3B4C  — AI Input Announce (sz=12). sub_148C3FC40.
//    0x4837B24B  — AI Cue/Difficulty (sz=12). sub_148C3C410. 10/match.
//    0x3BF3282E  — AI state-delta companion to 0x4837B24B (sz=8).
//
//  STATUS: raw forging is PATCHED since FIFA 23 (Kresor confirmed via
//  Discord). Working path is "send a class" via the Frostbite service
//  locator sub_145094BE0("online") + vtbl[0x48], OR the class-method
//  takeover sub_142814510 via fifaBaseServices::Aardvark singleton.
//
//  See memory/opcode_inventory.md for full detail including senders,
//  receivers, addresses, class hashes, and config keys.
// ─────────────────────────────────────────────────────────────────────────

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
//
// HISTORICAL: this 4-packet recipe is the OLD method. Patched since FIFA
// 23. New method = class-send path via sub_142814510 / sub_142814760 /
// sub_148563CF0. See opcode map above + memory/opcode_inventory.md.
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

    // One-shot latch — set true after SendDisableOpponentAi (roster-spoof)
    // succeeds once per match. Reset in ResetCapture() so every new match
    // re-fires automatically when g_playerIdCaptured flips true.
    extern volatile bool g_rosterSpoofFired;

    // Deep-hook AI takeover toggle. When true, the AFK_DECISION_BRAIN hook
    // (sub_14282BB00) intercepts calls for our own slots and invokes the
    // game's own sub_1427F7640 (FnAfkTakeover) directly with the exact args
    // the brain would have produced — then skips the brain's normal path.
    // No packet forging, no state replication; the game's own validated
    // code does the takeover.
    // Runtime-toggled via Settings > Deep Hook AI Takeover.
    extern volatile bool g_deepHookAiTakeover;

    // Byte-patch approach to forcing the AFK takeover path. EPT-patches
    // sub_14282BB00 at RVA 0x282BF0A (the `jz short` that skips the
    // fast-path FnAfkTakeover call) to two NOPs, so whenever the brain
    // reaches the fast-path block, sub_1427F7640 always fires.
    //
    // Zero EPT exit overhead — the patched bytes just execute as-is.
    // Invisible to read-view integrity checks via EPT-split.
    //
    // Prerequisite: normal brain gates still apply (CPU_VS_CPU,
    // matchCtx[0x2557], NOIDLE, NOIDLEREMOVE). If any fail the brain
    // returns before reaching our patched site and nothing fires.
    extern volatile bool g_forceAfkPath;
    void ApplyForceAfkPath(bool enable);

    // Hook-based one-shot ENTER dispatcher (Option C, supersedes the
    // byte-patch attempt at 0x1489A9EBA which was too broad — it fired at
    // boot/menu because sub_1489A9CE0 is session-level, not match-only).
    //
    // InstallStateMachineHook() installs an EPT hook on sub_1489A9CE0 entry.
    // The detour, on every call, checks ALL of these gates:
    //   1. g_forceStateMachineEnter toggle on
    //   2. matchCtx = FnGetMatchCtx() is non-null
    //   3. *(matchCtx + 0x4AD0) != 0  (IsInActiveGameplay — real match loaded, unpaused)
    //   4. *(matchCtx + 0x4CA1) != 0  (AFK feature gate live)
    //   5. One-shot latch per matchCtx (resets when matchCtx changes = new match)
    // If all pass, calls sub_1427FA200(matchCtx, 0, 0) ONCE and passes
    // through. The Enter call transitions phase to 2 internally, and the
    // latch prevents re-entry on subsequent ticks. No byte patching, no
    // menu-level misfires.
    //
    // Install at boot; the toggle just flips the bool at runtime.
    extern volatile bool g_forceStateMachineEnter;
    void ApplyForceStateMachineEnter(bool enable);
    bool InstallStateMachineHook();

    // Reset capture flag (called on match start / kickoff frame).
    void ResetCapture();

    // Called from HookedRouteGameMessage when an 0xA2CB726E packet
    // passes through; harvests ourPlayerId when team matches playerside.
    void OnIncomingControlOpcode(uint32_t team, uint32_t player);

    // Fire the 4-packet "attack" — give our side to AI.
    bool SendAiTakeover();

    // Fire for the opponent side (slot = opposite of playerside).
    bool SendDisableOpponentAi();

    // Test: fire a single 0xE81D3B4C packet with payload {0, 0, 1} (sz=12,
    // slot=0xFF, param7=0). Hypothesis: this is the AI-driver heartbeat /
    // takeover-ACK packet that the peer expects after a natural AFK
    // takeover. Working-tool logs show it; ours don't.
    bool FireAiHeartbeat();

    // Variant: the joystick/axis-input flavor seen in working logs —
    // payload {1.0f, 1.0f, 1} (12B: float, float, uint32). If the handshake
    // flavor doesn't change anything, this is the other shape seen in the
    // wire traffic — per-frame AI input announce.
    bool FireAiInputAnnounce();

    // ── 0xA2CB726E test fires (4 flavors, all sz=12, slot=0xFF, param7=0) ─
    //
    // A2CB726E is the controller-reassign packet — what the game sends
    // itself during natural AFK takeover. We know peer accepts its natural
    // form without DC, so firing flavors manually isolates which arg
    // combination the peer treats as a valid takeover signal vs noise.
    //
    // All four resolve matchCtx + our captain field slot automatically.

    // {0xFFFFFFFF, captainSlot, 0} — the FnAfkTakeover sentinel form.
    bool FireA2CBSentinel();

    // {mySide, captainSlot, 0} — treats our own team as the "receiver";
    // matches the natural re-broadcast form from sub_14281A4F0.
    bool FireA2CBTeamHome();

    // {oppSide, captainSlot, 0} — opposite team. Likely rejected but worth
    // a shot since we've never been able to poke the opponent's slot.
    bool FireA2CBTeamOpp();

    // 22-packet burst: {0xFFFFFFFF, k, 0} for k in 0..21.
    // Re-exposes the dormant BroadcastFullAiSweep path under the menu.
    bool FireA2CBFullSweep();

    // Direct call to the game's own FnAfkTakeover (sub_1427F7640) with
    // (matchCtx, captainSlot, 0, 1). Internally fires the three-packet
    // sequence (0xA53EAAB2 announce → sub_14282B1D0's 0x4E9507C9 state-sync
    // → 0xA2CB726E reassign) in the exact order the game does when it
    // triggers natural AFK takeover. If this still DataMismatches, the
    // issue isn't the packet sequence — it's something else about our
    // context that the peer validates (timing, mid-match vs match-setup,
    // prior state).
    bool CallFnAfkTakeover();

    // THE RECIPE — direct call to sub_14281B970 (FnClaimSlot) with our own
    // {teamId=mySide, playerId=g_ourPlayerId}. This is the low-level claim
    // primitive:
    //   - finds our slot by (team, player)
    //   - writes slot+0x190=1, matchCtx+0x2557=1
    //   - broadcasts 0xA2CB726E {0xFFFFFFFF, slotIdx, 0}
    //   - calls sub_14282B1D0 for HLI state sync
    //   - cascades per-team ACK
    // Peer's validator sub_142825AC0 accepts because sub_142803460 ==
    // payload[0] (owner match). No AI-driver enable needed — peer
    // simulates our AI locally once the claim lands.
    // Requires g_playerIdCaptured to be true (bridge captures from
    // incoming 0xA2CB726E traffic at match start).
    bool ClaimMySlot();
}
