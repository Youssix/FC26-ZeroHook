#pragma once
#include <cstdint>

// Pro Club features — Premium only.
// Search Game Alone : single-byte EPT patch (JNZ ↔ JZ).
// Skills 99        : EPT code-cave hook (mov [rsi],bl → mov byte [rsi],0x63).
// XP Boost         : EPT code-cave hook (movups xmm0,[r9+d] → write 10.0f).
// Tournament Spoof : EPT code-cave hook (force rax=0 → Round of 16).
namespace proclub
{
    extern bool g_searchAlone;
    extern bool g_searchAloneReady;

    extern bool g_skills99;
    extern bool g_skills99Ready;

    extern bool g_xpBoost;
    extern bool g_xpBoostReady;

    extern bool g_tournamentSpoof;
    extern bool g_tournamentSpoofReady;

    extern bool g_spoofEAID;
    extern char g_spoofEAIDText[22];

    bool Init(void* gameBase, unsigned long gameSize);

    // Per-frame: apply EPT patches only when toggles change.
    void Update();
}
