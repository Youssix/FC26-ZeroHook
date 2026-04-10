#pragma once
#include <cstdint>

namespace opp_info
{
    // ── Player data (populated by hook on match found) ──────────────
    struct PlayerData
    {
        char     name[64];
        char     platform[16];
        uint64_t personaId;
        uint64_t nucleusId;

        int      drRating;
        int      chemistry;
        int      teamOvr;
        int      skillRating;

        int      seasonWins;
        int      seasonLosses;
        int      seasonTies;
        int      totalGames;
        int      dnfPercent;
        int      starLevel;

        unsigned int creationYear;
        int      creationMonth;

        char     clubName[64];
        char     clubTag[32];
        int      badgeId;

        bool     valid;          // true once data is populated
    };

    extern PlayerData g_opponent;
    extern bool       g_showWindow;

    // ── Lifecycle ───────────────────────────────────────────────────
    bool Init(void* gameBase, unsigned long gameSize);   // pattern scans
    bool InstallHook();                                   // EPT hook on vtable[1]
    bool IsReady();                                       // patterns resolved?
    bool IsHooked();                                      // hook installed?
}
