#pragma once

namespace server {
    constexpr int MAX_REGIONS = 32;
    constexpr int MAX_SITES_PER_REGION = 8;

    struct RegionEntry {
        char regionName[64];
        char sites[MAX_SITES_PER_REGION][64];
        int siteCount;
    };

    // State
    inline bool initialized = false;
    inline bool enableOverride = false;
    inline char forcedPingSite[64] = {};
    inline char currentPingSite[64] = {};
    inline RegionEntry regions[MAX_REGIONS] = {};
    inline int regionCount = 0;
    inline int selectedRegion = 0;
    inline bool connected = false;

    // API
    bool Init(void* gameBase, unsigned long gameSize);
    bool IsReady();
    void SetForcedPingSite(const char* alias);
    void RestorePingSite();
    void RefreshCurrentPingSite();
    void EnumerateRegions();
    bool IsConnected();
    void Disconnect();
    void Reconnect();
    const char* GetRegionLabel(int idx);
}
