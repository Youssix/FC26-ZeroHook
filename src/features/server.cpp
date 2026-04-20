// server.cpp -- Server Changer: force matchmaking to specific EA datacenters
// NoCRT-safe: no std:: anything. Uses __stosb/__movsb, fmt::snprintf, spoof_call.

#include "server.h"
#include <intrin.h>
#include <Windows.h>
#include "../game/game.h"
#include "../comms/comms.h"
#include "../menu/toast.h"
#include "../log/log.h"
#include "../log/fmt.h"
#include "../spoof/spoof_call.hpp"

// ── NoCRT string helpers ────────────────────────────────────────────────

namespace
{
    void safe_strcpy(char* dst, const char* src, int maxLen)
    {
        int i = 0;
        while (src[i] && i < maxLen - 1) {
            dst[i] = src[i];
            i++;
        }
        dst[i] = '\0';
    }

    // Case-insensitive compare (NoCRT _stricmp replacement)
    int safe_stricmp(const char* a, const char* b)
    {
        while (*a && *b) {
            char ca = *a;
            char cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) return (int)ca - (int)cb;
            a++;
            b++;
        }
        return (int)(unsigned char)*a - (int)(unsigned char)*b;
    }

    bool SafeReadPtr(uintptr_t addr, uintptr_t* out)
    {
        __try {
            *out = *(uintptr_t*)addr;
            return true;
        } __except (1) {
            return false;
        }
    }

    bool SafeReadU8(uintptr_t addr, unsigned char* out)
    {
        __try {
            *out = *(unsigned char*)addr;
            return true;
        } __except (1) {
            return false;
        }
    }

    bool SafeReadI32(uintptr_t addr, int* out)
    {
        __try {
            *out = *(int*)addr;
            return true;
        } __except (1) {
            return false;
        }
    }

    // RIP-relative resolve: addr points to instruction with disp at +dispOff, instrLen total
    uintptr_t resolve_rip(uintptr_t addr, int dispOff, int instrLen)
    {
        if (!addr) return 0;
        __try {
            int disp = *(int*)(addr + dispOff);
            return addr + instrLen + disp;
        } __except (1) {
            return 0;
        }
    }

    // E8 call target resolve: addr points to E8 xx xx xx xx
    uintptr_t resolve_e8(uintptr_t addr)
    {
        if (!addr) return 0;
        __try {
            int disp = *(int*)(addr + 1);
            return addr + 5 + disp;
        } __except (1) {
            return 0;
        }
    }
}

// ── Resolved addresses ──────────────────────────────────────────────────

namespace
{
    // Pattern 1: LoginAdaptorState
    uintptr_t g_LoginAdaptorState = 0;
    unsigned char g_ConnectionOffset = 0;
    int g_SetPingSiteVtOff = 0;

    // Pattern 2: ConfigManager
    uintptr_t g_ConfigManager = 0;

    // Pattern 3: GetBestPingSiteAlias
    uintptr_t g_GetServiceLocatorFn = 0;
    uintptr_t g_GetAliasFn = 0;

    // Pattern 4: QosPing_DispatchMeasurements
    uintptr_t g_QosPingDispatchAddr = 0;

    // Pattern 5: BlazeWrapper
    uintptr_t g_BlazeWrapper = 0;
}

// ── Pointer chain for QosPingManager ────────────────────────────────────

namespace
{
    uintptr_t GetQosPingManager()
    {
        uintptr_t base = 0;
        if (!SafeReadPtr(g_BlazeWrapper, &base) || !base) return 0;

        uintptr_t p0 = 0;
        if (!SafeReadPtr(base, &p0) || !p0) return 0;

        uintptr_t p1 = 0;
        if (!SafeReadPtr(p0 + 0x350, &p1) || !p1) return 0;

        uintptr_t p2 = 0;
        if (!SafeReadPtr(p1 + 0x800, &p2) || !p2) return 0;

        uintptr_t qosMgr = 0;
        if (!SafeReadPtr(p2 + 0x2798, &qosMgr) || !qosMgr) return 0;

        return qosMgr;
    }

    // Walk LoginAdaptorState -> loginMgr
    uintptr_t GetLoginManager()
    {
        if (!g_LoginAdaptorState) return 0;

        uintptr_t state = 0;
        if (!SafeReadPtr(g_LoginAdaptorState, &state) || !state) return 0;

        uintptr_t inner = 0;
        if (!SafeReadPtr(state, &inner) || !inner) return 0;

        uintptr_t loginMgr = 0;
        if (!SafeReadPtr(inner + 0x70, &loginMgr) || !loginMgr) return 0;

        return loginMgr;
    }
}

// ── ModifyLatencyMap ────────────────────────────────────────────────────

namespace
{
    void ModifyLatencyMap(const char* targetAlias)
    {
        uintptr_t qosMgr = GetQosPingManager();
        if (!qosMgr) {
            log::debug("[SERVER] ModifyLatencyMap: QosPingManager null\r\n");
            return;
        }

        uintptr_t mapStart = 0, mapEnd = 0;
        if (!SafeReadPtr(qosMgr + 0x48, &mapStart) || !mapStart) {
            log::debug("[SERVER] ModifyLatencyMap: map start null\r\n");
            return;
        }
        if (!SafeReadPtr(qosMgr + 0x50, &mapEnd) || !mapEnd) {
            log::debug("[SERVER] ModifyLatencyMap: map end null\r\n");
            return;
        }

        if (mapEnd <= mapStart || (mapEnd - mapStart) > 0x10000) {
            log::debug("[SERVER] ModifyLatencyMap: invalid map range\r\n");
            return;
        }

        int entryCount = (int)((mapEnd - mapStart) / 0x20);
        log::debugf("[SERVER] ModifyLatencyMap: %d entries, target=%s\r\n",
            entryCount, targetAlias);

        bool foundTarget = false;

        for (int i = 0; i < entryCount; i++) {
            uintptr_t entry = mapStart + (uintptr_t)i * 0x20;

            // +0x00 = const char* alias
            uintptr_t aliasPtr = 0;
            if (!SafeReadPtr(entry, &aliasPtr) || !aliasPtr)
                continue;

            // Read alias string
            char aliasStr[64];
            __stosb((unsigned char*)aliasStr, 0, sizeof(aliasStr));
            __try {
                __movsb((unsigned char*)aliasStr, (const unsigned char*)aliasPtr, 63);
                aliasStr[63] = '\0';
            } __except (1) {
                continue;
            }

            // +0x18 = int32_t latency
            int* latencyPtr = (int*)(entry + 0x18);

            __try {
                if (safe_stricmp(aliasStr, targetAlias) == 0) {
                    *latencyPtr = 5;
                    foundTarget = true;
                } else {
                    *latencyPtr = 999;
                }
            } __except (1) {
                continue;
            }
        }

        if (foundTarget) {
            log::debugf("[SERVER] Latency map modified: %s=5, others=999\r\n", targetAlias);
        } else {
            log::debugf("[SERVER] WARNING: target '%s' not found in latency map\r\n", targetAlias);
        }
    }

    void ForceDispatchQoS()
    {
        if (!g_QosPingDispatchAddr) {
            log::debug("[SERVER] ForceDispatchQoS: dispatch addr null\r\n");
            return;
        }

        uintptr_t qosMgr = GetQosPingManager();
        if (!qosMgr) {
            log::debug("[SERVER] ForceDispatchQoS: QosPingManager null\r\n");
            return;
        }

        // void QosPing_DispatchMeasurements(this, bool)
        typedef void(__fastcall* dispatch_fn_t)(uintptr_t, unsigned char);
        auto fn = reinterpret_cast<dispatch_fn_t>(g_QosPingDispatchAddr);

        __try {
            spoof_call(fn, qosMgr, (unsigned char)1);
            log::debug("[SERVER] ForceDispatchQoS: sent\r\n");
        } __except (1) {
            log::debug("[SERVER] ForceDispatchQoS: exception\r\n");
        }
    }

    const char* ReadCurrentPingSite()
    {
        if (!g_GetAliasFn) return nullptr;

        // GetBestPingSiteAlias: sub rsp,28h / call ServiceLocator / ... / tail-call vtable[0x88]
        // Takes no meaningful args — pass 0 as dummy thisPtr (ignored)
        typedef const char*(__fastcall* get_alias_fn_t)(__int64);
        auto fn = reinterpret_cast<get_alias_fn_t>(g_GetAliasFn);

        __try {
            return spoof_call(fn, (__int64)0);
        } __except (1) {
            return nullptr;
        }
    }
}

// ── Region parsing ──────────────────────────────────────────────────────

namespace
{
    // Simple tokenizer: finds next delimiter, writes token to out, returns pointer past delimiter
    // Returns nullptr if end of string
    const char* NextToken(const char* str, char delim, char* out, int outMax)
    {
        int i = 0;
        while (*str && *str != delim && i < outMax - 1) {
            out[i++] = *str++;
        }
        out[i] = '\0';

        if (*str == delim) return str + 1;  // skip delimiter
        if (*str == '\0') return nullptr;    // end of string
        return str;
    }

    void ParseRegionsString(const char* str)
    {
        // Format: "Region=site1,site2|Region2=site3,site4"
        server::regionCount = 0;

        if (!str || !str[0]) return;

        const char* cursor = str;
        while (cursor && server::regionCount < server::MAX_REGIONS)
        {
            // Extract one region block (up to '|')
            char block[512];
            __stosb((unsigned char*)block, 0, sizeof(block));
            const char* next = NextToken(cursor, '|', block, sizeof(block));

            if (!block[0]) {
                cursor = next;
                continue;
            }

            // Split block by '=' into regionName and sites
            char regionName[64];
            char sitesStr[448];
            __stosb((unsigned char*)regionName, 0, sizeof(regionName));
            __stosb((unsigned char*)sitesStr, 0, sizeof(sitesStr));

            const char* eqPos = NextToken(block, '=', regionName, sizeof(regionName));
            if (eqPos) {
                safe_strcpy(sitesStr, eqPos, sizeof(sitesStr));
            }

            if (!regionName[0]) {
                cursor = next;
                continue;
            }

            server::RegionEntry& entry = server::regions[server::regionCount];
            safe_strcpy(entry.regionName, regionName, sizeof(entry.regionName));
            entry.siteCount = 0;

            // Parse comma-separated sites
            const char* siteCursor = sitesStr;
            while (siteCursor && entry.siteCount < server::MAX_SITES_PER_REGION)
            {
                char site[64];
                __stosb((unsigned char*)site, 0, sizeof(site));
                const char* siteNext = NextToken(siteCursor, ',', site, sizeof(site));

                if (site[0]) {
                    safe_strcpy(entry.sites[entry.siteCount], site, sizeof(entry.sites[0]));
                    entry.siteCount++;
                }

                siteCursor = siteNext;
            }

            if (entry.siteCount > 0)
                server::regionCount++;

            cursor = next;
        }

        log::debugf("[SERVER] Parsed %d regions\r\n", server::regionCount);
    }
}

// ── Init ────────────────────────────────────────────────────────────────

bool server::Init(void* gameBase, unsigned long gameSize)
{
    initialized = false;

    if (!gameBase || !gameSize) {
        log::debug("[SERVER] Init: no game module\r\n");
        return false;
    }

    log::debug("[SERVER] Scanning patterns...\r\n");

    // ── Pattern 1: LoginAdaptorState ──
    void* m1 = game::pattern_scan(gameBase, gameSize,
        "48 89 5C 24 ? 57 48 83 EC ? 48 8B 05 ? ? ? ? 33 C9 48 8B 78 ? 48 8B 17 48 8B 9A ? ? ? ? E8");
    if (m1) {
        uintptr_t matchAddr = (uintptr_t)m1;
        // RIP-relative at match+10 (disp at +13): resolve to global
        g_LoginAdaptorState = resolve_rip(matchAddr + 10, 3, 7);
        // Byte at match+22: connection offset
        SafeReadU8(matchAddr + 22, &g_ConnectionOffset);
        // Dword at match+29: vtable offset for SetPingSite
        SafeReadI32(matchAddr + 29, &g_SetPingSiteVtOff);

        log::debugf(
            "[SERVER] LoginAdaptorState: %p, connOff=0x%02X, vtOff=0x%X\r\n",
            (void*)g_LoginAdaptorState, (unsigned int)g_ConnectionOffset, (unsigned int)g_SetPingSiteVtOff);
    } else {
        log::debug("[SERVER] ERROR: LoginAdaptorState pattern not found\r\n");
    }

    // ── Pattern 2: ConfigManager (GetConfigMgr call site) ──
    void* m2 = game::pattern_scan(gameBase, gameSize,
        "E8 ? ? ? ? 48 8B C8 48 85 C0 0F 84 ? ? ? ? 48 8B 00 4C 8D 4C 24 ? 4C 8D 05 ? ? ? ? 48 89 B4 24");
    if (m2) {
        uintptr_t matchAddr = (uintptr_t)m2;
        // Resolve E8 call target
        uintptr_t getConfigMgrFn = resolve_e8(matchAddr);

        if (getConfigMgrFn) {
            // First bytes should be 48 8B 05 (mov rax, [rip+...])
            unsigned char firstBytes[3] = {};
            __try {
                __movsb(firstBytes, (const unsigned char*)getConfigMgrFn, 3);
            } __except (1) {
                firstBytes[0] = 0;
            }

            if (firstBytes[0] == 0x48 && firstBytes[1] == 0x8B && firstBytes[2] == 0x05) {
                g_ConfigManager = resolve_rip(getConfigMgrFn, 3, 7);
                log::debugf("[SERVER] ConfigManager: %p\r\n", (void*)g_ConfigManager);
            } else {
                log::debugf(
                    "[SERVER] ERROR: getConfigMgrFn first bytes: %02X %02X %02X (expected 48 8B 05)\r\n",
                    (unsigned int)firstBytes[0], (unsigned int)firstBytes[1], (unsigned int)firstBytes[2]);
            }
        } else {
            log::debug("[SERVER] ERROR: getConfigMgrFn resolve failed\r\n");
        }
    } else {
        log::debug("[SERVER] ERROR: ConfigManager pattern not found\r\n");
    }

    // ── Pattern 3: GetBestPingSiteAlias ──
    void* m3 = game::pattern_scan(gameBase, gameSize,
        "48 83 EC 28 E8 ? ? ? ? BA 63 6E 6E 63 48 8B 08 4C 8B 41 60 48 8B C8 41 FF D0 48 8B C8 48 8B 10 48 83 C4 28 48 FF A2 88 00 00 00");
    if (m3) {
        uintptr_t matchAddr = (uintptr_t)m3;
        g_GetAliasFn = matchAddr;
        g_GetServiceLocatorFn = resolve_e8(matchAddr + 4);

        log::debugf("[SERVER] GetAliasFn: %p, ServiceLocator: %p\r\n",
            (void*)g_GetAliasFn, (void*)g_GetServiceLocatorFn);
    } else {
        log::debug("[SERVER] ERROR: GetBestPingSiteAlias pattern not found\r\n");
    }

    // ── Pattern 4: QosPing_DispatchMeasurements ──
    void* m4 = game::pattern_scan(gameBase, gameSize,
        "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 83 B9 70 02 00 00 00 0F B6 F2 48 8B D9 75 ? 48 8B 41 08 48 8B 88 38 08 00 00");
    if (m4) {
        g_QosPingDispatchAddr = (uintptr_t)m4;
        log::debugf("[SERVER] QosPingDispatch: %p\r\n", (void*)g_QosPingDispatchAddr);
    } else {
        log::debug("[SERVER] ERROR: QosPing_DispatchMeasurements pattern not found\r\n");
    }

    // ── Pattern 5: BlazeWrapper ──
    void* m5 = game::pattern_scan(gameBase, gameSize,
        "48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B C8 48 8B 10 48 83 C4 ? 48 FF 62 ? CC");
    if (m5) {
        g_BlazeWrapper = resolve_rip((uintptr_t)m5, 3, 7);
        log::debugf("[SERVER] BlazeWrapper: %p\r\n", (void*)g_BlazeWrapper);
    } else {
        log::debug("[SERVER] WARNING: BlazeWrapper pattern not found, trying fallback\r\n");
        // Fallback: g_ConfigManager - 8
        if (g_ConfigManager) {
            g_BlazeWrapper = g_ConfigManager - 8;
            log::debugf("[SERVER] BlazeWrapper (fallback): %p\r\n", (void*)g_BlazeWrapper);
        } else {
            log::debug("[SERVER] ERROR: BlazeWrapper fallback failed (no ConfigManager)\r\n");
        }
    }

    // Validate minimum required
    bool ok = g_LoginAdaptorState && g_BlazeWrapper && g_QosPingDispatchAddr && g_GetAliasFn;
    initialized = ok;

    log::debugf("[SERVER] Init: %s\r\n", ok ? "ALL OK" : "SOME MISSING");

    return ok;
}

bool server::IsReady()
{
    return initialized;
}

// ── SetForcedPingSite ───────────────────────────────────────────────────

void server::SetForcedPingSite(const char* alias)
{
    if (!initialized || !alias || !alias[0]) return;

    safe_strcpy(forcedPingSite, alias, sizeof(forcedPingSite));
    enableOverride = true;

    log::debugf("[SERVER] Forcing ping site: %s\r\n", alias);

    // 1. Modify the QoS latency map
    ModifyLatencyMap(alias);

    // 2. Force dispatch the modified data
    ForceDispatchQoS();

    // 3. Refresh current reading
    RefreshCurrentPingSite();

    toast::Show(toast::Type::Success, "Server forced");
}

// ── RestorePingSite ─────────────────────────────────────────────────────

void server::RestorePingSite()
{
    enableOverride = false;
    __stosb((unsigned char*)forcedPingSite, 0, sizeof(forcedPingSite));

    log::debug("[SERVER] Ping site override restored\r\n");

    // Dispatch with original values (they'll re-measure naturally)
    ForceDispatchQoS();

    RefreshCurrentPingSite();
    toast::Show(toast::Type::Info, "Server restored");
}

// ── RefreshCurrentPingSite ──────────────────────────────────────────────

void server::RefreshCurrentPingSite()
{
    __stosb((unsigned char*)currentPingSite, 0, sizeof(currentPingSite));

    const char* alias = ReadCurrentPingSite();
    if (alias && alias[0]) {
        __try {
            safe_strcpy(currentPingSite, alias, sizeof(currentPingSite));
        } __except (1) {
            safe_strcpy(currentPingSite, "???", sizeof(currentPingSite));
        }
    }

    log::debugf("[SERVER] Current ping site: %s\r\n",
        currentPingSite[0] ? currentPingSite : "N/A");
}

// ── EnumerateRegions ────────────────────────────────────────────────────

void server::EnumerateRegions()
{
    regionCount = 0;
    __stosb((unsigned char*)regions, 0, sizeof(regions));

    if (!g_ConfigManager) {
        log::debug("[SERVER] EnumerateRegions: ConfigManager null\r\n");
        toast::Show(toast::Type::Error, "ConfigManager not found");
        return;
    }

    uintptr_t cfgInstance = 0;
    if (!SafeReadPtr(g_ConfigManager, &cfgInstance) || !cfgInstance) {
        log::debug("[SERVER] EnumerateRegions: ConfigManager deref null\r\n");
        toast::Show(toast::Type::Error, "ConfigManager instance null");
        return;
    }

    // Read vtable
    uintptr_t vtable = 0;
    if (!SafeReadPtr(cfgInstance, &vtable) || !vtable) {
        log::debug("[SERVER] EnumerateRegions: vtable null\r\n");
        return;
    }

    // vtable[7] (offset 0x38) = ReadConfigString
    // Signature: void(this, key, default, outBuf, bufSize)
    uintptr_t readConfigFn = 0;
    if (!SafeReadPtr(vtable + 0x38, &readConfigFn) || !readConfigFn) {
        log::debug("[SERVER] EnumerateRegions: ReadConfigString vtable entry null\r\n");
        return;
    }

    char outBuf[2048];
    __stosb((unsigned char*)outBuf, 0, sizeof(outBuf));

    typedef void(__fastcall* read_config_fn_t)(
        uintptr_t thisPtr, const char* key, const char* defaultVal,
        char* outBuf, int bufSize);
    auto fn = reinterpret_cast<read_config_fn_t>(readConfigFn);

    // Call directly — NOT through spoof_call.
    // spoof_call clobbers the 5th arg (bufSize) at [RSP+28h] for 5-arg functions.
    // FC26 does the same: direct call for internal game functions.
    __try {
        fn(cfgInstance,
            (const char*)"OSDK_CLUBS_PING_SITE_REGIONS_MAP",
            (const char*)"",
            (char*)outBuf,
            (int)sizeof(outBuf));
    } __except (1) {
        log::debug("[SERVER] EnumerateRegions: ReadConfigString exception\r\n");
        toast::Show(toast::Type::Error, "Config read failed");
        return;
    }

    if (!outBuf[0]) {
        log::debug("[SERVER] EnumerateRegions: empty result\r\n");
        toast::Show(toast::Type::Warning, "No regions returned");
        return;
    }

    char logBuf[256];
    // Truncate outBuf for logging (fmt doesn't support precision specifiers)
    char truncBuf[200];
    {
        int ci = 0;
        while (outBuf[ci] && ci < 199) { truncBuf[ci] = outBuf[ci]; ci++; }
        truncBuf[ci] = '\0';
    }
    log::debugf("[SERVER] Raw config: %s\r\n", truncBuf);

    ParseRegionsString(outBuf);

    if (regionCount > 0) {
        char logBuf[256];
        fmt::snprintf(logBuf, sizeof(logBuf), "Loaded %d regions", regionCount);
        toast::Show(toast::Type::Success, logBuf);
    } else {
        toast::Show(toast::Type::Warning, "No regions parsed");
    }
}

// ── IsConnected ─────────────────────────────────────────────────────────

bool server::IsConnected()
{
    uintptr_t loginMgr = GetLoginManager();
    if (!loginMgr) return false;

    // vtable[27] (offset 0xD8) = IsLoggedIntoEA
    uintptr_t vtable = 0;
    if (!SafeReadPtr(loginMgr, &vtable) || !vtable) return false;

    uintptr_t isLoggedInFn = 0;
    if (!SafeReadPtr(vtable + 0xD8, &isLoggedInFn) || !isLoggedInFn) return false;

    typedef bool(__fastcall* is_logged_in_fn_t)(uintptr_t);
    auto fn = reinterpret_cast<is_logged_in_fn_t>(isLoggedInFn);

    __try {
        bool result = spoof_call(fn, loginMgr);
        connected = result;
        return result;
    } __except (1) {
        return false;
    }
}

// ── Disconnect ──────────────────────────────────────────────────────────

void server::Disconnect()
{
    uintptr_t loginMgr = GetLoginManager();
    if (!loginMgr) {
        toast::Show(toast::Type::Error, "Login manager not found");
        return;
    }

    uintptr_t vtable = 0;
    if (!SafeReadPtr(loginMgr, &vtable) || !vtable) return;

    // vtable[7] (offset 0x38) = Logout(this, 0)
    uintptr_t logoutFn = 0;
    if (!SafeReadPtr(vtable + 0x38, &logoutFn) || !logoutFn) return;

    typedef void(__fastcall* logout_fn_t)(uintptr_t, int);
    auto fn = reinterpret_cast<logout_fn_t>(logoutFn);

    __try {
        spoof_call(fn, loginMgr, (int)0);
        log::debug("[SERVER] Disconnect sent\r\n");
        toast::Show(toast::Type::Info, "Disconnected");
    } __except (1) {
        log::debug("[SERVER] Disconnect exception\r\n");
        toast::Show(toast::Type::Error, "Disconnect failed");
    }
}

// ── Reconnect ───────────────────────────────────────────────────────────

void server::Reconnect()
{
    uintptr_t loginMgr = GetLoginManager();
    if (!loginMgr) {
        toast::Show(toast::Type::Error, "Login manager not found");
        return;
    }

    uintptr_t vtable = 0;
    if (!SafeReadPtr(loginMgr, &vtable) || !vtable) return;

    // vtable[10] (offset 0x50) = StartSilentLogin(this, 0, 1, 0)
    uintptr_t silentLoginFn = 0;
    if (!SafeReadPtr(vtable + 0x50, &silentLoginFn) || !silentLoginFn) return;

    typedef void(__fastcall* silent_login_fn_t)(uintptr_t, int, int, int);
    auto fn = reinterpret_cast<silent_login_fn_t>(silentLoginFn);

    __try {
        spoof_call(fn, loginMgr, (int)0, (int)1, (int)0);
        log::debug("[SERVER] Reconnect sent\r\n");
        toast::Show(toast::Type::Info, "Reconnecting...");
    } __except (1) {
        log::debug("[SERVER] Reconnect exception\r\n");
        toast::Show(toast::Type::Error, "Reconnect failed");
    }
}

// ── GetRegionLabel ──────────────────────────────────────────────────────

const char* server::GetRegionLabel(int idx)
{
    if (idx < 0 || idx >= regionCount) return "???";
    return regions[idx].regionName;
}
