#include "ai_trace.h"

#include <Windows.h>
#include "../offsets/offsets.h"
#include "../hook/ept_hook.h"
#include "../log/log.h"
#include "../log/fmt.h"

volatile bool ai_trace::g_traceOpcodes = false;

// ── Dedicated log file ────────────────────────────────────────────────
// Kept separate from zerohook.log so trace noise doesn't swamp the primary
// log we read for gameplay debugging.
namespace
{
    const char* trace_log_path()
    {
        static char path[MAX_PATH] = {};
        if (path[0] == '\0')
        {
            DWORD len = GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH);
            if (len > 0 && len < MAX_PATH - 48)
                lstrcatA(path, "\\Documents\\zerohook_ai_trace.log");
            else
            {
                GetTempPathA(MAX_PATH, path);
                lstrcatA(path, "zerohook_ai_trace.log");
            }
        }
        return path;
    }

    void write_trace(const char* msg)
    {
        static bool s_firstCall = true;
        DWORD access   = FILE_APPEND_DATA;
        DWORD creation = OPEN_ALWAYS;
        if (s_firstCall)
        {
            s_firstCall = false;
            access   = GENERIC_WRITE;
            creation = CREATE_ALWAYS;
        }
        HANDLE h = CreateFileA(trace_log_path(), access,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, creation,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE)
        {
            DWORD n = 0;
            WriteFile(h, msg, lstrlenA(msg), &n, nullptr);
            CloseHandle(h);
        }
    }

    inline unsigned long long capture_retaddr(void* ctx)
    {
        unsigned long long ra = 0;
        __try {
            unsigned long long rsp = ((ept::register_context_t*)ctx)->original_rsp;
            if (rsp) ra = *(unsigned long long*)rsp;
        } __except (1) {}
        return ra;
    }

    inline void emit_line(const char* fn, const char* extra, void* ctx)
    {
        if (!ai_trace::kEnabled) return;

        SYSTEMTIME st;
        GetLocalTime(&st);
        unsigned long long ra = capture_retaddr(ctx);

        char buf[512];
        fmt::snprintf(buf, sizeof(buf),
            "[%02d:%02d:%02d.%03d] [AI_TRACE] %s %s retaddr=%016llX tid=%u\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            fn, extra ? extra : "", ra, (unsigned)GetCurrentThreadId());
        write_trace(buf);
    }
}

void ai_trace::log_line(const char* msg) { write_trace(msg); }

// ── EPT params (one page each; shared via __declspec(align(4096))) ───
namespace
{
    // Active-path hooks (things that actually fire in-game).
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_afkDecisionBrain    = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_afkTakeover         = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_playerReturned      = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_stateSync           = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_resumeWrap          = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_featureFlagGet      = {};

    // Tripwires — zero hits so far but positioned to catch specific events.
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_takeoverActivate    = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_takeoverResume      = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_takeoverSlot        = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_createPlayerSwitch  = {};

    // Removed: TakeoverSlotWrap, ReleaseSlotWrap, PauseWrap, LxSetIsIdle,
    // LxSetIsActive, ReleaseSlot, TeamRelease, OnlineCpuStateMachine.
    // All either thin wrappers over already-hooked functions, Lua-script
    // only, or fire exclusively in menu/lobby (not the in-game AFK path
    // we care about).
}

// ── Detours (all return 0 = pass through; none mutate state) ─────────
//
// EPT stub calling convention: (void* ctx, ...original fastcall args). We
// read args directly; ctx is only used for retaddr + register inspection.

extern "C" unsigned long long TraceHook_TakeoverActivate(
    void* ctx, unsigned long long a1, char a2, char a3)
{
    char extra[128];
    fmt::snprintf(extra, sizeof(extra),
        "(matchCtx=%016llX, a2=%d, a3=%d)", a1, (int)a2, (int)a3);
    emit_line("sub_1427FA200 AI_TAKEOVER_ACTIVATE", extra, ctx);
    return 0;
}

extern "C" unsigned long long TraceHook_TakeoverResume(
    void* ctx, unsigned long long a1)
{
    char extra[64];
    fmt::snprintf(extra, sizeof(extra), "(matchCtx=%016llX)", a1);
    emit_line("sub_1427FCBD0 AI_TAKEOVER_RESUME", extra, ctx);
    return 0;
}

extern "C" unsigned long long TraceHook_TakeoverSlot(
    void* ctx, unsigned long long a1, int a2)
{
    char extra[96];
    fmt::snprintf(extra, sizeof(extra),
        "(matchCtx=%016llX, slot=%d)", a1, a2);
    emit_line("sub_142814760 TAKEOVER_SLOT", extra, ctx);
    return 0;
}

extern "C" unsigned long long TraceHook_ResumeWrap(
    void* ctx, unsigned long long a1, unsigned long long a2)
{
    char extra[96];
    fmt::snprintf(extra, sizeof(extra),
        "(pauseCtx=%016llX a2=%016llX)", a1, a2);
    emit_line("sub_148A9FFA0 RESUME->TAKEOVER", extra, ctx);
    return 0;
}

// Feature-flag reader fires per-lookup (many per frame on flag-heavy paths).
// Dedupe by name: each unique flag name is logged exactly once per session.
// In a previous run only 7 unique names appeared across 2000+ calls, so a
// fixed-size seen-list is plenty. Races are tolerated (may produce an
// occasional duplicate), never corruption.
namespace
{
    constexpr int kFfgNameCap = 256;
    constexpr int kFfgNameLen = 96;
    volatile long g_ffgSeenCount = 0;
    char          g_ffgSeenNames[kFfgNameCap][kFfgNameLen] = {};

    inline bool str_eq(const char* a, const char* b)
    {
        while (*a && *b && *a == *b) { ++a; ++b; }
        return *a == 0 && *b == 0;
    }
}
extern "C" unsigned long long TraceHook_FeatureFlagGet(
    void* ctx, unsigned long long a1, const char* a2, unsigned int a3)
{
    if (!a2) return 0;

    // 1. Scan already-seen names. If found, suppress.
    long seen = g_ffgSeenCount;
    if (seen > kFfgNameCap) seen = kFfgNameCap;
    __try {
        for (long i = 0; i < seen; ++i)
            if (str_eq(g_ffgSeenNames[i], a2)) return 0;
    } __except (1) { return 0; }

    // 2. Claim a slot atomically. Bail if the table is full.
    long idx = _InterlockedIncrement(&g_ffgSeenCount) - 1;
    if (idx >= kFfgNameCap) return 0;

    // 3. Copy the name (printable ASCII only, zero-terminated).
    __try {
        int k = 0;
        while (k < kFfgNameLen - 1
               && ((const unsigned char*)a2)[k] >= 0x20
               && ((const unsigned char*)a2)[k] < 0x7F) {
            g_ffgSeenNames[idx][k] = a2[k];
            ++k;
        }
        g_ffgSeenNames[idx][k] = 0;
    } __except (1) { return 0; }

    char extra[192];
    fmt::snprintf(extra, sizeof(extra),
        "(FIRST SEEN; table=%016llX name=\"%s\" default=%u)",
        a1, g_ffgSeenNames[idx], a3);
    emit_line("sub_146549750 FEATURE_FLAG_GET", extra, ctx);
    return 0;
}

extern "C" unsigned long long TraceHook_StateSync(
    void* ctx, unsigned long long a1, int a2, int a3)
{
    char extra[96];
    fmt::snprintf(extra, sizeof(extra),
        "(matchCtx=%016llX slot=%d flag=%d)", a1, a2, a3);
    emit_line("sub_14282B1D0 STATE_SYNC", extra, ctx);
    return 0;
}

extern "C" unsigned long long TraceHook_CreatePlayerSwitch(
    void* ctx, unsigned long long a1, unsigned long long a2,
    unsigned long long a3)
{
    char extra[128];
    fmt::snprintf(extra, sizeof(extra),
        "(a1=%016llX matchCtx=%016llX a3=%016llX)", a1, a2, a3);
    emit_line("sub_146E98A00 CREATE_PLAYER_SWITCH", extra, ctx);
    return 0;
}

// sub_142822CE0 — per-slot "player returned from AFK" (release companion).
// Called by AFK brain when the idle timer hasn't expired OR when explicit
// "user is back" event fires. Also called by sub_1427FA200 per-slot when
// matchCtx[0x4CA1] is clear.
extern "C" unsigned long long TraceHook_PlayerReturned(
    void* ctx, unsigned long long a1, unsigned int a2)
{
    char extra[96];
    fmt::snprintf(extra, sizeof(extra),
        "(matchCtx=%016llX slot=%u)", a1, a2);
    emit_line("sub_142822CE0 PLAYER_RETURNED", extra, ctx);
    return 0;
}

// ── AFK detection / policy ──────────────────────────────────────────

// sub_14282BB00 — THE AFK DECISION BRAIN. Queries three feature flags
// and maintains per-slot idle timers. Runs ~60 Hz during gameplay (once
// per slot per tick). CHANGE-DETECT per slot — only log when the 4-byte
// state signature for that slot changes.
namespace
{
    // Per-slot last-seen signature: 4 bytes packed into one uint32.
    // Byte 0: latch2554, 1: latch2557, 2: perslot_isAI, 3: perslot_timerOn.
    // Initial sentinel 0xFFFFFFFF guarantees first real sample logs.
    volatile unsigned int g_lastAfkBrain[22] = {
        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
    };
}
extern "C" unsigned long long TraceHook_AfkDecisionBrain(
    void* ctx, unsigned long long a1, unsigned int a2,
    unsigned long long a3, unsigned long long a4, unsigned int a5)
{
    if (a2 >= 22) return 0;  // out-of-range slot — safe skip

    unsigned char latch2554 = 0xFF;
    unsigned char latch2557 = 0xFF;
    unsigned char idleTimer = 0xFF;
    unsigned char idleActive= 0xFF;
    __try {
        latch2554  = *(unsigned char*)(a1 + 0x2554);
        latch2557  = *(unsigned char*)(a1 + 0x2557);
        idleTimer  = *(unsigned char*)(a1 + 0x4CD0 + (unsigned long long)a2 * 128);
        idleActive = *(unsigned char*)(a1 + 0x4CD1 + (unsigned long long)a2 * 128);
    } __except (1) {}

    unsigned int sig = ((unsigned int)latch2554)
                     | ((unsigned int)latch2557  << 8)
                     | ((unsigned int)idleTimer  << 16)
                     | ((unsigned int)idleActive << 24);

    // Fast-path: suppress identical repeats for this slot.
    if (sig == g_lastAfkBrain[a2]) return 0;
    g_lastAfkBrain[a2] = sig;

    char extra[256];
    fmt::snprintf(extra, sizeof(extra),
        "(matchCtx=%016llX slot=%u a3=%016llX eventType=%u latch2554=%u latch2557=%u perslot_isAI=%u perslot_timerOn=%u)",
        a1, a2, a3, a5, latch2554, latch2557, idleTimer, idleActive);
    emit_line("sub_14282BB00 AFK_DECISION_BRAIN", extra, ctx);
    return 0;
}

// sub_1427F7640 (FnAfkTakeover) — per-slot AFK takeover execution.
// CHANGE-DETECT: only log when (slot, teamFlag, eventType) differs from
// last call. Fires per-frame once a slot enters AFK state — previously
// emitted ~10 Hz of file I/O during a match.
namespace
{
    volatile unsigned long long g_lastAfkTakeoverSig = 0xFFFFFFFFFFFFFFFFULL;
}
extern "C" unsigned long long TraceHook_AfkTakeover(
    void* ctx, unsigned long long a1, unsigned long long a2,
    unsigned char a3, unsigned char a4)
{
    unsigned long long sig = ((a2 & 0xFFFF) << 16)
                           | ((unsigned long long)a3 << 8)
                           | (unsigned long long)a4;

    if (sig == g_lastAfkTakeoverSig) return 0;
    g_lastAfkTakeoverSig = sig;

    char extra[128];
    fmt::snprintf(extra, sizeof(extra),
        "(matchCtx=%016llX slot=%llu teamFlag=%u eventType=%u)",
        a1, a2, (unsigned)a3, (unsigned)a4);
    emit_line("sub_1427F7640 AFK_TAKEOVER", extra, ctx);
    return 0;
}

// ── install_all ──────────────────────────────────────────────────────
//
// Every target has a known RVA from the IDA dump (imagebase 0x140000000),
// so we don't pattern-scan — we compute `GameBase + rva` directly. Immune
// to false-positive matches (previous pattern-scan landed TAKEOVER_SLOT_WRAP
// on the wrong function and spammed 9k log lines/session), and lets us hook
// short/template-shaped functions that have no unique prologue.
//
// If the game binary updates and RVAs shift, re-dump and update this table.
namespace
{
    // IDA imagebase for FC26 07_04_2026.exe dump.
    constexpr uintptr_t kIdaImageBase = 0x140000000ULL;

    struct trace_target_t
    {
        const char* name;
        uintptr_t   ida_addr;  // absolute address from IDA (includes imagebase)
        void*       detour;
        ept::ept_hook_install_params_t* params;
    };

    void install_one(const trace_target_t& t)
    {
        char buf[192];

        uintptr_t rva    = t.ida_addr - kIdaImageBase;
        uintptr_t target = (uintptr_t)offsets::GameBase + rva;

        if (rva >= (uintptr_t)offsets::GameSize)
        {
            fmt::snprintf(buf, sizeof(buf),
                "[AI_TRACE] SKIP %s: rva=%llx out of module (size=%lx)\r\n",
                t.name, (unsigned long long)rva,
                (unsigned long)offsets::GameSize);
            ai_trace::log_line(buf);
            log::debug(buf);
            return;
        }

        fmt::snprintf(buf, sizeof(buf),
            "[AI_TRACE] installing %s @ %p (rva=%llx)\r\n",
            t.name, (void*)target, (unsigned long long)rva);
        ai_trace::log_line(buf);
        log::debug(buf);

        ept::install_hook(*t.params, (unsigned char*)target, t.detour, t.name);
    }
}

void ai_trace::install_all()
{
    if (!kEnabled) return;
    if (!offsets::GameBase || !offsets::GameSize) return;

    // Header — marks start of a new trace session.
    SYSTEMTIME st;
    GetLocalTime(&st);
    char hdr[192];
    fmt::snprintf(hdr, sizeof(hdr),
        "\r\n==== AI_TRACE session start %04d-%02d-%02d %02d:%02d:%02d (GameBase=%p) ====\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        offsets::GameBase);
    log_line(hdr);

    const trace_target_t targets[] = {
        // Active-path (in-game) — all protected with change-detect where
        // they fire at frame rate.
        { "sub_14282BB00 AFK_DECISION_BRAIN",   0x14282BB00ULL,
          (void*)&TraceHook_AfkDecisionBrain,    &g_params_afkDecisionBrain    },
        { "sub_1427F7640 AFK_TAKEOVER",         0x1427F7640ULL,
          (void*)&TraceHook_AfkTakeover,         &g_params_afkTakeover         },
        { "sub_142822CE0 PLAYER_RETURNED",      0x142822CE0ULL,
          (void*)&TraceHook_PlayerReturned,      &g_params_playerReturned      },
        { "sub_14282B1D0 STATE_SYNC",           0x14282B1D0ULL,
          (void*)&TraceHook_StateSync,           &g_params_stateSync           },
        { "sub_148A9FFA0 RESUME_WRAP",          0x148A9FFA0ULL,
          (void*)&TraceHook_ResumeWrap,          &g_params_resumeWrap          },
        { "sub_146549750 FEATURE_FLAG_GET",     0x146549750ULL,
          (void*)&TraceHook_FeatureFlagGet,      &g_params_featureFlagGet      },

        // Tripwires — only log when the specific event actually fires.
        { "sub_1427FA200 TAKEOVER_ACTIVATE",    0x1427FA200ULL,
          (void*)&TraceHook_TakeoverActivate,    &g_params_takeoverActivate    },
        { "sub_1427FCBD0 TAKEOVER_RESUME",      0x1427FCBD0ULL,
          (void*)&TraceHook_TakeoverResume,      &g_params_takeoverResume      },
        { "sub_142814760 TAKEOVER_SLOT",        0x142814760ULL,
          (void*)&TraceHook_TakeoverSlot,        &g_params_takeoverSlot        },
        { "sub_146E98A00 CREATE_PLAYER_SWITCH", 0x146E98A00ULL,
          (void*)&TraceHook_CreatePlayerSwitch,  &g_params_createPlayerSwitch  },
    };

    for (const auto& t : targets) install_one(t);

    log_line("[AI_TRACE] install_all complete\r\n");
}
