#include "ai_trace.h"

#include <Windows.h>
#include "../offsets/offsets.h"
#include "../game/game.h"
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
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_takeoverActivate    = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_takeoverResume      = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_takeoverSlot        = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_pauseWrap           = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_resumeWrap          = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_featureFlagGet      = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_stateSync           = {};
    __declspec(align(4096)) ept::ept_hook_install_params_t g_params_createPlayerSwitch  = {};
    // Note: no TAKEOVER_SLOT_WRAP hook — sub_148ACCB00 is a 10-byte thunk to
    // sub_142814760 (which we already hook). Its prologue is too generic
    // (40 53 48 83 EC 20 ... 5B E9) and pattern-matched the wrong function
    // firing ~30Hz. Dropped to eliminate 82% of previous trace-log noise.
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

extern "C" unsigned long long TraceHook_PauseWrap(
    void* ctx, unsigned long long a1, unsigned long long a2)
{
    char extra[96];
    fmt::snprintf(extra, sizeof(extra),
        "(pauseCtx=%016llX a2=%016llX)", a1, a2);
    emit_line("sub_148A9FEB0 PAUSE->TAKEOVER", extra, ctx);
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

// ── install_all ──────────────────────────────────────────────────────
namespace
{
    struct trace_target_t
    {
        const char* name;
        const char* pattern;
        void*       detour;
        ept::ept_hook_install_params_t* params;
        void**      resolved; // optional: if non-null, store resolved addr here
    };

    void install_one(const trace_target_t& t)
    {
        char buf[192];
        void* match = game::pattern_scan(
            offsets::GameBase, offsets::GameSize, t.pattern);
        if (!match)
        {
            fmt::snprintf(buf, sizeof(buf),
                "[AI_TRACE] SKIP %s: pattern not resolved\r\n", t.name);
            ai_trace::log_line(buf);
            log::debug(buf);
            return;
        }

        fmt::snprintf(buf, sizeof(buf),
            "[AI_TRACE] resolved %s -> %p\r\n", t.name, match);
        ai_trace::log_line(buf);
        log::debug(buf);

        if (t.resolved) *t.resolved = match;

        ept::install_hook(*t.params, (unsigned char*)match, t.detour, t.name);
    }
}

void ai_trace::install_all()
{
    if (!kEnabled) return;
    if (!offsets::GameBase || !offsets::GameSize) return;

    // Header — marks start of a new trace session.
    SYSTEMTIME st;
    GetLocalTime(&st);
    char hdr[160];
    fmt::snprintf(hdr, sizeof(hdr),
        "\r\n==== AI_TRACE session start %04d-%02d-%02d %02d:%02d:%02d ====\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    log_line(hdr);

    // Note: sub_146F01F40 / sub_146F04EA0 (lxSetPlayerIsIdlePlayer and
    // its sibling) share an identical prologue with ~15 other Lua binding
    // wrappers, so pattern-scan can't uniquely locate them without deeper
    // body signatures. Skipped here; they're Lua-driven and unlikely to
    // fire in online gameplay anyway.

    trace_target_t targets[] = {
        {
            "sub_1427FA200 TAKEOVER_ACTIVATE",
            "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 41 54 41 55 41 56 41 57 B8 40 24 00 00 E8",
            (void*)&TraceHook_TakeoverActivate,
            &g_params_takeoverActivate, nullptr
        },
        {
            "sub_1427FCBD0 TAKEOVER_RESUME",
            "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 41 56 41 57 48 8D AC 24 C0 DC FF FF B8 40 24 00 00",
            (void*)&TraceHook_TakeoverResume,
            &g_params_takeoverResume, nullptr
        },
        {
            "sub_148A9FEB0 PAUSE_WRAP",
            "40 57 48 83 EC 20 80 39 00 48 8B F9 0F 84 ? ? ? ? 83 79 08 00 0F 84 ? ? ? ? 80 79 01 00",
            (void*)&TraceHook_PauseWrap,
            &g_params_pauseWrap, nullptr
        },
        {
            "sub_148A9FFA0 RESUME_WRAP",
            "48 83 EC 28 80 79 0C 00 0F 84 ? ? ? ? 48 89 5C 24 30 48 89 7C 24 20 C6 41 0C 00 E8",
            (void*)&TraceHook_ResumeWrap,
            &g_params_resumeWrap, nullptr
        },
        {
            "sub_146549750 FEATURE_FLAG_GET",
            "48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 20 45 8B F0 48 8B F2 48 8B E9",
            (void*)&TraceHook_FeatureFlagGet,
            &g_params_featureFlagGet, nullptr
        },
        {
            "sub_146E98A00 CREATE_PLAYER_SWITCH",
            "48 89 5C 24 08 48 89 74 24 18 48 89 7C 24 20 55 41 54 41 55 41 56 41 57 48 8D AC 24 30 F9 FF FF",
            (void*)&TraceHook_CreatePlayerSwitch,
            &g_params_createPlayerSwitch, nullptr
        },
    };

    for (const auto& t : targets) install_one(t);

    // sub_142814760 (FnTakeOverSlot) and sub_14282B1D0 (FnAiStateSync)
    // are already resolved by offsets::Init(). Hook them directly.
    if (offsets::FnTakeOverSlot)
    {
        ept::install_hook(g_params_takeoverSlot,
            (unsigned char*)offsets::FnTakeOverSlot,
            (void*)&TraceHook_TakeoverSlot,
            "sub_142814760 TAKEOVER_SLOT");
        char b[128];
        fmt::snprintf(b, sizeof(b),
            "[AI_TRACE] hooked sub_142814760 -> %p\r\n",
            offsets::FnTakeOverSlot);
        log_line(b);
    }
    if (offsets::FnAiStateSync)
    {
        ept::install_hook(g_params_stateSync,
            (unsigned char*)offsets::FnAiStateSync,
            (void*)&TraceHook_StateSync,
            "sub_14282B1D0 STATE_SYNC");
        char b[128];
        fmt::snprintf(b, sizeof(b),
            "[AI_TRACE] hooked sub_14282B1D0 -> %p\r\n",
            offsets::FnAiStateSync);
        log_line(b);
    }

    log_line("[AI_TRACE] install_all complete\r\n");
}
