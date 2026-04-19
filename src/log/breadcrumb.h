#pragma once
#include <Windows.h>
#include "log.h"
#include "fmt.h"

// Crash-survival breadcrumb.
//
// Writes a single-line "last known stage" marker to a dedicated small file
// and FORCES a physical disk flush before returning. Unlike the main
// zerohook.log (which relies on OS cache), this file is guaranteed to
// survive a hard reset / BSOD / hypervisor abort.
//
// Usage model:
//   - Call breadcrumb::set("stage") right before any code that might
//     freeze/restart the machine (EPT hook install, kickoff dispatch,
//     spoof_call into game code).
//   - On next DllMain ATTACH, call breadcrumb::rescue_previous() — it
//     reads whatever the crumb file contained, copies it into the main
//     log prefixed with "[PREV SESSION LAST STAGE]", then deletes it.
//
// The flush is expensive (~1-10ms) so DO NOT call this per-tick — only
// at dangerous-path transitions (every few seconds at most).

namespace breadcrumb
{
    inline const char* get_path()
    {
        static char path[MAX_PATH] = {};
        if (path[0] == '\0')
        {
            DWORD len = GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH);
            if (len > 0 && len < MAX_PATH - 48)
                lstrcatA(path, "\\Documents\\zerohook_crumb.log");
            else
            {
                GetTempPathA(MAX_PATH, path);
                lstrcatA(path, "zerohook_crumb.log");
            }
        }
        return path;
    }

    inline void set(const char* stage)
    {
        if (!g_debugLog) return;

        SYSTEMTIME st;
        GetLocalTime(&st);
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();

        char line[256];
        fmt::snprintf(line, sizeof(line),
            "[%04d-%02d-%02d %02d:%02d:%02d.%03d] pid=%u tid=%u %s\r\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            pid, tid, stage ? stage : "(null)");

        HANDLE h = CreateFileA(
            get_path(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (h == INVALID_HANDLE_VALUE) return;

        DWORD written = 0;
        WriteFile(h, line, lstrlenA(line), &written, nullptr);
        FlushFileBuffers(h);   // force physical disk write — survives hard reset
        CloseHandle(h);
    }

    // Must be called once at startup, before anything else may set a new crumb.
    // Reads the previous session's crumb (if any), copies it to the main log
    // with a clear header, then deletes the crumb file.
    inline void rescue_previous()
    {
        const char* path = get_path();
        HANDLE h = CreateFileA(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (h == INVALID_HANDLE_VALUE) return;

        char buf[512] = {};
        DWORD read = 0;
        ReadFile(h, buf, sizeof(buf) - 1, &read, nullptr);
        CloseHandle(h);
        DeleteFileA(path);

        if (read == 0) return;
        buf[read < sizeof(buf) - 1 ? read : sizeof(buf) - 1] = '\0';

        log::to_file("\r\n========================================\r\n");
        log::to_file("[PREV SESSION LAST STAGE]\r\n");
        log::to_file(buf);
        log::to_file("========================================\r\n\r\n");
    }
}
