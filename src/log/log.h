#pragma once
#include <Windows.h>

// Set to true to enable verbose address/offset logging (for dev only)
inline constexpr bool g_debugLog = false;

namespace log
{
    inline const char* get_log_path()
    {
        static char path[MAX_PATH] = {};
        if (path[0] == '\0')
        {
            // %USERPROFILE%\Documents\zerohook.log
            DWORD len = GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH);
            if (len > 0 && len < MAX_PATH - 40)
                lstrcatA(path, "\\Documents\\zerohook.log");
            else
            {
                GetTempPathA(MAX_PATH, path);
                lstrcatA(path, "zerohook.log");
            }
        }
        return path;
    }

    inline void to_file(const char* msg)
    {
        static bool s_firstCall = true;
        DWORD access = FILE_APPEND_DATA;
        DWORD creation = OPEN_ALWAYS;

        if (s_firstCall)
        {
            s_firstCall = false;
            access = GENERIC_WRITE;
            creation = CREATE_ALWAYS;
        }

        HANDLE hFile = CreateFileA(
            get_log_path(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            creation,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            WriteFile(hFile, msg, lstrlenA(msg), &written, nullptr);
            CloseHandle(hFile);
        }
    }

    inline void debug(const char* msg)
    {
        if (g_debugLog) to_file(msg);
    }
}
