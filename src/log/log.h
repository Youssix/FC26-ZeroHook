#pragma once
#include <Windows.h>

namespace log
{
    inline const char* get_log_path()
    {
        static char path[MAX_PATH] = {};
        if (path[0] == '\0')
        {
            // %USERPROFILE%\Documents\ring1_inject.log
            DWORD len = GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH);
            if (len > 0 && len < MAX_PATH - 40)
                lstrcatA(path, "\\Documents\\ring1_inject.log");
            else
            {
                GetTempPathA(MAX_PATH, path);
                lstrcatA(path, "ring1_inject.log");
            }
        }
        return path;
    }

    inline void to_file(const char* msg)
    {
        // First call: truncate the log file so each injection starts clean
        static bool s_firstCall = true;
        DWORD access = FILE_APPEND_DATA;
        DWORD creation = OPEN_ALWAYS;

        if (s_firstCall)
        {
            s_firstCall = false;
            access = GENERIC_WRITE;
            creation = CREATE_ALWAYS;  // truncates existing file
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
            if (access == FILE_APPEND_DATA)
            {
                // Normal append — seek to end already handled by FILE_APPEND_DATA
            }
            DWORD written = 0;
            WriteFile(hFile, msg, lstrlenA(msg), &written, nullptr);
            CloseHandle(hFile);
        }
    }
}
