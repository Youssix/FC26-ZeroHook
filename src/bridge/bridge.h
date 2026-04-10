#pragma once
#include "memory_ops.h"
#include "protocol.h"
#include "pipe_server.h"

namespace bridge {

    inline bool init(const char* gameName)
    {
        auto& apis = pipeApis();
        if (!apis.pCreateThread) return false;

        // Build pipe name: \\.\pipe\zerohook-GAMENAME
        const char* prefix = "\\\\.\\pipe\\zerohook-";
        int pos = 0;
        while (*prefix && pos < 62) g_pipeName[pos++] = *prefix++;
        while (*gameName && pos < 62) g_pipeName[pos++] = *gameName++;
        g_pipeName[pos] = '\0';

        InterlockedExchange(&g_shutdown, 0);

        g_thread = apis.pCreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)pipeThread, nullptr, 0, nullptr);
        if (!g_thread) return false;

        char logBuf[128];
        fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Started on %s\n", g_pipeName);
        log::to_file(logBuf);
        return true;
    }

    inline void shutdown()
    {
        InterlockedExchange(&g_shutdown, 1);

        auto& apis = pipeApis();
        if (g_thread && apis.pWaitForSingleObject) {
            apis.pWaitForSingleObject(g_thread, 2000);
            if (apis.pCloseHandle) apis.pCloseHandle(g_thread);
            g_thread = nullptr;
        }

        char logBuf[64];
        fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Shutdown complete\n");
        log::to_file(logBuf);
    }

} // namespace bridge
