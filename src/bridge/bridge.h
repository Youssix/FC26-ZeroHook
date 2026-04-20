#pragma once
#include "memory_ops.h"
#include "protocol.h"
#include "pipe_server.h"
#include "../log/log.h"

namespace bridge {

    inline bool init(const char* gameName)
    {
        // Production gate: the entire bridge (named pipe, acceptor threads,
        // BP/watch install paths, ring buffers) is dev-only infrastructure
        // and must NEVER run in shipping builds. `g_debugLog` is inline
        // constexpr, so `if constexpr` is a compile-time strip — when the
        // flag is false the linker removes all bridge code, no named pipe
        // appears, no threads spawn, zero attack surface.
        if constexpr (!g_debugLog) return false;

        auto& apis = pipeApis();
        if (!apis.pCreateThread) return false;

        // Build pipe name: \\.\pipe\zerohook-GAMENAME
        const char* prefix = "\\\\.\\pipe\\zerohook-";
        int pos = 0;
        while (*prefix && pos < 62) g_pipeName[pos++] = *prefix++;
        while (*gameName && pos < 62) g_pipeName[pos++] = *gameName++;
        g_pipeName[pos] = '\0';

        InterlockedExchange(&g_shutdown, 0);

        int spawned = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            g_acceptors[i] = apis.pCreateThread(nullptr, 0,
                (LPTHREAD_START_ROUTINE)acceptorThread, nullptr, 0, nullptr);
            if (g_acceptors[i]) spawned++;
        }
        if (spawned == 0) return false;

        log::debugf("[bridge] Started on %s (%d acceptor threads)\n", g_pipeName, spawned);
        return true;
    }

    inline void shutdown()
    {
        if constexpr (!g_debugLog) return;

        InterlockedExchange(&g_shutdown, 1);

        auto& apis = pipeApis();
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (g_acceptors[i] && apis.pWaitForSingleObject) {
                apis.pWaitForSingleObject(g_acceptors[i], 2000);
                if (apis.pCloseHandle) apis.pCloseHandle(g_acceptors[i]);
                g_acceptors[i] = nullptr;
            }
        }

        log::debug("[bridge] Shutdown complete\n");
    }

} // namespace bridge
