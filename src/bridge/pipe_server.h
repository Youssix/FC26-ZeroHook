#pragma once
#include <Windows.h>
#include "protocol.h"
#include "../peb/peb.h"
#include "../log/log.h"
#include "../log/fmt.h"

namespace bridge {

    // ── Win32 pipe/thread function typedefs ──────────────────────────────
    typedef HANDLE(__stdcall* fnCreateNamedPipeA)(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
    typedef BOOL(__stdcall* fnConnectNamedPipe)(HANDLE, LPOVERLAPPED);
    typedef BOOL(__stdcall* fnDisconnectNamedPipe)(HANDLE);
    typedef BOOL(__stdcall* fnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL(__stdcall* fnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL(__stdcall* fnCloseHandle)(HANDLE);
    typedef HANDLE(__stdcall* fnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    typedef DWORD(__stdcall* fnWaitForSingleObject)(HANDLE, DWORD);
    typedef BOOL(__stdcall* fnFlushFileBuffers)(HANDLE);

    // ── Lazy-resolved pipe APIs ──────────────────────────────────────────
    struct PipeApis {
        fnCreateNamedPipeA   pCreateNamedPipeA;
        fnConnectNamedPipe   pConnectNamedPipe;
        fnDisconnectNamedPipe pDisconnectNamedPipe;
        fnReadFile           pReadFile;
        fnWriteFile          pWriteFile;
        fnCloseHandle        pCloseHandle;
        fnCreateThread       pCreateThread;
        fnWaitForSingleObject pWaitForSingleObject;
        fnFlushFileBuffers   pFlushFileBuffers;
        bool resolved;
    };

    inline PipeApis& pipeApis()
    {
        static PipeApis apis = {};
        if (!apis.resolved) {
            void* k32 = peb::GetModuleBase("kernel32.dll");
            if (k32) {
                apis.pCreateNamedPipeA    = (fnCreateNamedPipeA)peb::GetExportAddress(k32, "CreateNamedPipeA");
                apis.pConnectNamedPipe    = (fnConnectNamedPipe)peb::GetExportAddress(k32, "ConnectNamedPipe");
                apis.pDisconnectNamedPipe = (fnDisconnectNamedPipe)peb::GetExportAddress(k32, "DisconnectNamedPipe");
                apis.pReadFile            = (fnReadFile)peb::GetExportAddress(k32, "ReadFile");
                apis.pWriteFile           = (fnWriteFile)peb::GetExportAddress(k32, "WriteFile");
                apis.pCloseHandle         = (fnCloseHandle)peb::GetExportAddress(k32, "CloseHandle");
                apis.pCreateThread        = (fnCreateThread)peb::GetExportAddress(k32, "CreateThread");
                apis.pWaitForSingleObject = (fnWaitForSingleObject)peb::GetExportAddress(k32, "WaitForSingleObject");
                apis.pFlushFileBuffers    = (fnFlushFileBuffers)peb::GetExportAddress(k32, "FlushFileBuffers");
                apis.resolved = true;
            }
        }
        return apis;
    }

    // ── Global state ─────────────────────────────────────────────────────
    inline volatile long g_shutdown = 0;
    inline char g_pipeName[64] = {};

    // Per-client state. Each accepted connection gets its own slot with an
    // isolated scan state so concurrent clients don't clobber each other's
    // search results. Fixed-size pool avoids any allocator call on accept.
    constexpr int MAX_CLIENTS = 8;
    struct ClientSlot {
        volatile long inUse;
        HANDLE        pipe;
        ScanState     scanState;
    };
    inline ClientSlot g_clientSlots[MAX_CLIENTS] = {};

    // One acceptor thread per client slot. Each acceptor independently
    // creates a pipe instance and blocks in ConnectNamedPipe, so MAX_CLIENTS
    // listeners are always ready. Without this, only one instance exists at
    // a time and any second client trying to connect during the brief window
    // between accept and the next CreateNamedPipe call gets ERROR_PIPE_BUSY.
    inline HANDLE g_acceptors[MAX_CLIENTS] = {};

    // ── Per-client handler thread ────────────────────────────────────────
    inline DWORD __stdcall clientThread(void* param)
    {
        auto& apis = pipeApis();
        ClientSlot* slot = (ClientSlot*)param;
        HANDLE hPipe = slot->pipe;

        char logBuf[128];
        fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Client thread started (slot=%d)\n",
                      (int)(slot - g_clientSlots));
        log::to_file(logBuf);

        char readBuf[4096];
        int readPos = 0;

        while (!InterlockedCompareExchange(&g_shutdown, 0, 0)) {
            DWORD bytesRead = 0;
            BOOL ok = apis.pReadFile(hPipe, readBuf + readPos,
                                     (DWORD)(sizeof(readBuf) - readPos - 1), &bytesRead, nullptr);
            if (!ok || bytesRead == 0) break;  // disconnect / error

            readPos += bytesRead;
            readBuf[readPos] = '\0';

            while (true) {
                int nlPos = -1;
                for (int i = 0; i < readPos; i++) {
                    if (readBuf[i] == '\n') { nlPos = i; break; }
                }
                if (nlPos < 0) break;

                Command cmd;
                char responseBuf[0x20000];
                int responseLen = 0;

                if (parseCommand(readBuf, nlPos + 1, &cmd)) {
                    responseLen = processCommand(&cmd, responseBuf, sizeof(responseBuf),
                                                 &slot->scanState);
                } else {
                    responseLen = buildResponse(responseBuf, sizeof(responseBuf), false, "PARSE_ERROR");
                }

                if (responseLen > 0) {
                    DWORD written = 0;
                    apis.pWriteFile(hPipe, responseBuf, responseLen, &written, nullptr);
                    apis.pFlushFileBuffers(hPipe);
                }

                int consumed = nlPos + 1;
                int remaining = readPos - consumed;
                if (remaining > 0) {
                    for (int i = 0; i < remaining; i++)
                        readBuf[i] = readBuf[consumed + i];
                }
                readPos = remaining;
            }

            if (readPos >= (int)sizeof(readBuf) - 1) readPos = 0;  // overflow guard
        }

        // Cleanup this client's connection + scan state, release slot.
        apis.pDisconnectNamedPipe(hPipe);
        apis.pCloseHandle(hPipe);
        scanReset(&slot->scanState);
        slot->pipe = nullptr;
        _InterlockedExchange(&slot->inUse, 0);

        fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Client disconnected (slot=%d)\n",
                      (int)(slot - g_clientSlots));
        log::to_file(logBuf);
        return 0;
    }

    // Find a free client slot. Returns index or -1.
    inline int allocClientSlot()
    {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (_InterlockedCompareExchange(&g_clientSlots[i].inUse, 1, 0) == 0)
                return i;
        }
        return -1;
    }

    // ── Pipe accept thread ───────────────────────────────────────────────
    // Each acceptor maintains exactly one listening pipe instance. We spawn
    // MAX_CLIENTS of these from bridge::init so that many listeners are
    // always blocked in ConnectNamedPipe simultaneously.
    inline DWORD __stdcall acceptorThread(void* param)
    {
        (void)param;
        auto& apis = pipeApis();

        char logBuf[256];

        while (!InterlockedCompareExchange(&g_shutdown, 0, 0)) {
            // Create a new pipe instance for the next client. Unlimited
            // instances so multiple clients can coexist (MCP + debug script
            // + CLI, etc.). Each accept spawns a dedicated thread.
            HANDLE hPipe = apis.pCreateNamedPipeA(
                g_pipeName,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                nullptr
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] CreateNamedPipe failed\n");
                log::to_file(logBuf);
                Sleep(1000);
                continue;
            }

            // Block until a client connects.
            BOOL connected = apis.pConnectNamedPipe(hPipe, nullptr);
            if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
                apis.pCloseHandle(hPipe);
                if (InterlockedCompareExchange(&g_shutdown, 0, 0)) break;
                continue;
            }

            // Allocate a slot and spawn a handler thread.
            int slotIdx = allocClientSlot();
            if (slotIdx < 0) {
                fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Client pool full — rejecting\n");
                log::to_file(logBuf);
                apis.pDisconnectNamedPipe(hPipe);
                apis.pCloseHandle(hPipe);
                continue;
            }

            g_clientSlots[slotIdx].pipe = hPipe;
            g_clientSlots[slotIdx].scanState = {};

            HANDLE hClient = apis.pCreateThread(nullptr, 0,
                                                (LPTHREAD_START_ROUTINE)clientThread,
                                                &g_clientSlots[slotIdx], 0, nullptr);
            if (!hClient) {
                fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] CreateThread failed for slot %d\n", slotIdx);
                log::to_file(logBuf);
                apis.pDisconnectNamedPipe(hPipe);
                apis.pCloseHandle(hPipe);
                g_clientSlots[slotIdx].pipe = nullptr;
                _InterlockedExchange(&g_clientSlots[slotIdx].inUse, 0);
                continue;
            }

            // Detach — the thread owns cleanup.
            apis.pCloseHandle(hClient);

            fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Client accepted → slot %d\n", slotIdx);
            log::to_file(logBuf);
            // Loop back immediately to create the next pipe instance.
        }

        fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Pipe accept thread exiting\n");
        log::to_file(logBuf);
        return 0;
    }

} // namespace bridge
