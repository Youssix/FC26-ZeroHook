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
    inline HANDLE g_thread = nullptr;
    inline char g_pipeName[64] = {};

    // ── Pipe server thread ───────────────────────────────────────────────
    inline DWORD __stdcall pipeThread(void* param)
    {
        (void)param;
        auto& apis = pipeApis();
        ScanState scanState = {};

        char logBuf[256];
        fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Pipe thread started: %s\n", g_pipeName);
        log::to_file(logBuf);

        while (!InterlockedCompareExchange(&g_shutdown, 0, 0)) {
            // Create named pipe
            HANDLE hPipe = apis.pCreateNamedPipeA(
                g_pipeName,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,      // max instances
                65536,  // out buffer
                65536,  // in buffer
                0,      // default timeout
                nullptr
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] CreateNamedPipe failed\n");
                log::to_file(logBuf);
                Sleep(1000);
                continue;
            }

            fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Waiting for client...\n");
            log::to_file(logBuf);

            // Block until a client connects
            BOOL connected = apis.pConnectNamedPipe(hPipe, nullptr);
            if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
                apis.pCloseHandle(hPipe);
                if (InterlockedCompareExchange(&g_shutdown, 0, 0)) break;
                continue;
            }

            fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Client connected\n");
            log::to_file(logBuf);

            // Read loop: accumulate data until \n
            char readBuf[4096];
            int readPos = 0;

            while (!InterlockedCompareExchange(&g_shutdown, 0, 0)) {
                DWORD bytesRead = 0;
                BOOL ok = apis.pReadFile(hPipe, readBuf + readPos,
                                         (DWORD)(sizeof(readBuf) - readPos - 1), &bytesRead, nullptr);
                if (!ok || bytesRead == 0) {
                    // Client disconnected or error
                    break;
                }

                readPos += bytesRead;
                readBuf[readPos] = '\0';

                // Process all complete lines in the buffer
                while (true) {
                    // Find newline
                    int nlPos = -1;
                    for (int i = 0; i < readPos; i++) {
                        if (readBuf[i] == '\n') { nlPos = i; break; }
                    }
                    if (nlPos < 0) break; // no complete line yet

                    // Parse and process command
                    Command cmd;
                    char responseBuf[0x20000];
                    int responseLen = 0;

                    if (parseCommand(readBuf, nlPos + 1, &cmd)) {
                        responseLen = processCommand(&cmd, responseBuf, sizeof(responseBuf), &scanState);
                    } else {
                        responseLen = buildResponse(responseBuf, sizeof(responseBuf), false, "PARSE_ERROR");
                    }

                    // Write response
                    if (responseLen > 0) {
                        DWORD written = 0;
                        apis.pWriteFile(hPipe, responseBuf, responseLen, &written, nullptr);
                        apis.pFlushFileBuffers(hPipe);
                    }

                    // Shift remaining data to front of buffer
                    int consumed = nlPos + 1;
                    int remaining = readPos - consumed;
                    if (remaining > 0) {
                        for (int i = 0; i < remaining; i++)
                            readBuf[i] = readBuf[consumed + i];
                    }
                    readPos = remaining;
                }

                // Prevent overflow
                if (readPos >= (int)sizeof(readBuf) - 1) {
                    // Command too long, reset buffer
                    readPos = 0;
                }
            }

            // Client disconnected — cleanup and loop back
            apis.pDisconnectNamedPipe(hPipe);
            apis.pCloseHandle(hPipe);

            fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Client disconnected\n");
            log::to_file(logBuf);
        }

        // Cleanup scan state before exiting
        scanReset(&scanState);

        fmt::snprintf(logBuf, sizeof(logBuf), "[bridge] Pipe thread exiting\n");
        log::to_file(logBuf);
        return 0;
    }

} // namespace bridge
