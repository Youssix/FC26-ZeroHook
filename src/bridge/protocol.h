#pragma once
#include <Windows.h>
#include "memory_ops.h"
#include "watchpoint_ops.h"
#include "../log/fmt.h"

namespace bridge {

    struct Command {
        char cmd[16];
        char args[8][256];
        int  argCount;
    };

    // ── Parse "CMD:arg1:arg2\n" into Command struct ─────────────────────
    inline bool parseCommand(const char* input, int len, Command* out)
    {
        memZero(out, sizeof(Command));

        // Strip trailing \n or \r\n
        while (len > 0 && (input[len - 1] == '\n' || input[len - 1] == '\r'))
            len--;

        if (len <= 0) return false;

        // Extract command name (up to first ':' or end)
        int pos = 0;
        int cmdLen = 0;
        while (pos < len && input[pos] != ':' && cmdLen < 15) {
            out->cmd[cmdLen++] = input[pos++];
        }
        out->cmd[cmdLen] = '\0';

        // Parse colon-separated arguments
        out->argCount = 0;
        while (pos < len && out->argCount < 8) {
            if (input[pos] == ':') pos++; // skip ':'
            int argStart = pos;
            int argLen = 0;
            while (pos < len && input[pos] != ':' && argLen < 255) {
                out->args[out->argCount][argLen++] = input[pos++];
            }
            out->args[out->argCount][argLen] = '\0';
            if (argLen > 0) out->argCount++;
        }

        return cmdLen > 0;
    }

    // ── Build response: "OK:data\n" or "ERR:msg\n" ──────────────────────
    inline int buildResponse(char* buf, int max, bool ok, const char* data)
    {
        int pos = 0;
        const char* prefix = ok ? "OK" : "ERR";
        while (*prefix && pos < max - 1) buf[pos++] = *prefix++;

        if (data && data[0]) {
            if (pos < max - 1) buf[pos++] = ':';
            while (*data && pos < max - 1) buf[pos++] = *data++;
        }

        if (pos < max - 1) buf[pos++] = '\n';
        if (pos < max) buf[pos] = '\0';
        return pos;
    }

    // ── Process a command and write response ─────────────────────────────
    inline int processCommand(const Command* cmd, char* responseBuf, int responseMax, ScanState* scanState)
    {
        // PING
        if (strCmp(cmd->cmd, "PING") == 0) {
            return buildResponse(responseBuf, responseMax, true, "PONG");
        }

        // READ:addr:size
        if (strCmp(cmd->cmd, "READ") == 0) {
            if (cmd->argCount < 2)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            uintptr_t addr = parseHex(cmd->args[0], strLen(cmd->args[0]));
            int size = (int)parseHex(cmd->args[1], strLen(cmd->args[1]));

            if (addr < 0x10000)
                return buildResponse(responseBuf, responseMax, false, "BAD_ADDR");
            if (size <= 0 || size > 0x10000)
                return buildResponse(responseBuf, responseMax, false, "SIZE_LIMIT");

            // Read into temp buffer, then hex encode
            unsigned char tempBuf[0x10000];
            int bytesRead = readMemory(addr, tempBuf, size);
            if (bytesRead <= 0)
                return buildResponse(responseBuf, responseMax, false, "ACCESS_DENIED");

            char hexBuf[0x20002]; // 64K * 2 + nul
            hexEncode(tempBuf, bytesRead, hexBuf, sizeof(hexBuf));
            return buildResponse(responseBuf, responseMax, true, hexBuf);
        }

        // WRITE:addr:hexdata
        if (strCmp(cmd->cmd, "WRITE") == 0) {
            if (cmd->argCount < 2)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            uintptr_t addr = parseHex(cmd->args[0], strLen(cmd->args[0]));
            if (addr < 0x10000)
                return buildResponse(responseBuf, responseMax, false, "BAD_ADDR");

            int hexLen = strLen(cmd->args[1]);
            int dataSize = hexLen / 2;
            if (dataSize <= 0 || dataSize > 0x1000)
                return buildResponse(responseBuf, responseMax, false, "SIZE_LIMIT");

            unsigned char dataBuf[0x1000];
            int decoded = hexDecode(cmd->args[1], hexLen, dataBuf, sizeof(dataBuf));
            if (decoded < 0)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            int written = writeMemory(addr, dataBuf, decoded);
            if (written <= 0)
                return buildResponse(responseBuf, responseMax, false, "PROTECT_FAIL");

            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)written);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_INIT:F32:value
        if (strCmp(cmd->cmd, "SCAN_INIT") == 0) {
            if (cmd->argCount < 2)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            // Only F32 supported in V1
            if (strCmp(cmd->args[0], "F32") != 0)
                return buildResponse(responseBuf, responseMax, false, "UNSUPPORTED_TYPE");

            float targetValue = parseFloat(cmd->args[1], strLen(cmd->args[1]));
            int count = scanInit(scanState, targetValue);

            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)count);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_EXACT:F32:value
        if (strCmp(cmd->cmd, "SCAN_EXACT") == 0) {
            if (cmd->argCount < 2)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            float targetValue = parseFloat(cmd->args[1], strLen(cmd->args[1]));
            int count = scanExact(scanState, targetValue);

            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)count);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_CHANGED
        if (strCmp(cmd->cmd, "SCAN_CHANGED") == 0) {
            int count = scanChanged(scanState);
            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)count);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_UNCHANGED
        if (strCmp(cmd->cmd, "SCAN_UNCHANGED") == 0) {
            int count = scanUnchanged(scanState);
            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)count);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_RESULTS[:max]
        if (strCmp(cmd->cmd, "SCAN_RESULTS") == 0) {
            int maxResults = 256;
            if (cmd->argCount >= 1 && strLen(cmd->args[0]) > 0)
                maxResults = (int)parseHex(cmd->args[0], strLen(cmd->args[0]));
            if (maxResults <= 0) maxResults = 256;
            if (maxResults > scanState->count) maxResults = scanState->count;

            char resultBuf[0x10000];
            int pos = 0;

            for (int i = 0; i < maxResults && pos < (int)sizeof(resultBuf) - 64; i++) {
                if (i > 0 && pos < (int)sizeof(resultBuf) - 1)
                    resultBuf[pos++] = ',';

                // addr=hexvalue
                char addrHex[20];
                fmt::snprintf(addrHex, sizeof(addrHex), "%llX", (unsigned long long)scanState->addresses[i]);
                for (int j = 0; addrHex[j] && pos < (int)sizeof(resultBuf) - 1; j++)
                    resultBuf[pos++] = addrHex[j];

                if (pos < (int)sizeof(resultBuf) - 1)
                    resultBuf[pos++] = '=';

                // Read current value and hex encode it
                float curVal = 0;
                __try { curVal = *(float*)scanState->addresses[i]; }
                __except (EXCEPTION_EXECUTE_HANDLER) { curVal = 0; }

                char valHex[16];
                hexEncode(&curVal, 4, valHex, sizeof(valHex));
                for (int j = 0; valHex[j] && pos < (int)sizeof(resultBuf) - 1; j++)
                    resultBuf[pos++] = valHex[j];
            }

            // Append remaining count if truncated
            int remaining = scanState->count - maxResults;
            if (remaining > 0) {
                char tail[32];
                fmt::snprintf(tail, sizeof(tail), "...%d_more", remaining);
                for (int j = 0; tail[j] && pos < (int)sizeof(resultBuf) - 1; j++)
                    resultBuf[pos++] = tail[j];
            }

            resultBuf[pos] = '\0';
            return buildResponse(responseBuf, responseMax, true, resultBuf);
        }

        // SCAN_RESET
        if (strCmp(cmd->cmd, "SCAN_RESET") == 0) {
            scanReset(scanState);
            return buildResponse(responseBuf, responseMax, true, nullptr);
        }

        // ── Watchpoints (NtClose → kernel implant → hypervisor) ───────────
        // All return ERR:NO_IMPLANT if the kernel implant isn't loaded.

        // WATCH_INSTALL:target_va:access_mask:length:filter_cr3[:count_only]
        // access_mask: bit0=R bit1=W bit2=X. length 1..4096. filter_cr3 0=off,
        // FFFFFFFFFFFFFFFF=cr3_tracker, else raw PFN.
        if (strCmp(cmd->cmd, "WATCH_INSTALL") == 0) {
            if (cmd->argCount < 4)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            uintptr_t target_va  = parseHex(cmd->args[0], strLen(cmd->args[0]));
            unsigned char  access_mask = (unsigned char)parseHex(cmd->args[1], strLen(cmd->args[1]));
            unsigned int   length      = (unsigned int)parseHex(cmd->args[2], strLen(cmd->args[2]));
            unsigned long long filter_cr3 = parseHex(cmd->args[3], strLen(cmd->args[3]));
            unsigned char  count_only  = 0;
            if (cmd->argCount >= 5)
                count_only = (unsigned char)parseHex(cmd->args[4], strLen(cmd->args[4]));

            if (target_va < 0x10000)
                return buildResponse(responseBuf, responseMax, false, "BAD_ADDR");
            if (length == 0 || length > 4096)
                return buildResponse(responseBuf, responseMax, false, "BAD_LENGTH");
            if (access_mask == 0 || (access_mask & ~0x07) != 0)
                return buildResponse(responseBuf, responseMax, false, "BAD_ACCESS");

            // Page-relative offset is implicit from VA & 0xFFF.
            unsigned short offset_in_page = (unsigned short)(target_va & 0xFFF);
            unsigned short length_in_page = (unsigned short)length;

            unsigned short id = watchInstall(target_va,
                                              access_mask,
                                              offset_in_page,
                                              length_in_page,
                                              filter_cr3,
                                              count_only);
            if (id == 0)
                return buildResponse(responseBuf, responseMax, false, "NO_IMPLANT_OR_FAIL");

            char outBuf[16];
            fmt::snprintf(outBuf, sizeof(outBuf), "%X", (unsigned int)id);
            return buildResponse(responseBuf, responseMax, true, outBuf);
        }

        // WATCH_REMOVE:id
        if (strCmp(cmd->cmd, "WATCH_REMOVE") == 0) {
            if (cmd->argCount < 1)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            unsigned short id = (unsigned short)parseHex(cmd->args[0], strLen(cmd->args[0]));
            if (id == 0)
                return buildResponse(responseBuf, responseMax, false, "BAD_ID");

            unsigned long long ok = watchRemove(id);
            if (!ok)
                return buildResponse(responseBuf, responseMax, false, "NO_IMPLANT_OR_FAIL");
            return buildResponse(responseBuf, responseMax, true, "1");
        }

        // WATCH_DRAIN[:max_events]   (default 64, hard cap 256)
        // Response: count_hex,event0_hex,event1_hex,...  (each event = 256 hex chars / 128 bytes)
        if (strCmp(cmd->cmd, "WATCH_DRAIN") == 0) {
            unsigned int max_events = 64;
            if (cmd->argCount >= 1 && strLen(cmd->args[0]) > 0)
                max_events = (unsigned int)parseHex(cmd->args[0], strLen(cmd->args[0]));
            if (max_events == 0) max_events = 64;
            if (max_events > 256) max_events = 256;

            // 256 events * 128B = 32KB; well under the 128KB response cap.
            static watchpoint_event_t s_events[256];
            memZero(s_events, (int)(max_events * sizeof(watchpoint_event_t)));

            unsigned long long copied = watchDrain(s_events, max_events);
            // copied == 0 might be "no events" (legit) OR "implant absent". The
            // implant-absent path also returns 0 from req.result, so we have
            // no way here to distinguish. The Python tool can interpret 0 as
            // "no events available" — install/remove pre-checks already catch
            // the implant-absent case loudly.

            // Build response: count,event0,event1,...
            static char outBuf[0x20000];
            int pos = 0;

            char countHex[16];
            fmt::snprintf(countHex, sizeof(countHex), "%llX", copied);
            for (int j = 0; countHex[j] && pos < (int)sizeof(outBuf) - 1; j++)
                outBuf[pos++] = countHex[j];

            for (unsigned long long i = 0; i < copied && pos < (int)sizeof(outBuf) - 260; i++) {
                if (pos < (int)sizeof(outBuf) - 1) outBuf[pos++] = ',';
                char evHex[260]; // 128*2 + nul
                hexEncode(&s_events[i], (int)sizeof(watchpoint_event_t),
                          evHex, sizeof(evHex));
                for (int j = 0; evHex[j] && pos < (int)sizeof(outBuf) - 1; j++)
                    outBuf[pos++] = evHex[j];
            }
            outBuf[pos] = '\0';

            return buildResponse(responseBuf, responseMax, true, outBuf);
        }

        // WATCH_STATS:id   → returns hits_hex,dropped_hex
        if (strCmp(cmd->cmd, "WATCH_STATS") == 0) {
            if (cmd->argCount < 1)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            unsigned short id = (unsigned short)parseHex(cmd->args[0], strLen(cmd->args[0]));
            if (id == 0)
                return buildResponse(responseBuf, responseMax, false, "BAD_ID");

            unsigned long long packed = watchStats(id);
            unsigned int hits    = (unsigned int)(packed >> 32);
            unsigned int dropped = (unsigned int)(packed & 0xFFFFFFFFu);

            char outBuf[40];
            fmt::snprintf(outBuf, sizeof(outBuf), "%X,%X", hits, dropped);
            return buildResponse(responseBuf, responseMax, true, outBuf);
        }

        return buildResponse(responseBuf, responseMax, false, "UNKNOWN_CMD");
    }

} // namespace bridge
